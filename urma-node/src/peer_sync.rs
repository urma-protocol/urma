//! Fast inventory synchronization from configured URMA peers. A peer page is an
//! untrusted claim: every fetched package is proof-verified by `admit_record`
//! against the independently selected header chain, and coverage is recorded
//! only after a complete range has every advertised record present locally.
//! Full-block audit (`indexed_through`) remains the separate, stronger claim.
//! A peer that answers with an invalid page, package or reply is disconnected
//! and backed off; one that stays Busy for many turns is disconnected so the
//! connection slot it holds frees up for others. So is one that answers turn
//! after turn without anything we can use (stale listings, unscanned pages),
//! and a peer refused by the local connection limit gets the slot of the
//! connected peer that progressed longest ago.
use crate::{
    DialLimit, Error,
    engine::Engine,
    model::{OverlayPeerStatus, OverlayStatus, RecordReceipt},
    peer::PeerSource,
    peer_protocol::{InventoryPage, Placement},
    recorded::{RecordedError, unix_seconds},
};
use libp2p::PeerId;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub type ConnectedPeers = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Public overlay identity facts reported in status; never secrets.
pub struct OverlayInfo {
    pub peer_id: String,
    pub listen: Option<String>,
    pub peer_book: u64,
    pub connected: ConnectedPeers,
}

/// Configured inventory peers. Each label is the peer's libp2p identity.
pub struct PeerSync {
    pub peers: Vec<(String, PeerSource)>,
    pub info: OverlayInfo,
}

/// One claimed range being walked page by page; lives only in memory.
struct Range {
    from: u64,
    to: u64,
    after: Option<Placement>,
    entries: Vec<Placement>,
    next: usize,
    more: bool,
    scanned_through: u64,
    generation: u64,
    /// Consecutive Missing answers for records this range advertised.
    missing: u32,
}

struct Peer {
    label: String,
    id: String,
    peer_id: PeerId,
    source: PeerSource,
    range: Mutex<Option<Range>>,
    last_request: Mutex<Option<Instant>>,
    last_error: Mutex<Option<RecordedError>>,
    backoff: Mutex<Backoff>,
    busy_turns: AtomicU32,
    idle_turns: AtomicU32,
    last_progress: Mutex<Option<u64>>,
    /// Scheduler step at which this peer was first seen connected, if it is.
    connected_since: Mutex<Option<u64>>,
}

/// Sync backoff after peer errors: consecutive blamed turns and the Unix
/// second before which the peer is skipped.
struct Backoff {
    failures: u32,
    until: Option<u64>,
}

impl Peer {
    fn backoff_until(&self, now: u64) -> Result<Option<u64>, Error> {
        let backoff = self.backoff.lock().map_err(|_| poisoned())?;
        Ok(backoff.until.filter(|until| *until > now))
    }

    fn last_progress(&self) -> Result<Option<u64>, Error> {
        Ok(*self.last_progress.lock().map_err(|_| poisoned())?)
    }

    /// Skip this peer until at least `now + seconds`, unblamed: failures and
    /// the book are untouched, and a longer backoff is never shortened.
    fn hold_off(&self, now: u64, seconds: u64) -> Result<(), Error> {
        let until = now.checked_add(seconds).unwrap_or(u64::MAX);
        let mut backoff = self.backoff.lock().map_err(|_| poisoned())?;
        backoff.until = Some(backoff.until.map_or(until, |current| current.max(until)));
        Ok(())
    }

    /// Wait for an evicted connection to close so its slot is really free,
    /// bounded by `EVICT_WAIT`, the step deadline and cancellation.
    fn wait_closed(&self, stop: &AtomicBool, deadline: Instant) -> bool {
        let until = deadline.min(Instant::now() + Scheduler::EVICT_WAIT);
        while self.source.connected() {
            if stop.load(Ordering::Acquire) || Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        true
    }
}

/// Why a step stopped early. `Blame` is a protocol violation by the peer;
/// `Error` is ours, transport or retryable.
enum Pause {
    Done,
    Abandon,
    Error(Error),
    Blame(Error),
}

/// How one step ended for the peer it ran with: remote Busy builds a streak,
/// local Busy and transport failures retry quietly.
enum Turn {
    Quiet,
    Busy(Error),
    Retry(Error),
    Blamed(Error),
}

/// A failed request blames the peer only for a protocol violation: never for
/// capacity (ours or theirs), transport failure or our reorg.
fn blame(error: Error) -> Pause {
    match error {
        Error::Busy(_)
        | Error::PeerBusy
        | Error::Transport(_)
        | Error::DialDenied(_)
        | Error::Stale => Pause::Error(error),
        other => Pause::Blame(other),
    }
}

impl From<Error> for Pause {
    fn from(error: Error) -> Self {
        Pause::Error(error)
    }
}

/// Per-round budgets for one peer: request spacing, fetch count, wall clock;
/// whether the peer was asked anything and whether an admission or coverage
/// came of it.
struct Round<'a> {
    stop: &'a AtomicBool,
    deadline: Instant,
    fetched: usize,
    requested_page: bool,
    contacted: bool,
    progressed: bool,
}

impl Round<'_> {
    fn open(&self) -> Result<(), Pause> {
        if self.stop.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Pause::Done);
        }
        Ok(())
    }
}

pub(crate) struct Scheduler {
    peers: Mutex<Vec<Arc<Peer>>>,
    turn: AtomicUsize,
    info: OverlayInfo,
    admitted: AtomicU64,
    rejected: AtomicU64,
    penalized: Mutex<Vec<PeerId>>,
    steps: AtomicU64,
}

fn poisoned() -> Error {
    Error::Invalid("peer synchronization state poisoned".into())
}

/// A connected peer that has held its slot for more than one step without
/// progress for `IDLE_BACKOFF` seconds, or ever.
fn evictable(peer: &Peer, step: u64, now: u64) -> Result<bool, Error> {
    let settled = peer
        .connected_since
        .lock()
        .map_err(|_| poisoned())?
        .is_some_and(|since| step >= since.saturating_add(2));
    let idle = peer
        .last_progress()?
        .is_none_or(|at| now >= at.saturating_add(Scheduler::IDLE_BACKOFF));
    Ok(settled && idle && peer.source.connected())
}

fn inventory_peer(label: String, source: PeerSource) -> Result<Peer, Error> {
    let peer_id = match label.parse::<PeerId>() {
        Ok(id) => id,
        Err(error) => {
            return Err(Error::Invalid(format!("inventory peer label: {error}")));
        }
    };
    Ok(Peer {
        label,
        id: peer_id.to_string(),
        peer_id,
        source,
        range: Mutex::new(None),
        last_request: Mutex::new(None),
        last_error: Mutex::new(None),
        backoff: Mutex::new(Backoff {
            failures: 0,
            until: None,
        }),
        busy_turns: AtomicU32::new(0),
        idle_turns: AtomicU32::new(0),
        last_progress: Mutex::new(None),
        connected_since: Mutex::new(None),
    })
}

impl Scheduler {
    /// Heights per claimed range, inclusive of both ends.
    pub const RANGE_HEIGHTS: u64 = 4096;
    /// Entries requested per inventory page.
    pub const PAGE_ENTRIES: u32 = 512;
    /// Package fetches per worker round.
    pub const ROUND_FETCHES: usize = 16;
    /// Wall-clock budget of one step, checked between requests.
    pub const ROUND_TIME: Duration = Duration::from_secs(20);
    /// Minimum spacing between requests to one peer (its 4/s token bucket).
    pub const REQUEST_SPACING: Duration = Duration::from_millis(250);
    /// Sync backoff after a peer error: 30 s, doubling per repeat, capped at a day.
    pub const BACKOFF_SECONDS: u64 = 30;
    pub const BACKOFF_CAP: u64 = 86_400;
    /// Consecutive Busy turns after which a peer is disconnected.
    pub const BUSY_TURNS: u32 = 10;
    /// Consecutive Missing answers for advertised records that blame a peer.
    pub const MISSING_ANSWERS: u32 = 2;
    /// Consecutive answered turns without progress after which a peer's slot
    /// is released for `IDLE_BACKOFF` seconds, unblamed. The same span guards
    /// eviction: only a peer without progress for that long can be evicted,
    /// and an evicted peer is held off for it too.
    pub const IDLE_TURNS: u32 = 3;
    pub const IDLE_BACKOFF: u64 = 60;
    /// Longest wait for an evicted connection to close before the retry.
    pub const EVICT_WAIT: Duration = Duration::from_secs(2);
    const MAX_PEERS: usize = 1024;

    pub(crate) fn new(sync: PeerSync) -> Result<Self, Error> {
        if sync.peers.len() > Self::MAX_PEERS {
            return Err(Error::Invalid("too many inventory peers".into()));
        }
        let mut peers: Vec<Arc<Peer>> = Vec::new();
        for (label, source) in sync.peers {
            let peer = inventory_peer(label, source)?;
            if peers.iter().any(|known| known.id == peer.id) {
                return Err(Error::Invalid("duplicate inventory peer".into()));
            }
            peers.push(Arc::new(peer));
        }
        Ok(Self {
            peers: Mutex::new(peers),
            turn: AtomicUsize::new(0),
            info: sync.info,
            admitted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            penalized: Mutex::new(Vec::new()),
            steps: AtomicU64::new(0),
        })
    }

    /// One bounded step with the next non-omitting, non-backed-off peer in
    /// rotation. Busy, deadline and cancellation keep the range; a step
    /// interrupted by `stop` records nothing about the peer.
    pub(crate) fn step(&self, engine: &Engine, stop: &AtomicBool) -> Result<(), Error> {
        let omitting = engine.omitting_peers()?;
        let now = unix_seconds()?;
        let step = self.steps.fetch_add(1, Ordering::Relaxed);
        self.observe_connections(step)?;
        let Some(peer) = self.next_peer(&omitting, now)? else {
            return Ok(());
        };
        let deadline = Instant::now() + Self::ROUND_TIME;
        let denied = self.turn(&peer, engine, stop, deadline, now)?;
        if denied && self.free_slot_for(&peer, step, stop, deadline, now)? {
            self.turn(&peer, engine, stop, deadline, now)?;
        }
        Ok(())
    }

    /// One turn with `peer`. Returns whether our established-connection
    /// limit refused its dial, the only refusal an eviction can cure.
    fn turn(
        &self,
        peer: &Peer,
        engine: &Engine,
        stop: &AtomicBool,
        deadline: Instant,
        now: u64,
    ) -> Result<bool, Error> {
        let mut round = Round {
            stop,
            deadline,
            fetched: 0,
            requested_page: false,
            contacted: false,
            progressed: false,
        };
        let outcome = self.advance(peer, engine, &mut round);
        if stop.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.track_progress(peer, &outcome, &round, now)?;
        let denied = matches!(
            &outcome,
            Ok(Turn::Retry(Error::DialDenied(DialLimit::Established)))
        );
        let result = self.judge(peer, outcome, now)?;
        *peer.last_error.lock().map_err(|_| poisoned())? = RecordedError::from_result(&result);
        Ok(denied)
    }

    /// Note at which step each inventory peer was first seen connected.
    fn observe_connections(&self, step: u64) -> Result<(), Error> {
        for peer in self.snapshot()? {
            let mut since = peer.connected_since.lock().map_err(|_| poisoned())?;
            *since = match (peer.source.connected(), *since) {
                (true, Some(first)) => Some(first),
                (true, None) => Some(step),
                (false, _gone) => None,
            };
        }
        Ok(())
    }

    /// Peers sync is currently skipping, for discovery not to redial them.
    pub(crate) fn backed_off(&self, now: u64) -> Result<Vec<String>, Error> {
        let mut skipped = Vec::new();
        for peer in self.snapshot()? {
            if peer.backoff_until(now)?.is_some() {
                skipped.push(peer.id.clone());
            }
        }
        Ok(skipped)
    }

    /// An admission, coverage or an already-held listed record is progress
    /// and resets the idle streak. `IDLE_TURNS` quiet turns in a row that
    /// asked the peer and got nothing usable release its slot for
    /// `IDLE_BACKOFF`: no blame, no book penalty, failures untouched.
    fn track_progress(
        &self,
        peer: &Peer,
        outcome: &Result<Turn, Error>,
        round: &Round,
        now: u64,
    ) -> Result<(), Error> {
        if round.progressed {
            peer.idle_turns.store(0, Ordering::Relaxed);
            *peer.last_progress.lock().map_err(|_| poisoned())? = Some(now);
            return Ok(());
        }
        if !round.contacted || !matches!(outcome, Ok(Turn::Quiet)) {
            return Ok(());
        }
        let idle = peer.idle_turns.fetch_add(1, Ordering::Relaxed) + 1;
        if idle < Self::IDLE_TURNS {
            return Ok(());
        }
        peer.idle_turns.store(0, Ordering::Relaxed);
        peer.source.disconnect();
        peer.hold_off(now, Self::IDLE_BACKOFF)
    }

    /// Our established-connection limit refused `starved`: evict the
    /// connected inventory peer that progressed longest ago, but only one
    /// without progress for `IDLE_BACKOFF` (or ever) that has stayed connected
    /// for more than one step. The victim is held off for `IDLE_BACKOFF`, in
    /// sync and in discovery, so nothing redials it into the freed slot.
    /// Returns whether its connection closed in time for `starved` to retry
    /// in this step. One eviction per step, and no second one for `starved`
    /// before that retry; the scheduler runs one request at a time, so no
    /// other inventory peer is mid-request.
    fn free_slot_for(
        &self,
        starved: &Peer,
        step: u64,
        stop: &AtomicBool,
        deadline: Instant,
        now: u64,
    ) -> Result<bool, Error> {
        let mut oldest: Option<(Arc<Peer>, Option<u64>)> = None;
        for peer in self.snapshot()? {
            if peer.id == starved.id || !evictable(&peer, step, now)? {
                continue;
            }
            let progress = peer.last_progress()?;
            if oldest.as_ref().is_none_or(|(_, best)| progress < *best) {
                oldest = Some((peer, progress));
            }
        }
        let Some((victim, _progress)) = oldest else {
            return Ok(false);
        };
        victim.source.disconnect();
        victim.hold_off(now, Self::IDLE_BACKOFF)?;
        Ok(victim.wait_closed(stop, deadline))
    }

    /// A blamed turn disconnects the peer and backs it off; remote Busy turns
    /// build a streak that disconnects the peer at `BUSY_TURNS`; a quiet turn
    /// resets both. Retries and our own failures say nothing about the peer.
    fn judge(
        &self,
        peer: &Peer,
        outcome: Result<Turn, Error>,
        now: u64,
    ) -> Result<Result<(), Error>, Error> {
        match outcome {
            Ok(Turn::Quiet) => {
                peer.busy_turns.store(0, Ordering::Relaxed);
                peer.backoff.lock().map_err(|_| poisoned())?.failures = 0;
                Ok(Ok(()))
            }
            Ok(Turn::Busy(error)) => {
                let streak = peer.busy_turns.fetch_add(1, Ordering::Relaxed) + 1;
                if streak < Self::BUSY_TURNS {
                    return Ok(Err(error));
                }
                peer.busy_turns.store(0, Ordering::Relaxed);
                peer.source.disconnect();
                Ok(Err(Error::Busy(format!(
                    "{error}; busy for {streak} turns, disconnected"
                ))))
            }
            Ok(Turn::Blamed(error)) => {
                peer.busy_turns.store(0, Ordering::Relaxed);
                self.penalize(peer, now)?;
                Ok(Err(error))
            }
            Ok(Turn::Retry(error)) | Err(error) => Ok(Err(error)),
        }
    }

    fn penalize(&self, peer: &Peer, now: u64) -> Result<(), Error> {
        peer.source.disconnect();
        let mut backoff = peer.backoff.lock().map_err(|_| poisoned())?;
        backoff.failures = backoff.failures.checked_add(1).unwrap_or(u32::MAX);
        let delay = 2u64
            .checked_pow(backoff.failures - 1)
            .and_then(|factor| factor.checked_mul(Self::BACKOFF_SECONDS))
            .map_or(Self::BACKOFF_CAP, |delay| delay.min(Self::BACKOFF_CAP));
        backoff.until = Some(now.checked_add(delay).unwrap_or(u64::MAX));
        drop(backoff);
        let mut penalized = self.penalized.lock().map_err(|_| poisoned())?;
        if !penalized.contains(&peer.peer_id) {
            penalized.push(peer.peer_id);
        }
        Ok(())
    }

    /// Peers backed off since the last call, for the peer book to record.
    pub(crate) fn drain_penalized(&self) -> Result<Vec<PeerId>, Error> {
        let mut penalized = self.penalized.lock().map_err(|_| poisoned())?;
        Ok(std::mem::take(&mut *penalized))
    }

    /// Reconcile with the peer book: known identities keep their peer state and
    /// in-flight range, new ones join, ones no longer offered are dropped.
    pub(crate) fn refresh(&self, offered: Vec<(String, PeerSource)>) -> Result<(), Error> {
        if offered.len() > Self::MAX_PEERS {
            return Err(Error::Invalid("too many inventory peers".into()));
        }
        let mut peers = self.peers.lock().map_err(|_| poisoned())?;
        let mut next: Vec<Arc<Peer>> = Vec::with_capacity(offered.len());
        for (label, source) in offered {
            let candidate = inventory_peer(label, source)?;
            if next.iter().any(|kept| kept.id == candidate.id) {
                continue;
            }
            match peers.iter().find(|known| known.id == candidate.id) {
                Some(known) => next.push(Arc::clone(known)),
                None => next.push(Arc::new(candidate)),
            }
        }
        *peers = next;
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<Arc<Peer>>, Error> {
        Ok(self.peers.lock().map_err(|_| poisoned())?.clone())
    }

    fn next_peer(&self, omitting: &[String], now: u64) -> Result<Option<Arc<Peer>>, Error> {
        let peers = self.snapshot()?;
        let count = peers.len();
        for _ in 0..count {
            let peer = &peers[self.turn.fetch_add(1, Ordering::Relaxed) % count];
            if !omitting.contains(&peer.id) && peer.backoff_until(now)?.is_none() {
                return Ok(Some(Arc::clone(peer)));
            }
        }
        Ok(None)
    }

    fn advance(&self, peer: &Peer, engine: &Engine, round: &mut Round) -> Result<Turn, Error> {
        let mut slot = peer.range.lock().map_err(|_| poisoned())?;
        if slot.is_none() {
            *slot = open(peer, engine)?;
            // Nothing left to ask a fully synced peer: as fresh as progress,
            // so surplus synced peers are not evicted every IDLE_BACKOFF.
            round.progressed |= slot.is_none();
        }
        // A peer error or our own failure abandons the range; it is requested
        // again from the persisted cursor on this peer's next turn.
        match self.walk(peer, engine, &mut slot, round) {
            Ok(()) | Err(Pause::Done) => Ok(Turn::Quiet),
            Err(Pause::Abandon) | Err(Pause::Error(Error::Stale)) => {
                *slot = None;
                Ok(Turn::Quiet)
            }
            Err(Pause::Error(Error::PeerBusy)) => Ok(Turn::Busy(Error::PeerBusy)),
            Err(Pause::Error(
                retry @ (Error::Busy(_) | Error::Transport(_) | Error::DialDenied(_)),
            )) => Ok(Turn::Retry(retry)),
            Err(Pause::Blame(error)) => {
                *slot = None;
                Ok(Turn::Blamed(error))
            }
            Err(Pause::Error(error)) => {
                *slot = None;
                Err(error)
            }
        }
    }

    fn walk(
        &self,
        peer: &Peer,
        engine: &Engine,
        slot: &mut Option<Range>,
        round: &mut Round,
    ) -> Result<(), Pause> {
        while let Some(range) = slot.as_mut() {
            round.open()?;
            if let Some(&entry) = range.entries.get(range.next) {
                if !selected(engine, &entry)? {
                    return Err(Pause::Abandon);
                }
                if engine.record(entry.txid)?.is_none() {
                    if round.fetched == Self::ROUND_FETCHES {
                        return Err(Pause::Done);
                    }
                    round.fetched += 1;
                    pace(peer, round)?;
                    let missing = &mut range.missing;
                    round.progressed |=
                        self.acquire(peer, engine, &entry, missing, round.deadline)?;
                } else {
                    round.progressed = true;
                }
                range.next += 1;
            } else if range.more {
                if round.requested_page {
                    return Err(Pause::Done);
                }
                round.requested_page = true;
                pace(peer, round)?;
                let Some(page) = peer
                    .source
                    .inventory_until(
                        (range.from, range.to),
                        range.after,
                        Self::PAGE_ENTRIES,
                        round.stop,
                        round.deadline,
                    )
                    .map_err(blame)?
                else {
                    return Err(Pause::Done);
                };
                if !accept(range, page).map_err(Pause::Blame)? {
                    *slot = None;
                }
            } else {
                let through = range.to.min(range.scanned_through);
                engine.record_peer_coverage(&peer.id, range.from, through, range.generation)?;
                round.progressed = true;
                *slot = None;
            }
        }
        Ok(())
    }

    /// Fetch one advertised record from the advertising peer and admit it. A
    /// peer that answers Missing leaves the entry listed-only: it neither blocks
    /// coverage nor is retried within this range. `MISSING_ANSWERS` Missing
    /// answers in a row within one range blame the peer; an invalid package
    /// always does. Returns whether a record was admitted.
    fn acquire(
        &self,
        peer: &Peer,
        engine: &Engine,
        entry: &Placement,
        missing: &mut u32,
        deadline: Instant,
    ) -> Result<bool, Pause> {
        let fetched = peer
            .source
            .fetch_until(entry.txid, deadline)
            .map_err(blame)?;
        let Some(package) = fetched else {
            *missing += 1;
            if *missing < Self::MISSING_ANSWERS {
                return Ok(false);
            }
            return Err(Pause::Blame(Error::Invalid(
                "peer reported advertised records missing".into(),
            )));
        };
        *missing = 0;
        let receipt = match engine.admit_record(package) {
            Ok(receipt) => receipt,
            Err(invalid @ Error::Invalid(_)) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(Pause::Blame(invalid));
            }
            Err(local) => return Err(Pause::Error(local)),
        };
        self.admitted.fetch_add(1, Ordering::Relaxed);
        if !placed(&receipt, entry) {
            return Err(Pause::Blame(Error::Invalid(
                "peer inventory placement disagrees with its proven record".into(),
            )));
        }
        Ok(true)
    }

    pub(crate) fn status(&self, engine: &Engine) -> Result<OverlayStatus, Error> {
        let start = engine.status()?.application_start.height;
        let now = unix_seconds()?;
        let known = self.snapshot()?;
        let mut peers = Vec::with_capacity(known.len());
        for peer in &known {
            let cursor = engine.peer_cursor(&peer.id)?;
            let synced_through = cursor.checked_sub(1).filter(|height| *height >= start);
            let recorded = peer.last_error.lock().map_err(|_| poisoned())?.clone();
            let (last_error, last_error_at) = RecordedError::split(recorded);
            peers.push(OverlayPeerStatus {
                label: peer.label.clone(),
                cursor,
                synced_through,
                last_error,
                last_error_at,
                backoff_until: peer.backoff_until(now)?,
                last_progress_at: peer.last_progress()?,
            });
        }
        Ok(OverlayStatus {
            peer_id: self.info.peer_id.clone(),
            listen: self.info.listen.clone(),
            peer_book: self.info.peer_book,
            connected: (self.info.connected)(),
            admitted: self.admitted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            peers,
            discovery: None,
        })
    }
}

/// Keep requests to one peer at least `REQUEST_SPACING` apart, waiting in
/// short slices so cancellation and the round deadline stay responsive. The
/// round counts as having asked the peer once pacing lets a request through.
fn pace(peer: &Peer, round: &mut Round) -> Result<(), Pause> {
    let mut last = peer.last_request.lock().map_err(|_| poisoned())?;
    if let Some(previous) = *last {
        let ready = previous + Scheduler::REQUEST_SPACING;
        while Instant::now() < ready {
            round.open()?;
            let wait = ready.saturating_duration_since(Instant::now());
            std::thread::sleep(wait.min(Duration::from_millis(50)));
        }
    }
    round.open()?;
    *last = Some(Instant::now());
    round.contacted = true;
    Ok(())
}

/// The next unclaimed range for this peer, bounded by the local selected tip.
/// The range keeps the generation observed here for its whole lifetime, so a
/// reorg between rounds makes its coverage claim Stale instead of mislabelled.
fn open(peer: &Peer, engine: &Engine) -> Result<Option<Range>, Error> {
    let status = engine.status()?;
    let Some(tip) = status.selected_tip else {
        return Ok(None);
    };
    let from = engine.peer_cursor(&peer.id)?;
    if from > tip.height {
        return Ok(None);
    }
    let span_end = from
        .checked_add(Scheduler::RANGE_HEIGHTS - 1)
        .ok_or_else(|| Error::Invalid("peer cursor overflows the height range".into()))?;
    Ok(Some(Range {
        from,
        to: tip.height.min(span_end),
        after: None,
        entries: Vec::new(),
        next: 0,
        more: true,
        scanned_through: 0,
        generation: status.generation,
        missing: 0,
    }))
}

/// Install a page. Returns false when the peer has not scanned this range yet.
/// Entries must be strictly ordered after the page cursor and inside the
/// requested range; anything else is a peer error. Entries above the peer's
/// own scanned prefix (blocks still waiting on a dependency) are dropped
/// without blame: they are outside what the page can claim.
fn accept(range: &mut Range, page: InventoryPage) -> Result<bool, Error> {
    let Some(scanned_through) = page.scanned_through.filter(|height| *height >= range.from) else {
        return Ok(false);
    };
    let limit = usize::try_from(Scheduler::PAGE_ENTRIES)
        .map_err(|error| Error::Invalid(format!("page limit: {error}")))?;
    if page.entries.len() > limit || (page.more && page.entries.is_empty()) {
        return Err(Error::Invalid("peer inventory page size is invalid".into()));
    }
    let mut previous = range.after;
    for entry in &page.entries {
        if entry.height < range.from
            || entry.height > range.to
            || previous
                .is_some_and(|last| (entry.height, entry.position) <= (last.height, last.position))
        {
            return Err(Error::Invalid(
                "peer inventory entry is out of range or order".into(),
            ));
        }
        previous = Some(*entry);
    }
    range.after = previous;
    range.entries = page
        .entries
        .into_iter()
        .filter(|entry| entry.height <= scanned_through)
        .collect();
    range.next = 0;
    range.more = page.more;
    range.scanned_through = scanned_through;
    Ok(true)
}

/// A listing whose block differs from our selected header at that height comes
/// from another view of the chain (a reorg in flight); it is not a peer error.
fn selected(engine: &Engine, entry: &Placement) -> Result<bool, Error> {
    match engine.archive()?.ticket(entry.height) {
        Ok(ticket) => Ok(ticket.point().hash == entry.block_hash),
        Err(Error::Invalid(_outside_selected_view)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn placed(receipt: &RecordReceipt, entry: &Placement) -> bool {
    receipt.block.height == entry.height
        && receipt.block.hash == entry.block_hash
        && receipt.position == entry.position
        && receipt.txid == entry.txid
        && receipt.wtxid == entry.wtxid
}
