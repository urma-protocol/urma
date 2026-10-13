//! Fast inventory synchronization from configured URMA peers. A peer page is an
//! untrusted claim: every fetched package is proof-verified by `admit_record`
//! against the independently selected header chain, and coverage is recorded
//! only after a complete range has every advertised record present locally.
//! Full-block audit (`indexed_through`) remains the separate, stronger claim.
use crate::{
    Error,
    engine::Engine,
    model::{OverlayPeerStatus, OverlayStatus, RecordReceipt},
    peer::PeerSource,
    peer_protocol::{InventoryPage, Placement},
    recorded::RecordedError,
};
use libp2p::PeerId;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
}

struct Peer {
    label: String,
    id: String,
    source: PeerSource,
    range: Mutex<Option<Range>>,
    last_request: Mutex<Option<Instant>>,
    last_error: Mutex<Option<RecordedError>>,
}

/// Why a step stopped early without blaming the peer.
enum Pause {
    Done,
    Abandon,
    Error(Error),
}

impl From<Error> for Pause {
    fn from(error: Error) -> Self {
        Pause::Error(error)
    }
}

/// Per-round budgets for one peer: request spacing, fetch count, wall clock.
struct Round<'a> {
    stop: &'a AtomicBool,
    deadline: Instant,
    fetched: usize,
    requested_page: bool,
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
    peers: Vec<Peer>,
    turn: AtomicUsize,
    info: OverlayInfo,
    admitted: AtomicU64,
    rejected: AtomicU64,
}

fn poisoned() -> Error {
    Error::Invalid("peer synchronization state poisoned".into())
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
    const MAX_PEERS: usize = 1024;

    pub(crate) fn new(sync: PeerSync) -> Result<Self, Error> {
        if sync.peers.len() > Self::MAX_PEERS {
            return Err(Error::Invalid("too many inventory peers".into()));
        }
        let mut peers: Vec<Peer> = Vec::new();
        for (label, source) in sync.peers {
            let id = match label.parse::<PeerId>() {
                Ok(id) => id.to_string(),
                Err(error) => {
                    return Err(Error::Invalid(format!("inventory peer label: {error}")));
                }
            };
            if peers.iter().any(|peer| peer.id == id) {
                return Err(Error::Invalid("duplicate inventory peer".into()));
            }
            peers.push(Peer {
                label,
                id,
                source,
                range: Mutex::new(None),
                last_request: Mutex::new(None),
                last_error: Mutex::new(None),
            });
        }
        Ok(Self {
            peers,
            turn: AtomicUsize::new(0),
            info: sync.info,
            admitted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        })
    }

    /// One bounded step with the next non-omitting peer in rotation. Busy,
    /// deadline and cancellation end the step quietly and keep the range; a
    /// step interrupted by `stop` records nothing about the peer.
    pub(crate) fn step(&self, engine: &Engine, stop: &AtomicBool) -> Result<(), Error> {
        let omitting = engine.omitting_peers()?;
        let Some(peer) = self.next_peer(&omitting) else {
            return Ok(());
        };
        let mut round = Round {
            stop,
            deadline: Instant::now() + Self::ROUND_TIME,
            fetched: 0,
            requested_page: false,
        };
        let outcome = self.advance(peer, engine, &mut round);
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        *peer.last_error.lock().map_err(|_| poisoned())? = RecordedError::from_result(&outcome);
        Ok(())
    }

    fn next_peer(&self, omitting: &[String]) -> Option<&Peer> {
        let count = self.peers.len();
        (0..count)
            .map(|_| &self.peers[self.turn.fetch_add(1, Ordering::Relaxed) % count])
            .find(|peer| !omitting.contains(&peer.id))
    }

    fn advance(&self, peer: &Peer, engine: &Engine, round: &mut Round) -> Result<(), Error> {
        let mut slot = peer.range.lock().map_err(|_| poisoned())?;
        if slot.is_none() {
            *slot = open(peer, engine)?;
        }
        match self.walk(peer, engine, &mut slot, round) {
            Ok(()) | Err(Pause::Done) => Ok(()),
            Err(Pause::Abandon) | Err(Pause::Error(Error::Stale)) => {
                *slot = None;
                Ok(())
            }
            Err(Pause::Error(Error::Busy(_retry_next_round))) => Ok(()),
            Err(Pause::Error(error)) => {
                // A failed admission or a lying page abandons the range; it is
                // requested again from the persisted cursor on this peer's turn.
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
            if let Some(entry) = range.entries.get(range.next) {
                if !selected(engine, entry)? {
                    return Err(Pause::Abandon);
                }
                if engine.record(entry.txid)?.is_none() {
                    if round.fetched == Self::ROUND_FETCHES {
                        return Err(Pause::Done);
                    }
                    round.fetched += 1;
                    pace(peer, round)?;
                    self.acquire(peer, engine, entry, round.deadline)?;
                }
                range.next += 1;
            } else if range.more {
                if round.requested_page {
                    return Err(Pause::Done);
                }
                round.requested_page = true;
                pace(peer, round)?;
                let Some(page) = peer.source.inventory_until(
                    (range.from, range.to),
                    range.after,
                    Self::PAGE_ENTRIES,
                    round.stop,
                    round.deadline,
                )?
                else {
                    return Err(Pause::Done);
                };
                if !accept(range, page)? {
                    *slot = None;
                }
            } else {
                let through = range.to.min(range.scanned_through);
                engine.record_peer_coverage(&peer.id, range.from, through, range.generation)?;
                *slot = None;
            }
        }
        Ok(())
    }

    /// Fetch one advertised record from the advertising peer and admit it. A
    /// peer that answers Missing leaves the entry listed-only: it neither blocks
    /// coverage nor is retried within this range.
    fn acquire(
        &self,
        peer: &Peer,
        engine: &Engine,
        entry: &Placement,
        deadline: Instant,
    ) -> Result<(), Pause> {
        let Some(package) = peer.source.fetch_until(entry.txid, deadline)? else {
            return Ok(());
        };
        let receipt = match engine.admit_record(package) {
            Ok(receipt) => receipt,
            Err(error) => {
                if !matches!(error, Error::Busy(_) | Error::Stale) {
                    self.rejected.fetch_add(1, Ordering::Relaxed);
                }
                return Err(Pause::Error(error));
            }
        };
        self.admitted.fetch_add(1, Ordering::Relaxed);
        if !placed(&receipt, entry) {
            return Err(Pause::Error(Error::Invalid(
                "peer inventory placement disagrees with its proven record".into(),
            )));
        }
        Ok(())
    }

    pub(crate) fn status(&self, engine: &Engine) -> Result<OverlayStatus, Error> {
        let start = engine.status()?.application_start.height;
        let mut peers = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
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
        })
    }
}

/// Keep requests to one peer at least `REQUEST_SPACING` apart, waiting in
/// short slices so cancellation and the round deadline stay responsive.
fn pace(peer: &Peer, round: &Round) -> Result<(), Pause> {
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
