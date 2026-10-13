use crate::config::{
    P2P_FETCH_ATTEMPTS, P2P_IDLE_POLL_MILLIS, P2P_MAX_HEADERS_PER_MESSAGE, P2P_TOP_UP_BUDGET_SECS,
};
use crate::error::Error;
use crate::p2p::blocks::{BlockCache, Held};
use crate::p2p::headers::{Extension, HeaderChain};
use crate::p2p::peer::Peer;
use crate::p2p::peers::Peers;
use crate::p2p::pipeline::{self, Holder, InFlight};
use bitcoin::BlockHash;
use bitcoin::block::Header;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urma_chain::decode;
use urma_chain::observation::Chain;

pub(super) enum Command {
    Block {
        hash: BlockHash,
        reply: SyncSender<Result<Vec<u8>, Error>>,
    },
    Refresh {
        reply: SyncSender<Result<(), Error>>,
    },
}

pub(super) enum Freshness {
    Never,
    At(Instant),
}

pub(super) struct Status {
    pub(super) peers: usize,
    pub(super) target: u64,
    pub(super) synced: bool,
    pub(super) refreshed: Freshness,
}

pub(super) struct Shared {
    pub(super) chain: Chain,
    pub(super) pinned: Vec<SocketAddr>,
    pub(super) cache_dir: PathBuf,
    pub(super) headers: Mutex<HeaderChain>,
    pub(super) blocks: Mutex<BlockCache>,
    pub(super) status: Mutex<Status>,
    pub(super) stop: AtomicBool,
}

pub(super) fn locked<'a, T>(mutex: &'a Mutex<T>, what: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(
                what,
                "light client lock poisoned; continuing with its last state"
            );
            poisoned.into_inner()
        }
    }
}

pub(super) fn run(shared: Arc<Shared>, commands: Receiver<Command>) {
    let mut peers = Peers::new(shared.chain, shared.pinned.clone(), &shared.cache_dir);
    let mut flight = InFlight::default();
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        maintain_peers(&shared, &mut peers);
        pipeline::settle(&shared, &mut peers, &mut flight);
        let synced = locked(&shared.status, "status").synced;
        if !synced {
            if sync_round(&shared, &mut peers).is_err() {
                std::thread::sleep(Duration::from_millis(P2P_IDLE_POLL_MILLIS));
            }
            continue;
        }
        match commands.recv_timeout(Duration::from_millis(P2P_IDLE_POLL_MILLIS)) {
            Ok(command) => serve(&shared, &mut peers, &mut flight, command),
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => {
                tracing::warn!("light client command channel closed; worker stops");
                return;
            }
        }
    }
}

fn maintain_peers(shared: &Shared, peers: &mut Peers) {
    peers.poll_idle();
    peers.absorb_gossip();
    if peers.count() < peers.target() {
        let height = locked(&shared.headers, "headers").tip_height();
        let started = Instant::now();
        peers.discover();
        tracing::debug!(
            target: "urma_startup",
            chain = shared.chain.label(),
            stage = "peer_discovery",
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            pooled = peers.pool_size(),
            "light client stage completed"
        );
        let started = Instant::now();
        let patience = match peers.count() {
            0 => Duration::from_secs(P2P_TOP_UP_BUDGET_SECS),
            _ => Duration::ZERO,
        };
        peers.top_up(height, patience);
        tracing::debug!(
            target: "urma_startup",
            chain = shared.chain.label(),
            stage = "peer_connect",
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            connected = peers.count(),
            dialing = peers.dialing(),
            pooled = peers.pool_size(),
            "light client stage completed"
        );
    }
    let mut status = locked(&shared.status, "status");
    status.peers = peers.count();
    status.target = status.target.max(peers.announced_height());
}

fn now_unix() -> Result<u32, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::Invalid(format!("system clock precedes the unix epoch: {error}"))
        })?;
    Ok(u32::try_from(elapsed.as_secs())?)
}

fn serve(shared: &Shared, peers: &mut Peers, flight: &mut InFlight, command: Command) {
    match command {
        Command::Refresh { reply } => {
            let outcome = sync_round(shared, peers);
            match reply.send(outcome) {
                Ok(()) => (),
                Err(error) => tracing::warn!(%error, "refresh requester went away"),
            }
        }
        Command::Block { hash, reply } => {
            match reply.send(fetch_block(shared, peers, flight, hash)) {
                Ok(()) => (),
                Err(error) => tracing::warn!(%error, "block requester went away"),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HeaderPeerAction {
    Advance,
    KeepForContext,
    Ban,
    Drop,
}

#[derive(Default)]
struct HeaderRound {
    answered: usize,
    context: Option<Error>,
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod sync_tests;

#[cfg(test)]
mod header_round_tests {
    use super::*;
    use urma_chain::pow::PowError;

    fn missing() -> Error {
        Error::Context {
            message: "retarget".into(),
            cause: Box::new(Error::HeaderContext(PowError::ShortWindow {
                needed: 2017,
                got: 2,
            })),
        }
    }

    #[test]
    fn local_context_preserves_peer_without_counting_a_successful_answer() {
        let mut round = HeaderRound::default();
        assert_eq!(
            round.observe(Err(missing())),
            HeaderPeerAction::KeepForContext
        );
        assert_eq!(round.answered, 0);
        assert_eq!(
            round.observe(Err(Error::Invalid("bits".into()))),
            HeaderPeerAction::Ban
        );
        assert_eq!(
            round.observe(Err(Error::Io(std::io::ErrorKind::TimedOut.into()))),
            HeaderPeerAction::Drop
        );
        assert_eq!(round.answered, 0);
        assert!(round.finish().unwrap_err().is_header_context());
    }

    #[test]
    fn only_successful_sync_counts_and_empty_round_is_not_success() {
        assert!(matches!(
            HeaderRound::default().finish(),
            Err(Error::Unsupported(_))
        ));
        let mut round = HeaderRound::default();
        assert_eq!(
            round.observe(Err(missing())),
            HeaderPeerAction::KeepForContext
        );
        assert_eq!(round.observe(Ok(())), HeaderPeerAction::Advance);
        assert_eq!(round.answered, 1);
        assert_eq!(
            round.observe(Err(missing())),
            HeaderPeerAction::KeepForContext
        );
        assert_eq!(round.answered, 1);
        round.finish().unwrap();
    }
}

impl HeaderRound {
    fn observe(&mut self, outcome: Result<(), Error>) -> HeaderPeerAction {
        match outcome {
            Ok(()) => {
                self.answered += 1;
                HeaderPeerAction::Advance
            }
            Err(error) if error.is_header_context() => {
                self.context = Some(error);
                HeaderPeerAction::KeepForContext
            }
            Err(Error::Invalid(_)) => HeaderPeerAction::Ban,
            Err(_) => HeaderPeerAction::Drop,
        }
    }

    fn finish(self) -> Result<(), Error> {
        if self.answered > 0 {
            Ok(())
        } else {
            Err(self.context.unwrap_or_else(|| {
                Error::Unsupported("no peer answered the header refresh".into())
            }))
        }
    }
}

fn sync_round(shared: &Shared, peers: &mut Peers) -> Result<(), Error> {
    let started = Instant::now();
    let refreshing = locked(&shared.status, "status").synced;
    let mut round = HeaderRound::default();
    let tip = locked(&shared.headers, "headers").tip_height();
    let order: Vec<SocketAddr> = peers
        .order_for_headers(tip)
        .into_iter()
        .map(|index| peers.connected[index].address)
        .collect();
    for address in order {
        let Some(index) = peers
            .connected
            .iter()
            .position(|peer| peer.address == address)
        else {
            continue;
        };
        let (advanced, outcome) = match sync_from(shared, peers, index) {
            Ok(advanced) => (advanced, Ok(())),
            Err(error) => {
                tracing::warn!(peer = %peers.connected[index].address, %error, "header synchronization failed");
                (false, Err(error))
            }
        };
        let tip = locked(&shared.headers, "headers").tip_height();
        let caught_up = tip >= peers.best_height(tip);
        match round.observe(outcome) {
            HeaderPeerAction::Advance if refreshing && advanced && caught_up => break,
            HeaderPeerAction::Advance | HeaderPeerAction::KeepForContext => (),
            HeaderPeerAction::Ban => {
                peers.ban_peer(index);
            }
            HeaderPeerAction::Drop => {
                peers.drop_peer(index);
            }
        }
    }
    let answered = round.answered;
    let mut status = locked(&shared.status, "status");
    status.peers = peers.count();
    if answered > 0 {
        status.synced = true;
        status.refreshed = Freshness::At(Instant::now());
        let tip = locked(&shared.headers, "headers").tip_height();
        status.target = status.target.max(tip);
    }
    tracing::debug!(
        target: "urma_startup",
        chain = shared.chain.label(),
        stage = "header_sync_round",
        elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
        answered,
        connected = status.peers,
        success = answered > 0,
        "light client stage completed"
    );
    round.finish()
}

fn record_proof(shared: &Shared, peer: &mut Peer, batch: &[Header]) {
    let headers = locked(&shared.headers, "headers");
    let Some(last) = batch.last() else {
        peer.start_height = peer
            .start_height
            .min(headers.tip_height().saturating_sub(1));
        return;
    };
    match headers.height_of(last.block_hash()) {
        Ok(height) => {
            peer.proven_height = match peer.proven_height {
                Some(proven) => Some(proven.max(height)),
                None => Some(height),
            }
        }
        Err(error) => {
            tracing::debug!(peer = %peer.address, %error, "headers answer is off our chain")
        }
    }
}

fn sync_from(shared: &Shared, peers: &mut Peers, index: usize) -> Result<bool, Error> {
    let mut advanced = false;
    loop {
        let mut locator = locked(&shared.headers, "headers").locator();
        if locator.len() > 1 {
            locator.remove(0);
        }
        let started = Instant::now();
        let requested = peers.connected[index].request_headers(locator);
        tracing::debug!(
            target: "urma_startup",
            chain = shared.chain.label(),
            stage = "header_request",
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            result = ?requested.as_ref().map(Vec::len),
            "light client stage completed"
        );
        let batch = requested?;
        let now = now_unix()?;
        let outcome = {
            let mut headers = locked(&shared.headers, "headers");
            let started = Instant::now();
            let extended = headers.extend(&batch, now);
            tracing::debug!(
                target: "urma_startup",
                chain = shared.chain.label(),
                stage = "header_batch_apply",
                elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
                headers = batch.len(),
                result = ?extended,
                "light client stage completed"
            );
            let outcome = extended?;
            match outcome {
                Extension::Ignored => (),
                Extension::Appended(..) | Extension::Reorganized { .. } => {
                    let started = Instant::now();
                    let persisted = headers.persist();
                    tracing::debug!(
                        target: "urma_startup",
                        chain = shared.chain.label(),
                        stage = "header_persist",
                        elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
                        headers = headers.synced_count() + 1,
                        result = ?persisted,
                        "light client stage completed"
                    );
                    persisted?;
                }
            }
            outcome
        };
        record_proof(shared, &mut peers.connected[index], &batch);
        match outcome {
            Extension::Ignored => return Ok(advanced),
            Extension::Appended(count) => {
                advanced = true;
                tracing::info!(peer = %peers.connected[index].address, count, "headers appended");
            }
            Extension::Reorganized {
                fork_height,
                appended,
            } => {
                advanced = true;
                tracing::warn!(peer = %peers.connected[index].address, fork_height, appended, "header chain reorganized");
                locked(&shared.blocks, "blocks").prune_above(fork_height);
            }
        }
        if batch.len() < P2P_MAX_HEADERS_PER_MESSAGE {
            return Ok(advanced);
        }
    }
}

fn fetch_block(
    shared: &Shared,
    peers: &mut Peers,
    flight: &mut InFlight,
    hash: BlockHash,
) -> Result<Vec<u8>, Error> {
    let height = locked(&shared.headers, "headers").height_of(hash)?;
    let held = locked(&shared.blocks, "blocks").get(hash);
    match held {
        Held::Cached(raw) => {
            pipeline::fill(shared, peers, flight, height + 1, &HashSet::new());
            return Ok(raw);
        }
        Held::Absent => (),
    }
    let mut failures = Vec::new();
    let mut lacking = HashSet::new();
    for attempt in 0..P2P_FETCH_ATTEMPTS {
        if let Holder::Nobody = flight.holder(hash) {
            pipeline::fill(shared, peers, flight, height, &lacking);
        }
        let holder = match flight.holder(hash) {
            Holder::Peer(address) => peers
                .connected
                .iter()
                .position(|peer| peer.address == address),
            Holder::Nobody => None,
        };
        let Some(index) = holder else {
            locked(&shared.status, "status").peers = peers.count();
            return Err(Error::Unsupported(format!(
                "block {hash}: no connected peer after {attempt} attempts: {}",
                failures.join("; ")
            )));
        };
        let address = peers.connected[index].address;
        match pipeline::receive(shared, peers, flight, index, (height, hash)) {
            Ok(raw) => {
                pipeline::fill(shared, peers, flight, height + 1, &lacking);
                return Ok(raw);
            }
            Err(Error::Missing(message)) => {
                tracing::warn!(peer = %address, %message, "peer lacks the requested block");
                failures.push(message);
                lacking.insert(address);
                flight.forget(hash);
            }
            Err(error @ Error::Invalid(_)) => {
                tracing::warn!(peer = %address, %error, "peer banned for an invalid block");
                failures.push(error.to_string());
                flight.forget_peer(address);
                peers.ban_peer(index);
            }
            Err(error) => {
                tracing::warn!(peer = %address, %error, attempt, "peer dropped during block fetch; retrying with another peer");
                failures.push(error.to_string());
                flight.forget_peer(address);
                peers.drop_peer(index);
            }
        }
    }
    Err(Error::Unsupported(format!(
        "block {hash} unavailable after {P2P_FETCH_ATTEMPTS} peer attempts: {}",
        failures.join("; ")
    )))
}

pub(super) fn admit_block(
    shared: &Shared,
    raw: &[u8],
    hash: BlockHash,
    height: u64,
) -> Result<(), Error> {
    let block = decode::esplora_block(raw, shared.chain, hash)?;
    let expected = locked(&shared.headers, "headers").header_at(height)?;
    if block.header != expected {
        return Err(Error::Invalid(
            "peer block header differs from the verified header".into(),
        ));
    }
    locked(&shared.blocks, "blocks").insert(hash, height, raw.to_vec());
    Ok(())
}
