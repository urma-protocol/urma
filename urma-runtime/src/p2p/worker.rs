use crate::config::{
    P2P_FETCH_ATTEMPTS, P2P_IDLE_POLL_MILLIS, P2P_MAX_HEADERS_PER_MESSAGE, P2P_MIN_PEERS,
    P2P_PREFETCH_BLOCKS,
};
use crate::error::Error;
use crate::p2p::blocks::{BlockCache, Held};
use crate::p2p::headers::{Extension, HeaderChain};
use crate::p2p::peers::Peers;
use bitcoin::BlockHash;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
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
    let mut peers = Peers::new(shared.chain, shared.pinned.clone());
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        maintain_peers(&shared, &mut peers);
        let synced = locked(&shared.status, "status").synced;
        if !synced {
            if !sync_round(&shared, &mut peers) {
                std::thread::sleep(Duration::from_millis(P2P_IDLE_POLL_MILLIS));
            }
            continue;
        }
        match commands.recv() {
            Ok(command) => serve(&shared, &mut peers, command),
            Err(error) => {
                tracing::warn!(%error, "light client command channel closed; worker stops");
                return;
            }
        }
    }
}

fn maintain_peers(shared: &Shared, peers: &mut Peers) {
    peers.absorb_gossip();
    if peers.count() < P2P_MIN_PEERS {
        let height = locked(&shared.headers, "headers").tip_height();
        peers.discover();
        peers.top_up(height);
        tracing::debug!(
            connected = peers.count(),
            pooled = peers.pool_size(),
            "peer set maintained"
        );
    }
    let mut status = locked(&shared.status, "status");
    status.peers = peers.count();
    status.target = status.target.max(peers.best_height());
}

fn now_unix() -> Result<u32, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::Invalid(format!("system clock precedes the unix epoch: {error}"))
        })?;
    Ok(u32::try_from(elapsed.as_secs())?)
}

fn serve(shared: &Shared, peers: &mut Peers, command: Command) {
    match command {
        Command::Refresh { reply } => {
            let outcome = match sync_round(shared, peers) {
                true => Ok(()),
                false => Err(Error::Unsupported(
                    "no peer answered the header refresh".into(),
                )),
            };
            match reply.send(outcome) {
                Ok(()) => (),
                Err(error) => tracing::warn!(%error, "refresh requester went away"),
            }
        }
        Command::Block { hash, reply } => match reply.send(fetch_block(shared, peers, hash)) {
            Ok(()) => (),
            Err(error) => tracing::warn!(%error, "block requester went away"),
        },
    }
}

fn sync_round(shared: &Shared, peers: &mut Peers) -> bool {
    let mut answered = 0;
    let mut index = 0;
    while index < peers.count() {
        match sync_from(shared, peers, index) {
            Ok(()) => {
                answered += 1;
                index += 1;
            }
            Err(error @ Error::Invalid(_)) => {
                tracing::warn!(peer = %peers.connected[index].address, %error, "peer banned for invalid headers");
                peers.ban_peer(index);
            }
            Err(error) => {
                tracing::warn!(peer = %peers.connected[index].address, %error, "peer dropped during header sync");
                peers.drop_peer(index);
            }
        }
    }
    let mut status = locked(&shared.status, "status");
    status.peers = peers.count();
    if answered > 0 {
        status.synced = true;
        status.refreshed = Freshness::At(Instant::now());
        let tip = locked(&shared.headers, "headers").tip_height();
        status.target = status.target.max(tip);
    }
    answered > 0
}

fn sync_from(shared: &Shared, peers: &mut Peers, index: usize) -> Result<(), Error> {
    loop {
        let locator = locked(&shared.headers, "headers").locator();
        let batch = peers.connected[index].request_headers(locator)?;
        let now = now_unix()?;
        let outcome = {
            let mut headers = locked(&shared.headers, "headers");
            let outcome = headers.extend(&batch, now)?;
            match outcome {
                Extension::Ignored => (),
                Extension::Appended(..) | Extension::Reorganized { .. } => headers.persist()?,
            }
            outcome
        };
        match outcome {
            Extension::Ignored => return Ok(()),
            Extension::Appended(count) => {
                tracing::info!(peer = %peers.connected[index].address, count, "headers appended");
            }
            Extension::Reorganized {
                fork_height,
                appended,
            } => {
                tracing::warn!(peer = %peers.connected[index].address, fork_height, appended, "header chain reorganized");
                locked(&shared.blocks, "blocks").prune_above(fork_height);
            }
        }
        if batch.len() < P2P_MAX_HEADERS_PER_MESSAGE {
            return Ok(());
        }
    }
}

fn fetch_block(shared: &Shared, peers: &mut Peers, hash: BlockHash) -> Result<Vec<u8>, Error> {
    let (height, tip) = {
        let headers = locked(&shared.headers, "headers");
        let height = headers.height_of(hash)?;
        (height, headers.tip_height())
    };
    match locked(&shared.blocks, "blocks").get(hash) {
        Held::Cached(raw) => return Ok(raw),
        Held::Absent => (),
    }
    let mut failures = Vec::new();
    let mut lacking = HashSet::new();
    for attempt in 0..P2P_FETCH_ATTEMPTS {
        let usable = |peers: &Peers| {
            peers
                .order_for_block(height, tip)
                .into_iter()
                .find(|index| !lacking.contains(&peers.connected[*index].address))
        };
        let Some(index) = usable(peers) else {
            locked(&shared.status, "status").peers = peers.count();
            return Err(Error::Unsupported(format!(
                "block {hash}: no connected peer after {attempt} attempts: {}",
                failures.join("; ")
            )));
        };
        let address = peers.connected[index].address;
        match fetch_from(shared, peers, index, hash, height) {
            Ok(raw) => return Ok(raw),
            Err(Error::Missing(message)) => {
                tracing::warn!(peer = %address, %message, "peer lacks the requested block");
                failures.push(message);
                lacking.insert(address);
            }
            Err(error @ Error::Invalid(_)) => {
                tracing::warn!(peer = %address, %error, "peer banned for an invalid block");
                failures.push(error.to_string());
                peers.ban_peer(index);
            }
            Err(error) => {
                tracing::warn!(peer = %address, %error, attempt, "peer dropped during block fetch; retrying with another peer");
                failures.push(error.to_string());
                peers.drop_peer(index);
            }
        }
    }
    Err(Error::Unsupported(format!(
        "block {hash} unavailable after {P2P_FETCH_ATTEMPTS} peer attempts: {}",
        failures.join("; ")
    )))
}

fn fetch_from(
    shared: &Shared,
    peers: &mut Peers,
    index: usize,
    hash: BlockHash,
    height: u64,
) -> Result<Vec<u8>, Error> {
    let raw = peers.connected[index].request_block(hash)?;
    admit_block(shared, &raw, hash, height)?;
    prefetch(shared, peers, height, index);
    Ok(raw)
}

fn admit_block(shared: &Shared, raw: &[u8], hash: BlockHash, height: u64) -> Result<(), Error> {
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

fn prefetch_targets(shared: &Shared, served: u64) -> Vec<(u64, BlockHash)> {
    let headers = locked(&shared.headers, "headers");
    let blocks = locked(&shared.blocks, "blocks");
    let mut targets = Vec::new();
    let tip = headers.tip_height();
    let last = (served + P2P_PREFETCH_BLOCKS).min(tip);
    for height in served + 1..=last {
        let hash = match headers.hash_at(height) {
            Ok(hash) => hash,
            Err(error) => {
                tracing::warn!(height, %error, "prefetch stopped at a header the chain no longer holds");
                break;
            }
        };
        match blocks.get(hash) {
            Held::Cached(_raw) => continue,
            Held::Absent => targets.push((height, hash)),
        }
    }
    targets
}

fn prefetch(shared: &Shared, peers: &mut Peers, served: u64, served_by: usize) {
    let targets = prefetch_targets(shared, served);
    let mut asked = Vec::new();
    for (slot, (height, hash)) in targets.into_iter().enumerate() {
        if slot >= peers.count() {
            break;
        }
        let index = (served_by + 1 + slot) % peers.count();
        match peers.connected[index].ask_block(hash) {
            Ok(()) => asked.push((index, height, hash)),
            Err(error) => {
                tracing::warn!(peer = %peers.connected[index].address, %error, "prefetch request failed");
            }
        }
    }
    let mut dropped = Vec::new();
    for (index, height, hash) in asked {
        let answer = peers.connected[index].await_block(hash);
        match answer.and_then(|raw| admit_block(shared, &raw, hash, height)) {
            Ok(()) => tracing::debug!(height, "block prefetched"),
            Err(error) => {
                tracing::warn!(peer = %peers.connected[index].address, %error, height, "prefetch failed; peer dropped");
                dropped.push(index);
            }
        }
    }
    dropped.sort_unstable();
    for index in dropped.into_iter().rev() {
        peers.drop_peer(index);
    }
    locked(&shared.status, "status").peers = peers.count();
}
