use crate::config::{P2P_IDLE_POLL_MILLIS, P2P_MAX_HEADERS_PER_MESSAGE, P2P_MIN_PEERS};
use crate::error::Error;
use crate::p2p::blocks::{BlockCache, Held};
use crate::p2p::headers::{Extension, HeaderChain};
use crate::p2p::peers::Peers;
use bitcoin::BlockHash;
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
    let mut peers = Peers::new(shared.chain);
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
        match peers.seed() {
            Ok(()) => (),
            Err(error) => tracing::warn!(%error, "peer discovery incomplete"),
        }
        peers.top_up(height);
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
    maintain_peers(shared, peers);
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
    for round in 0..2 {
        if round == 1 {
            peers.top_up(tip);
        }
        let mut index = 0;
        let order = peers.order_for_block(height, tip);
        while index < order.len() && order[index] < peers.count() {
            match fetch_from(shared, peers, order[index], hash, height) {
                Ok(raw) => return Ok(raw),
                Err(Error::Missing(message)) => {
                    tracing::warn!(peer = %peers.connected[order[index]].address, %message, "peer lacks the requested block");
                    failures.push(message);
                    index += 1;
                }
                Err(error @ Error::Invalid(_)) => {
                    tracing::warn!(peer = %peers.connected[order[index]].address, %error, "peer banned for an invalid block");
                    failures.push(error.to_string());
                    peers.ban_peer(order[index]);
                    break;
                }
                Err(error) => {
                    tracing::warn!(peer = %peers.connected[order[index]].address, %error, "peer dropped during block fetch");
                    failures.push(error.to_string());
                    peers.drop_peer(order[index]);
                    break;
                }
            }
        }
    }
    Err(Error::Unsupported(format!(
        "block {hash} unavailable from connected peers: {}",
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
    let block = decode::esplora_block(&raw, shared.chain, hash)?;
    let expected = locked(&shared.headers, "headers").header_at(height)?;
    if block.header != expected {
        return Err(Error::Invalid(
            "peer block header differs from the verified header".into(),
        ));
    }
    locked(&shared.blocks, "blocks").insert(hash, height, raw.clone());
    Ok(raw)
}
