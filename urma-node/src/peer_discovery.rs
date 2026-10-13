//! Bitcoin-style peer discovery. Seeds bootstrap a sparse book; afterwards
//! connected peers exchange verified addresses. A dial proves only that a
//! Noise identity on this chain answered at an address: never record
//! availability or honesty. Each Service round performs at most three
//! network operations and checks cancellation between them.
use crate::{
    Error,
    engine::Engine,
    model::DiscoveryStatus,
    peer::{PeerNetwork, PeerSource},
    peer_protocol::GossipPeer,
    peerbook::PeerBook,
    recorded::{RecordedError, read},
};
use libp2p::{Multiaddr, PeerId};
use rand::seq::SliceRandom;
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct Discovery {
    network: Arc<PeerNetwork>,
    book: Arc<Mutex<PeerBook>>,
    path: PathBuf,
    announce: Vec<Multiaddr>,
    round: AtomicU64,
    seed_error: Mutex<Option<RecordedError>>,
    gossip_error: Mutex<Option<RecordedError>>,
}

/// Network operations left in this round; stop ends the round early.
struct Budget<'a> {
    left: usize,
    stop: &'a AtomicBool,
}

impl Budget<'_> {
    fn take(&mut self) -> bool {
        if self.left == 0 || self.stop.load(Ordering::Acquire) {
            return false;
        }
        self.left -= 1;
        true
    }
}

fn poisoned() -> Error {
    Error::Invalid("peer discovery state poisoned".into())
}

fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| Error::Invalid(format!("system clock before 1970: {error}")))
}

impl Discovery {
    /// Connected peers the round tries to reach.
    pub const TARGET: usize = 8;
    pub const DIALS_PER_ROUND: usize = 2;
    pub const OPERATIONS_PER_ROUND: usize = 3;
    /// Rounds between address requests to one random connected peer.
    pub const GOSSIP_EVERY: u64 = 30;
    pub const GOSSIP_LIMIT: u32 = 32;
    /// Rounds between seed passes while below target.
    pub const SEED_EVERY: u64 = 600;
    /// At startup seeds are dialed while fewer entries than this are verified.
    pub const BOOTSTRAP_VERIFIED: u64 = 4;
    /// Wall-clock bound of one dial or address request.
    pub const OPERATION_TIME: Duration = Duration::from_secs(10);

    /// `path` is where the book is saved after a round changes it; `announce`
    /// are this node's own public addresses offered to peers.
    pub fn new(
        network: Arc<PeerNetwork>,
        book: Arc<Mutex<PeerBook>>,
        path: PathBuf,
        announce: Vec<Multiaddr>,
    ) -> Self {
        Self {
            network,
            book,
            path,
            announce,
            round: AtomicU64::new(0),
            seed_error: Mutex::new(None),
            gossip_error: Mutex::new(None),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, PeerBook>, Error> {
        self.book.lock().map_err(|_| poisoned())
    }

    /// Inventory peers from the book: identified, non-omitting, one per peer.
    pub fn sync_sources(&self, omitting: &[String]) -> Result<Vec<(String, PeerSource)>, Error> {
        let addresses = self.lock()?.sync_addresses(omitting);
        Ok(addresses
            .into_iter()
            .map(|address| (address.peer_id().to_string(), self.network.source(address)))
            .collect())
    }

    /// One bounded round: refresh the served gossip snapshot, seeds when due,
    /// up to two dials while below target, every thirtieth round one address
    /// request.
    pub fn step(&self, engine: &Engine, stop: &AtomicBool) -> Result<(), Error> {
        let round = self.round.fetch_add(1, Ordering::Relaxed);
        let omitting = engine.omitting_peers()?;
        self.publish(&omitting)?;
        let mut budget = Budget {
            left: Self::OPERATIONS_PER_ROUND,
            stop,
        };
        let mut changed = false;
        if self.seeds_due(round)? {
            changed |= self.dial_seeds(&omitting, &mut budget)?;
        }
        changed |= self.dial_candidates(&omitting, &mut budget)?;
        if round % Self::GOSSIP_EVERY == Self::GOSSIP_EVERY - 1 {
            changed |= self.ask_for_peers(&omitting, &mut budget)?;
        }
        if changed {
            self.lock()?.save(&self.path)?;
        }
        Ok(())
    }

    /// Verified book entries, plus this node when it announces addresses.
    fn publish(&self, omitting: &[String]) -> Result<(), Error> {
        let limit = usize::try_from(Self::GOSSIP_LIMIT)
            .map_err(|error| Error::Invalid(format!("gossip limit: {error}")))?;
        let at = now()?;
        let mut peers = Vec::new();
        if !self.announce.is_empty() {
            peers.push(GossipPeer {
                peer_id: self.network.peer_id(),
                addrs: self.announce.clone(),
                last_seen: at,
            });
        }
        for mut peer in self.lock()?.gossip(limit, omitting) {
            peer.last_seen = peer.last_seen.min(at);
            peers.push(peer);
        }
        self.network.set_gossip(peers);
        Ok(())
    }

    fn seeds_due(&self, round: u64) -> Result<bool, Error> {
        if self.network.connected_peer_ids().len() >= Self::TARGET {
            return Ok(false);
        }
        let verified = self.lock()?.stats().verified;
        Ok((round == 0 && verified < Self::BOOTSTRAP_VERIFIED)
            || (round > 0 && round % Self::SEED_EVERY == 0))
    }

    /// Dial one address outside the book lock and record the outcome.
    fn dial(&self, address: &Multiaddr, stop: &AtomicBool) -> Result<Result<PeerId, Error>, Error> {
        let deadline = Instant::now() + Self::OPERATION_TIME;
        let outcome = self.network.dial(address.clone(), stop, deadline);
        if stop.load(Ordering::Acquire) {
            return Ok(outcome);
        }
        let at = now()?;
        let mut book = self.lock()?;
        match &outcome {
            Ok(peer) => book.succeeded(address, *peer, self.network.peer_id(), at),
            Err(_failure) => book.failed(address, at),
        }
        Ok(outcome)
    }

    fn dial_seeds(&self, omitting: &[String], budget: &mut Budget) -> Result<bool, Error> {
        let seeds = self.lock()?.seeds(omitting);
        let mut dialed = false;
        let mut error = None;
        let mut reached = false;
        for seed in seeds {
            if !budget.take() {
                break;
            }
            dialed = true;
            match self.dial(&seed, budget.stop)? {
                Ok(_peer) => reached = true,
                Err(failure) => error = Some(format!("{seed}: {failure}")),
            }
        }
        if dialed {
            let recorded = if reached {
                None
            } else {
                error.map(RecordedError::now)
            };
            *self.seed_error.lock().map_err(|_| poisoned())? = recorded;
        }
        Ok(dialed)
    }

    fn dial_candidates(&self, omitting: &[String], budget: &mut Budget) -> Result<bool, Error> {
        let connected = self.network.connected_peer_ids();
        if connected.len() >= Self::TARGET {
            return Ok(false);
        }
        let candidates =
            self.lock()?
                .candidates(now()?, &connected, omitting, Self::DIALS_PER_ROUND);
        let mut dialed = false;
        for candidate in candidates {
            if !budget.take() {
                break;
            }
            dialed = true;
            // Either outcome is already recorded in the book (success or backoff).
            match self.dial(&candidate, budget.stop)? {
                Ok(_reached) => (),
                Err(_backed_off) => (),
            }
        }
        Ok(dialed)
    }

    /// Ask one random connected, non-omitting peer for addresses and merge
    /// them under the book's caps.
    fn ask_for_peers(&self, omitting: &[String], budget: &mut Budget) -> Result<bool, Error> {
        let connected: Vec<PeerId> = self
            .network
            .connected_peer_ids()
            .into_iter()
            .filter(|peer| !omitting.contains(&peer.to_string()))
            .collect();
        let Some(peer) = connected.choose(&mut rand::thread_rng()).copied() else {
            return Ok(false);
        };
        if !budget.take() {
            return Ok(false);
        }
        let deadline = Instant::now() + Self::OPERATION_TIME;
        let outcome = self
            .network
            .peers_of(peer, Self::GOSSIP_LIMIT, budget.stop, deadline);
        let mut error = self.gossip_error.lock().map_err(|_| poisoned())?;
        match outcome {
            Ok(peers) => {
                *error = None;
                let local = self.network.peer_id();
                Ok(self.lock()?.merge(&peers, local, omitting) > 0)
            }
            Err(failure) => {
                *error = Some(RecordedError::now(format!("{peer}: {failure}")));
                Ok(false)
            }
        }
    }

    pub fn status(&self) -> Result<DiscoveryStatus, Error> {
        let stats = self.lock()?.stats();
        let (last_seed_round_error, last_seed_round_error_at) =
            RecordedError::split(read(&self.seed_error, "seed round")?);
        let (last_gossip_error, last_gossip_error_at) =
            RecordedError::split(read(&self.gossip_error, "gossip")?);
        Ok(DiscoveryStatus {
            seeds: stats.seeds,
            book: stats.book,
            verified: stats.verified,
            gossip: stats.gossip,
            last_seed_round_error,
            last_seed_round_error_at,
            last_gossip_error,
            last_gossip_error_at,
        })
    }

    pub fn book_json(&self) -> Result<Value, Error> {
        Ok(self.lock()?.json())
    }
}
