use crate::config::{
    P2P_CONNECT_ATTEMPTS_PER_ROUND, P2P_LIMITED_PEER_DEPTH, P2P_MIN_PEERS, P2P_SEED_TIMEOUT_SECS,
    P2P_TOP_UP_BUDGET_SECS,
};
use crate::error::Error;
use crate::p2p::discovery::{Discovery, Next};
use crate::p2p::peer::Peer;
use rand::seq::SliceRandom;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;

struct Resolution {
    seed: &'static str,
    outcome: Result<Vec<SocketAddr>, std::io::Error>,
}

pub(super) struct Peers {
    chain: Chain,
    discovery: Discovery,
    pinned: Vec<SocketAddr>,
    answers: Receiver<Resolution>,
    asker: SyncSender<Resolution>,
    inflight: usize,
    pub(super) connected: Vec<Peer>,
}

impl Peers {
    pub(super) fn new(chain: Chain, pinned: Vec<SocketAddr>) -> Self {
        let (asker, answers) = mpsc::sync_channel(64);
        Self {
            chain,
            discovery: Discovery::new(),
            pinned,
            answers,
            asker,
            inflight: 0,
            connected: Vec::new(),
        }
    }

    pub(super) fn discover(&mut self) {
        let now = Instant::now();
        self.collect(Duration::ZERO);
        if !self.discovery.seeding_due(now) {
            return;
        }
        self.discovery.mark_seeded(now);
        if !self.pinned.is_empty() {
            self.discovery.readmit(self.pinned.clone());
            return;
        }
        let params = self.chain.params();
        for seed in params.dns_seeds {
            let asker = self.asker.clone();
            let port = params.port;
            let spawned = std::thread::Builder::new()
                .name("urma-dns".into())
                .spawn(move || {
                    let outcome = (*seed, port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.collect());
                    match asker.send(Resolution { seed, outcome }) {
                        Ok(()) => (),
                        Err(error) => tracing::warn!(seed, %error, "dns answer arrived after discovery closed"),
                    }
                });
            match spawned {
                Ok(_handle) => self.inflight += 1,
                Err(error) => tracing::warn!(seed, %error, "dns resolver thread could not start"),
            }
        }
        self.collect(Duration::from_secs(P2P_SEED_TIMEOUT_SECS));
        if self.discovery.drought_warns(Instant::now()) {
            tracing::warn!(
                chain = self.chain.label(),
                "no peer addresses resolved from any dns seed for a whole interval"
            );
        }
    }

    pub(super) fn pool_size(&self) -> usize {
        self.discovery.len()
    }

    fn collect(&mut self, patience: Duration) {
        let mut arrived = Vec::new();
        for resolution in self.answers.try_iter() {
            arrived.push(resolution);
        }
        for resolution in arrived {
            self.inflight -= 1;
            self.admit(resolution);
        }
        let deadline = Instant::now() + patience;
        while self.inflight > 0 {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            match self.answers.recv_timeout(remaining) {
                Ok(resolution) => {
                    self.inflight -= 1;
                    self.admit(resolution);
                }
                Err(RecvTimeoutError::Timeout) => {
                    tracing::warn!(
                        pending = self.inflight,
                        "dns seeds still unanswered after the discovery window; continuing without them"
                    );
                    return;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    tracing::error!("dns answer channel closed while answers were pending");
                    return;
                }
            }
        }
    }

    fn admit(&mut self, resolution: Resolution) {
        match resolution.outcome {
            Ok(mut addresses) => {
                addresses.shuffle(&mut rand::thread_rng());
                tracing::debug!(
                    seed = resolution.seed,
                    count = addresses.len(),
                    "dns seed resolved"
                );
                self.discovery.offer_seeded(addresses);
            }
            Err(error) => match self.discovery.is_empty() && self.inflight == 0 {
                true => {
                    tracing::warn!(seed = resolution.seed, %error, "last dns seed failed with an empty peer pool")
                }
                false => {
                    tracing::debug!(seed = resolution.seed, %error, "dns seed did not resolve; other seeds or pooled addresses remain")
                }
            },
        }
    }

    pub(super) fn absorb_gossip(&mut self) {
        let mut learned = Vec::new();
        for peer in &mut self.connected {
            learned.append(&mut peer.learned);
        }
        learned.shuffle(&mut rand::thread_rng());
        for address in learned {
            self.discovery.offer_gossip(address);
        }
    }

    pub(super) fn top_up(&mut self, our_height: u64) {
        let started = Instant::now();
        let mut attempts = 0;
        while self.connected.len() < P2P_MIN_PEERS
            && attempts < P2P_CONNECT_ATTEMPTS_PER_ROUND
            && started.elapsed() < Duration::from_secs(P2P_TOP_UP_BUDGET_SECS)
        {
            let Next::Address(address) = self.discovery.next() else {
                break;
            };
            attempts += 1;
            match Peer::connect(self.chain, address, our_height) {
                Ok(peer) => {
                    tracing::info!(peer = %address, services = %peer.services, height = peer.start_height, "peer connected");
                    self.connected.push(peer);
                }
                Err(Error::Io(error))
                    if error.kind() == std::io::ErrorKind::NetworkUnreachable
                        && address.is_ipv6() =>
                {
                    tracing::warn!(peer = %address, %error, "ipv6 unreachable; skipping ipv6 peers for this session");
                    self.discovery.unreachable_v6();
                }
                Err(error) => tracing::warn!(peer = %address, %error, "peer connection refused"),
            }
        }
    }

    pub(super) fn count(&self) -> usize {
        self.connected.len()
    }

    pub(super) fn best_height(&self) -> u64 {
        self.connected
            .iter()
            .map(|peer| peer.start_height)
            .fold(0, u64::max)
    }

    pub(super) fn drop_peer(&mut self, index: usize) {
        self.connected.remove(index);
    }

    pub(super) fn ban_peer(&mut self, index: usize) {
        let peer = self.connected.remove(index);
        self.discovery.ban(peer.address.ip());
    }

    pub(super) fn order_for_block(&self, height: u64, tip: u64) -> Vec<usize> {
        let deep = tip.max(height) - height > P2P_LIMITED_PEER_DEPTH;
        let mut full = Vec::new();
        let mut limited = Vec::new();
        for (index, peer) in self.connected.iter().enumerate() {
            match peer.limited() {
                true => limited.push(index),
                false => full.push(index),
            }
        }
        if !deep {
            full.append(&mut limited);
        }
        full
    }
}
