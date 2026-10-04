use crate::config::{
    P2P_ADDRESS_POOL, P2P_CONNECT_ATTEMPTS_PER_ROUND, P2P_LIMITED_PEER_DEPTH, P2P_MAX_PEERS,
};
use crate::error::{Error, ensure};
use crate::p2p::peer::Peer;
use rand::seq::SliceRandom;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use urma_chain::observation::Chain;

pub(super) struct Peers {
    chain: Chain,
    candidates: VecDeque<SocketAddr>,
    tried: HashSet<SocketAddr>,
    banned: HashSet<IpAddr>,
    pub(super) connected: Vec<Peer>,
}

impl Peers {
    pub(super) fn new(chain: Chain) -> Self {
        Self {
            chain,
            candidates: VecDeque::new(),
            tried: HashSet::new(),
            banned: HashSet::new(),
            connected: Vec::new(),
        }
    }

    pub(super) fn seed(&mut self) -> Result<(), Error> {
        let params = self.chain.params();
        let mut found = Vec::new();
        for seed in params.dns_seeds {
            match (*seed, params.port).to_socket_addrs() {
                Ok(addresses) => found.extend(addresses),
                Err(error) => tracing::warn!(seed, %error, "dns seed did not resolve"),
            }
        }
        found.shuffle(&mut rand::thread_rng());
        for address in found {
            self.offer(address);
        }
        ensure!(
            !self.candidates.is_empty(),
            "no peer addresses resolved from the {} dns seeds",
            self.chain.label()
        );
        Ok(())
    }

    fn offer(&mut self, address: SocketAddr) {
        if self.candidates.len() >= P2P_ADDRESS_POOL
            || self.tried.contains(&address)
            || self.banned.contains(&address.ip())
            || self.candidates.contains(&address)
        {
            return;
        }
        self.candidates.push_back(address);
    }

    pub(super) fn absorb_gossip(&mut self) {
        let mut learned = Vec::new();
        for peer in &mut self.connected {
            learned.append(&mut peer.learned);
        }
        learned.shuffle(&mut rand::thread_rng());
        for address in learned {
            self.offer(address);
        }
    }

    pub(super) fn top_up(&mut self, our_height: u64) {
        let mut attempts = 0;
        while self.connected.len() < P2P_MAX_PEERS && attempts < P2P_CONNECT_ATTEMPTS_PER_ROUND {
            let Some(address) = self.candidates.pop_front() else {
                break;
            };
            attempts += 1;
            self.tried.insert(address);
            match Peer::connect(self.chain, address, our_height) {
                Ok(peer) => {
                    tracing::info!(peer = %address, services = %peer.services, height = peer.start_height, "peer connected");
                    self.connected.push(peer);
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
        self.banned.insert(peer.address.ip());
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
