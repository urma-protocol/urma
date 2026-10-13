use crate::config::{
    P2P_CONNECT_TIMEOUT_SECS, P2P_DIAL_CONCURRENCY, P2P_GOSSIP_FUTURE_SECS,
    P2P_GOSSIP_PENALTY_SECS, P2P_IPV6_ROUTE_PROBE, P2P_LIMITED_PEER_DEPTH, P2P_MAX_PEERS,
};
use crate::error::Error;
use crate::p2p::addr::{routable, unix_now};
use crate::p2p::book::PeerBook;
use crate::p2p::discovery::{Discovery, Next};
use crate::p2p::peer::{Gossiped, Peer};
use rand::seq::SliceRandom;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;

struct Resolution {
    seed: &'static str,
    outcome: Result<Vec<SocketAddr>, std::io::Error>,
}

struct Dialed {
    address: SocketAddr,
    outcome: Result<Peer, Error>,
}

pub(super) struct Peers {
    chain: Chain,
    discovery: Discovery,
    pinned: Vec<SocketAddr>,
    book: PeerBook,
    answers: Receiver<Resolution>,
    asker: SyncSender<Resolution>,
    inflight: usize,
    dials: Receiver<Dialed>,
    dialer: Sender<Dialed>,
    dialing: HashSet<SocketAddr>,
    warmed: bool,
    pub(super) connected: Vec<Peer>,
}

fn ipv6_routable() -> bool {
    let probe = UdpSocket::bind("[::]:0").and_then(|socket| socket.connect(P2P_IPV6_ROUTE_PROBE));
    match probe {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(%error, "no ipv6 route; ipv6 peers are skipped");
            false
        }
    }
}

impl Peers {
    pub(super) fn new(chain: Chain, pinned: Vec<SocketAddr>, cache_dir: &Path) -> Self {
        let (asker, answers) = mpsc::sync_channel(64);
        let (dialer, dials) = mpsc::channel();
        let mut discovery = Discovery::new();
        if pinned.is_empty() && !ipv6_routable() {
            discovery.unreachable_v6();
        }
        Self {
            chain,
            discovery,
            pinned,
            book: PeerBook::open(cache_dir, chain),
            answers,
            asker,
            inflight: 0,
            dials,
            dialer,
            dialing: HashSet::new(),
            warmed: false,
            connected: Vec::new(),
        }
    }

    pub(super) fn discover(&mut self) {
        let now = Instant::now();
        self.collect();
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
        let mut fixed: Vec<SocketAddr> = Vec::new();
        for seed in params.fixed_seeds {
            match seed.parse() {
                Ok(address) => fixed.push(address),
                Err(error) => tracing::warn!(seed, %error, "fixed seed is not a socket address"),
            }
        }
        fixed.shuffle(&mut rand::thread_rng());
        self.discovery.readmit(fixed);
        self.discovery.readmit(self.book.addresses());
        if self.discovery.drought_warns(Instant::now()) {
            tracing::warn!(
                chain = self.chain.label(),
                "no peer addresses from the peer book, fixed seeds or dns seeds for a whole interval"
            );
        }
    }

    pub(super) fn pool_size(&self) -> usize {
        self.discovery.len()
    }

    #[cfg(test)]
    pub(super) fn redial_pending(&self) -> usize {
        self.discovery.redial_pending()
    }

    fn collect(&mut self) {
        let mut arrived = Vec::new();
        for resolution in self.answers.try_iter() {
            arrived.push(resolution);
        }
        for resolution in arrived {
            self.inflight -= 1;
            match resolution.outcome {
                Ok(mut addresses) => {
                    addresses.retain(routable);
                    addresses.shuffle(&mut rand::thread_rng());
                    tracing::debug!(
                        seed = resolution.seed,
                        count = addresses.len(),
                        "dns seed resolved"
                    );
                    for address in addresses {
                        self.discovery.offer_gossip(address);
                    }
                }
                Err(error) => {
                    tracing::debug!(seed = resolution.seed, %error, "dns seed did not resolve")
                }
            }
        }
    }

    pub(super) fn absorb_gossip(&mut self) {
        let mut learned = Vec::new();
        for peer in &mut self.connected {
            learned.append(&mut peer.learned);
        }
        self.admit_gossip(learned);
    }

    fn admit_gossip(&mut self, mut learned: Vec<Gossiped>) {
        if !self.pinned.is_empty() {
            tracing::trace!(count = learned.len(), "gossip ignored: peers are pinned");
            return;
        }
        let now = match unix_now() {
            Ok(now) => now,
            Err(error) => {
                tracing::warn!(%error, "gossip ignored: no usable clock to judge its age");
                return;
            }
        };
        learned.retain(|gossiped| routable(&gossiped.address));
        learned.sort_by_key(|gossiped| Reverse(credible_time(gossiped.time, now)));
        for gossiped in learned {
            self.discovery.offer_gossip(gossiped.address);
        }
    }

    pub(super) fn target(&self) -> usize {
        match self.pinned.is_empty() {
            true => P2P_MAX_PEERS,
            false => self.pinned.len(),
        }
    }

    pub(super) fn top_up(&mut self, our_height: u64, patience: Duration) {
        self.settle(our_height, 0, Duration::ZERO);
        self.launch(our_height);
        self.settle(our_height, 1, patience);
        if !self.warmed && !self.connected.is_empty() {
            self.warmed = true;
            let grace = Duration::from_secs(P2P_CONNECT_TIMEOUT_SECS);
            self.settle(our_height, self.target(), grace);
        }
    }

    fn held(&self, address: SocketAddr) -> bool {
        self.dialing.contains(&address) || self.connected.iter().any(|peer| peer.address == address)
    }

    fn launch(&mut self, our_height: u64) {
        while self.connected.len() < self.target() && self.dialing.len() < P2P_DIAL_CONCURRENCY {
            let Next::Address(address) = self.discovery.next(Instant::now()) else {
                return;
            };
            if self.held(address) {
                continue;
            }
            let dialer = self.dialer.clone();
            let chain = self.chain;
            let spawned = std::thread::Builder::new()
                .name("urma-dial".into())
                .spawn(move || {
                    let outcome = Peer::connect(chain, address, our_height);
                    match dialer.send(Dialed { address, outcome }) {
                        Ok(()) => (),
                        Err(error) => tracing::debug!(peer = %address, %error, "dial finished after the pool closed"),
                    }
                });
            match spawned {
                Ok(_handle) => {
                    self.dialing.insert(address);
                }
                Err(error) => {
                    tracing::warn!(peer = %address, %error, "dial thread could not start");
                    return;
                }
            }
        }
    }

    fn settle(&mut self, our_height: u64, goal: usize, patience: Duration) {
        let deadline = Instant::now() + patience;
        while !self.dialing.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let waited = match self.connected.len() < goal && !remaining.is_zero() {
                true => self.dials.recv_timeout(remaining),
                false => match self.dials.try_recv() {
                    Ok(dialed) => Ok(dialed),
                    Err(TryRecvError::Empty) => Err(RecvTimeoutError::Timeout),
                    Err(TryRecvError::Disconnected) => Err(RecvTimeoutError::Disconnected),
                },
            };
            match waited {
                Ok(dialed) => {
                    self.dialing.remove(&dialed.address);
                    self.finish(dialed);
                    self.launch(our_height);
                }
                Err(RecvTimeoutError::Timeout) => return,
                Err(RecvTimeoutError::Disconnected) => {
                    tracing::error!("dial result channel closed while dials were pending");
                    return;
                }
            }
        }
    }

    fn finish(&mut self, dialed: Dialed) {
        let address = dialed.address;
        match dialed.outcome {
            Ok(peer) => {
                if self.pinned.is_empty() {
                    match unix_now() {
                        Ok(now) => self.book.record(address, now),
                        Err(error) => {
                            tracing::warn!(peer = %address, %error, "good peer not recorded")
                        }
                    }
                }
                if self.connected.len() >= self.target()
                    || self.connected.iter().any(|held| held.address == address)
                {
                    tracing::debug!(peer = %address, "dial succeeded after the peer target was met or the peer is already held");
                    return;
                }
                tracing::info!(peer = %address, services = %peer.services, height = peer.start_height, "peer connected");
                self.connected.push(peer);
                let pinned = &self.pinned;
                self.connected
                    .sort_by_key(|peer| pinned.iter().position(|address| *address == peer.address));
            }
            Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NetworkUnreachable
                    && address.is_ipv6()
                    && self.pinned.is_empty() =>
            {
                tracing::debug!(peer = %address, %error, "ipv6 unreachable; skipping ipv6 peers");
                self.discovery.unreachable_v6();
            }
            Err(error) => tracing::debug!(peer = %address, %error, "peer dial failed"),
        }
    }

    pub(super) fn poll_idle(&mut self) {
        let mut index = self.connected.len();
        while index > 0 {
            index -= 1;
            match self.connected[index].poll() {
                Ok(()) => (),
                Err(error) => {
                    tracing::info!(peer = %self.connected[index].address, %error, "peer dropped while idle");
                    self.drop_peer(index);
                }
            }
        }
    }

    pub(super) fn count(&self) -> usize {
        self.connected.len()
    }

    pub(super) fn dialing(&self) -> usize {
        self.dialing.len()
    }

    pub(super) fn best_height(&self, tip: u64) -> u64 {
        self.connected
            .iter()
            .map(|peer| peer.height_hint(tip))
            .fold(0, u64::max)
    }

    pub(super) fn announced_height(&self) -> u64 {
        self.connected
            .iter()
            .map(|peer| peer.start_height)
            .fold(0, u64::max)
    }

    pub(super) fn drop_peer(&mut self, index: usize) {
        let peer = self.connected.remove(index);
        self.discovery.dropped(peer.address, Instant::now());
    }

    pub(super) fn ban_peer(&mut self, index: usize) {
        let peer = self.connected.remove(index);
        self.discovery.ban(peer.address.ip());
    }

    pub(super) fn order_for_block(&self, height: u64, tip: u64) -> Vec<usize> {
        self.ranked(
            height,
            tip.max(height) - height > P2P_LIMITED_PEER_DEPTH,
            tip,
        )
    }

    pub(super) fn order_for_headers(&self, tip: u64) -> Vec<usize> {
        self.ranked(tip, false, tip)
    }

    fn ranked(&self, height: u64, deep: bool, tip: u64) -> Vec<usize> {
        let mut full = Vec::new();
        let mut limited = Vec::new();
        let holders = self
            .connected
            .iter()
            .any(|peer| peer.height_hint(tip) >= height);
        for (index, peer) in self.connected.iter().enumerate() {
            if holders && peer.height_hint(tip) < height {
                continue;
            }
            match peer.limited() {
                true => limited.push(index),
                false => full.push(index),
            }
        }
        if !deep {
            full.append(&mut limited);
        }
        if self.pinned.is_empty() {
            full.sort_by_key(|index| {
                let peer = &self.connected[*index];
                Reverse((peer.height_hint(tip), peer.proven_height))
            });
        }
        full
    }
}

fn credible_time(time: u32, now: u64) -> u64 {
    let time = u64::from(time);
    match time > now + P2P_GOSSIP_FUTURE_SECS {
        true => now.saturating_sub(P2P_GOSSIP_PENALTY_SECS),
        false => time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gossiped(address: &str, time: u32) -> Gossiped {
        Gossiped {
            address: address.parse().unwrap(),
            time,
        }
    }

    #[test]
    fn pinned_peers_ignore_gossip_and_set_the_connection_target() {
        let dir = tempfile::tempdir().unwrap();
        let now = u32::try_from(unix_now().unwrap()).unwrap();
        let learned = vec![
            gossiped("8.8.4.4:19335", now - 60),
            gossiped("9.9.9.9:19335", now - 30),
        ];
        let pinned = vec!["127.0.0.1:19335".parse().unwrap()];
        let mut peers = Peers::new(Chain::LitecoinTestnet, pinned, dir.path());
        peers.admit_gossip(learned.clone());
        assert_eq!(peers.pool_size(), 0);
        assert_eq!(peers.target(), 1);
        peers.discover();
        assert_eq!(
            peers.pool_size(),
            1,
            "pinned only: no book, fixed or dns seeds"
        );
        let mut open = Peers::new(Chain::LitecoinTestnet, Vec::new(), dir.path());
        open.admit_gossip(learned);
        assert_eq!(open.pool_size(), 2);
        assert_eq!(open.target(), P2P_MAX_PEERS);
        assert_eq!(
            open.discovery.next(Instant::now()),
            Next::Address("9.9.9.9:19335".parse().unwrap()),
            "the most recently seen gossip is dialed first"
        );
    }

    #[test]
    fn gossip_admits_only_routable_addresses_and_distrusts_future_times() {
        let dir = tempfile::tempdir().unwrap();
        let now = u32::try_from(unix_now().unwrap()).unwrap();
        let mut peers = Peers::new(Chain::LitecoinTestnet, Vec::new(), dir.path());
        peers.admit_gossip(vec![
            gossiped("127.0.0.1:19335", now),
            gossiped("192.168.1.5:19335", now),
            gossiped("100.64.0.1:19335", now),
            gossiped("198.18.0.1:19335", now),
            gossiped("8.8.8.8:0", now),
            gossiped("[fd00::1]:19335", now),
            gossiped("[fe80::1]:19335", now),
            gossiped("[2001:db8::1]:19335", now),
            gossiped("8.8.4.4:19335", now - 3600),
            gossiped("1.1.1.1:19335", u32::MAX),
        ]);
        assert_eq!(peers.pool_size(), 2);
        assert_eq!(
            peers.discovery.next(Instant::now()),
            Next::Address("8.8.4.4:19335".parse().unwrap()),
            "an hour-old address beats one claiming the far future"
        );
        assert_eq!(
            peers.discovery.next(Instant::now()),
            Next::Address("1.1.1.1:19335".parse().unwrap())
        );
    }

    #[test]
    fn pinned_ipv6_peers_survive_a_missing_ipv6_route() {
        let dir = tempfile::tempdir().unwrap();
        let pinned: SocketAddr = "[::1]:19335".parse().unwrap();
        let mut peers = Peers::new(Chain::LitecoinTestnet, vec![pinned], dir.path());
        peers.discover();
        assert_eq!(peers.discovery.next(Instant::now()), Next::Address(pinned));
    }
}
