//! Peer gossip and explicit dialing. Gossiped addresses are untrusted routing
//! hints; a dial proves only the remote transport identity, and the Peers probe
//! that follows it only that the peer speaks this protocol on the same chain.
use crate::{
    Error,
    peer::{
        Answer, Behaviour, CALL_TIMEOUT, Command, PeerNetwork, Pending, bind_response, request,
    },
    peer_limits::LimitDenied,
    peer_protocol::{
        GossipPeer, Kind, PEER_ADDRESSES_MAX, PEERS_LIMIT, PEERS_MAX, Reply, Response,
    },
    source::check_cancelled,
};
use bitcoin::BlockHash;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    multiaddr::Protocol,
    swarm::{ConnectionId, DialError, dial_opts::DialOpts},
};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// State shared between the network thread and the owner: the gossip snapshot
/// the scheduler hands over, and public addresses peers observed for us.
pub(crate) struct Shared {
    local: PeerId,
    gossip: Mutex<Vec<GossipPeer>>,
    observed: Mutex<ObservedAddrs>,
    connected: Mutex<BTreeSet<PeerId>>,
    identified: Mutex<VecDeque<(PeerId, Vec<Multiaddr>)>>,
}

/// Public addresses outbound peers reported observing for this node. A
/// candidate is confirmed only once WITNESSES distinct peers reported it.
#[derive(Default)]
pub struct ObservedAddrs {
    candidates: Vec<(Multiaddr, BTreeSet<PeerId>)>,
    confirmed: Vec<Multiaddr>,
}

impl ObservedAddrs {
    pub const WITNESSES: usize = 2;
    const CANDIDATES_MAX: usize = 32;
    const CONFIRMED_MAX: usize = 8;

    /// Record one report; non-public or non-literal addresses are ignored.
    /// Returns the address when this report is the one that confirms it.
    pub fn observe(&mut self, address: Multiaddr, reporter: PeerId) -> Option<Multiaddr> {
        if !is_public(&address)
            || validate_gossip_address(&address).is_err()
            || self.confirmed.contains(&address)
        {
            return None;
        }
        let index = match self
            .candidates
            .iter()
            .position(|(known, _)| *known == address)
        {
            Some(index) => index,
            None => {
                if self.candidates.len() == Self::CANDIDATES_MAX {
                    self.candidates.remove(0);
                }
                self.candidates.push((address, BTreeSet::new()));
                self.candidates.len() - 1
            }
        };
        self.candidates[index].1.insert(reporter);
        if self.candidates[index].1.len() < Self::WITNESSES {
            return None;
        }
        let (address, _) = self.candidates.remove(index);
        if self.confirmed.len() == Self::CONFIRMED_MAX {
            self.confirmed.remove(0);
        }
        self.confirmed.push(address.clone());
        Some(address)
    }

    pub fn confirmed(&self) -> Vec<Multiaddr> {
        self.confirmed.clone()
    }
}

impl Shared {
    const GOSSIP_MAX: usize = 256;
    const IDENTIFIED_MAX: usize = 64;
    const ENVELOPE: usize = 1024;

    pub(crate) fn new(local: PeerId) -> Self {
        Self {
            local,
            gossip: Mutex::new(Vec::new()),
            observed: Mutex::new(ObservedAddrs::default()),
            connected: Mutex::new(BTreeSet::new()),
            identified: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue a connected peer's own literal public addresses (newest 64 peers).
    pub(crate) fn identified(&self, peer: PeerId, advertised: Vec<Multiaddr>) {
        let addresses: Vec<Multiaddr> = advertised
            .into_iter()
            .filter(|address| validate_gossip_address(address).is_ok() && is_public(address))
            .take(PEER_ADDRESSES_MAX)
            .collect();
        if addresses.is_empty() || peer == self.local {
            return;
        }
        let mut queue = match self.identified.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.retain(|(known, _)| *known != peer);
        if queue.len() == Self::IDENTIFIED_MAX {
            queue.pop_front();
        }
        queue.push_back((peer, addresses));
    }

    fn drain_identified(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        match self.identified.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        }
    }

    fn set_gossip(&self, mut peers: Vec<GossipPeer>) {
        peers.truncate(Self::GOSSIP_MAX);
        if let Ok(mut gossip) = self.gossip.lock() {
            *gossip = peers;
        }
    }

    fn observed(&self) -> Vec<Multiaddr> {
        match self.observed.lock() {
            Ok(observed) => observed.confirmed(),
            Err(poisoned) => poisoned.into_inner().confirmed(),
        }
    }

    pub(crate) fn is_connected(&self, peer: PeerId) -> bool {
        match self.connected.lock() {
            Ok(connected) => connected.contains(&peer),
            Err(poisoned) => poisoned.into_inner().contains(&peer),
        }
    }

    fn connected(&self) -> Vec<PeerId> {
        match self.connected.lock() {
            Ok(connected) => connected.iter().copied().collect(),
            Err(poisoned) => poisoned.into_inner().iter().copied().collect(),
        }
    }

    /// First established connection of a peer, or its last one closing.
    pub(crate) fn set_connected(&self, peer: PeerId, connected: bool) {
        let mut set = match self.connected.lock() {
            Ok(set) => set,
            Err(poisoned) => poisoned.into_inner(),
        };
        match connected {
            true => set.insert(peer),
            false => set.remove(&peer),
        };
    }

    /// One identify report, counted only from outbound connections. Returns
    /// the address once this report confirms it.
    pub(crate) fn observe(&self, address: Multiaddr, reporter: PeerId) -> Option<Multiaddr> {
        match self.observed.lock() {
            Ok(mut observed) => observed.observe(address, reporter),
            Err(poisoned) => poisoned.into_inner().observe(address, reporter),
        }
    }

    /// Answer a Peers request from the snapshot. Only IP-literal addresses are
    /// forwarded, private and loopback ones only to loopback requesters. Neither
    /// the requester nor this node is listed; future `last_seen` is clamped.
    pub(crate) fn serve(&self, requester: PeerId, loopback: bool, limit: u32) -> Reply {
        let Ok(limit) = usize::try_from(limit) else {
            return Reply::Refused;
        };
        if limit > usize::try_from(PEERS_MAX).unwrap_or(0) {
            return Reply::Refused;
        }
        let Ok(snapshot) = self.gossip.lock() else {
            return Reply::Busy;
        };
        let now = unix_now();
        let mut peers = Vec::new();
        let listed = snapshot
            .iter()
            .filter(|entry| entry.peer_id != requester && entry.peer_id != self.local);
        for entry in listed {
            if peers.len() == limit {
                break;
            }
            let addrs: Vec<Multiaddr> = entry
                .addrs
                .iter()
                .filter(|address| validate_gossip_address(address).is_ok())
                .filter(|address| loopback || is_public(address))
                .take(PEER_ADDRESSES_MAX)
                .cloned()
                .collect();
            if !addrs.is_empty() {
                peers.push(GossipPeer {
                    peer_id: entry.peer_id,
                    addrs,
                    last_seen: entry.last_seen.min(now),
                });
            }
        }
        loop {
            match serde_json::to_vec(&peers) {
                Ok(bytes) if bytes.len() + Self::ENVELOPE <= PEERS_LIMIT => break,
                Ok(_) => {
                    peers.pop();
                }
                Err(_) => return Reply::Busy,
            }
        }
        Reply::Peers(peers)
    }
}

/// Globally routable IP, or a DNS name other than localhost. IPv4-mapped IPv6
/// addresses are judged as the IPv4 address they carry.
pub fn is_public(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => public_v4(ip),
        Some(Protocol::Ip6(ip)) => match ip.to_ipv4_mapped() {
            Some(mapped) => public_v4(mapped),
            None => public_v6(ip),
        },
        Some(
            Protocol::Dns(name)
            | Protocol::Dns4(name)
            | Protocol::Dns6(name)
            | Protocol::Dnsaddr(name),
        ) => name != "localhost" && !name.ends_with(".localhost"),
        _ => false,
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _] = ip.octets();
    let reserved = first == 0
        || (first == 100 && (second & 0xc0) == 64)
        || (first == 192 && second == 0 && third == 0)
        || (first == 198 && (second & 0xfe) == 18)
        || first >= 240;
    !(reserved
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_documentation())
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let documentation = ip.segments()[..2] == [0x2001, 0x0db8];
    !(documentation
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local())
}

fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_clock_before_epoch) => 0,
    }
}

pub(crate) fn is_loopback(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_loopback(),
        Some(Protocol::Ip6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Gossip carries only `/ip4|ip6/<literal>/tcp/<port>[/p2p/<id>]`: names come
/// from operators (seeds, manual entries), never from peers.
pub fn validate_gossip_address(address: &Multiaddr) -> Result<Option<PeerId>, Error> {
    match address.iter().next() {
        Some(Protocol::Ip4(_) | Protocol::Ip6(_)) => validate_dial(address),
        _ => Err(Error::Invalid(
            "gossiped addresses must be IP literals with TCP".into(),
        )),
    }
}

/// An operator announce address: a public IP literal with TCP, without a /p2p
/// of another node. Returned without /p2p, as identify advertises it.
pub fn validate_announce(address: &Multiaddr, local: PeerId) -> Result<Multiaddr, Error> {
    if validate_gossip_address(address)?.is_some_and(|named| named != local) {
        return Err(Error::Invalid("announce address names another peer".into()));
    }
    if !is_public(address) {
        return Err(Error::Invalid("announce address must be public".into()));
    }
    Ok(address
        .iter()
        .filter(|part| !matches!(part, Protocol::P2p(_)))
        .collect())
}

/// Operator-supplied dial targets: `/ip4|ip6|dns|dns4|dns6/<host>/tcp/<port>`
/// or `/dnsaddr/<name>`, each with optional `/p2p`. Returns the named identity.
pub fn validate_dial(address: &Multiaddr) -> Result<Option<PeerId>, Error> {
    let invalid = || Error::Invalid("peer dial requires host, TCP port and optional /p2p".into());
    let mut parts = address.iter();
    match parts.next() {
        Some(Protocol::Dnsaddr(_)) => (),
        Some(
            Protocol::Ip4(_)
            | Protocol::Ip6(_)
            | Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_),
        ) => match parts.next() {
            Some(Protocol::Tcp(port)) if port != 0 => (),
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    }
    let peer = match parts.next() {
        None => None,
        Some(Protocol::P2p(peer)) => Some(peer),
        Some(_) => return Err(invalid()),
    };
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok(peer)
}

/// Bind the reply to its request, then check every gossiped hint's shape.
pub(crate) fn validate_peers(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: Response,
) -> Result<Vec<GossipPeer>, Error> {
    bind_response(genesis, peer, pending, &response)?;
    let Kind::Peers { limit } = pending.kind else {
        return Err(Error::Invalid("peers reply to another request".into()));
    };
    match response.result {
        Reply::Peers(peers) => {
            let limit = usize::try_from(limit).map_err(|e| Error::Invalid(e.to_string()))?;
            if peers.len() > limit {
                return Err(Error::Invalid(
                    "peer gossip exceeds the requested limit".into(),
                ));
            }
            for entry in &peers {
                check_gossip(entry)?;
            }
            Ok(peers)
        }
        Reply::Busy => Err(Error::PeerBusy),
        _ => Err(Error::Invalid(
            "peer refused the peers request or answered another kind".into(),
        )),
    }
}

fn check_gossip(entry: &GossipPeer) -> Result<(), Error> {
    let peer = entry.peer_id;
    if entry.addrs.is_empty() || entry.addrs.len() > PEER_ADDRESSES_MAX {
        return Err(Error::Invalid(
            "peer gossip address count out of range".into(),
        ));
    }
    for address in &entry.addrs {
        if validate_gossip_address(address)?.is_some_and(|named| named != peer) {
            return Err(Error::Invalid(
                "peer gossip address names another peer".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) struct Dial {
    address: Multiaddr,
    deadline: Instant,
    answer: mpsc::SyncSender<Result<PeerId, Error>>,
}

impl Dial {
    fn answer(&self, result: Result<PeerId, Error>) {
        let _ = self.answer.try_send(result);
    }
}

/// Outstanding explicit dials on the network thread, keyed by connection.
#[derive(Default)]
pub(crate) struct Dials(HashMap<ConnectionId, (Option<PeerId>, Dial)>);

impl Dials {
    const MAX: usize = 8;

    pub(crate) fn start(&mut self, swarm: &mut Swarm<Behaviour>, dial: Dial) {
        let expected = match validate_dial(&dial.address) {
            Ok(expected) => expected,
            Err(error) => return dial.answer(Err(error)),
        };
        if Instant::now() >= dial.deadline || self.0.len() >= Self::MAX {
            return dial.answer(Err(Error::Busy("peer dial capacity or deadline".into())));
        }
        if let Some(peer) = expected.filter(|peer| swarm.is_connected(peer)) {
            return dial.answer(Ok(peer));
        }
        let options = match expected {
            Some(peer) => DialOpts::peer_id(peer)
                .addresses(vec![dial.address.clone()])
                .build(),
            None => DialOpts::unknown_peer_id()
                .address(dial.address.clone())
                .build(),
        };
        let connection = options.connection_id();
        match swarm.dial(options) {
            Ok(()) => {
                self.0.insert(connection, (expected, dial));
            }
            Err(error) => dial.answer(Err(dial_error(&error))),
        }
    }

    pub(crate) fn established(&mut self, connection: ConnectionId, peer: PeerId) {
        if let Some((expected, dial)) = self.0.remove(&connection) {
            if expected.is_some_and(|expected| expected != peer) {
                return dial.answer(Err(Error::Invalid(
                    "dialed peer authenticated as another identity".into(),
                )));
            }
            dial.answer(Ok(peer));
        }
    }

    pub(crate) fn failed(&mut self, connection: ConnectionId, error: &DialError) {
        if let Some((_, dial)) = self.0.remove(&connection) {
            dial.answer(Err(dial_error(error)));
        }
    }

    /// A dial past its deadline is answered now; a late connection idles out.
    pub(crate) fn expire(&mut self) {
        let now = Instant::now();
        self.0.retain(|_, (_, dial)| {
            if now < dial.deadline {
                return true;
            }
            dial.answer(Err(Error::Busy("peer dial deadline".into())));
            false
        });
    }

    pub(crate) fn close(&mut self) {
        for (_, (_, dial)) in self.0.drain() {
            dial.answer(Err(Error::Busy("peer network stopped".into())));
        }
    }
}

fn dial_error(error: &DialError) -> Error {
    match error {
        DialError::Denied { cause } => match cause.downcast_ref::<LimitDenied>() {
            Some(LimitDenied(limit)) => Error::DialDenied(*limit),
            None => Error::Invalid(format!("peer dial: {error}")),
        },
        DialError::DialPeerConditionFalse(condition) => {
            Error::Busy(format!("peer dial already pending ({condition:?})"))
        }
        other => Error::Invalid(format!("peer dial: {other}")),
    }
}

impl PeerNetwork {
    const DIAL_POLL: Duration = Duration::from_millis(50);

    /// Replace the snapshot served to Peers requests. Order is preserved; the
    /// first entries are the ones a bounded request receives.
    pub fn set_gossip(&self, peers: Vec<GossipPeer>) {
        self.shared.set_gossip(peers);
    }

    /// Public addresses connected peers reported observing for this node.
    pub fn observed_addrs(&self) -> Vec<Multiaddr> {
        self.shared.observed()
    }

    /// Peers with at least one established connection right now, sorted.
    pub fn connected_peer_ids(&self) -> Vec<PeerId> {
        self.shared.connected()
    }

    /// Connected peers' own literal public addresses learned through identify
    /// since the last call, newest 64 peers; the queue is emptied.
    pub fn drain_identified(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.shared.drain_identified()
    }

    /// Dial an address (with or without `/p2p`), then probe the peer with a
    /// zero-limit Peers request. Returns the authenticated identity; the
    /// connection stays for later requests. A Busy probe is an error that keeps
    /// the connection; any other failed probe closes it: the peer is on another
    /// chain or does not speak this protocol.
    pub fn dial(
        &self,
        address: Multiaddr,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<PeerId, Error> {
        validate_dial(&address)?;
        check_cancelled(cancelled)?;
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Busy("peer network stopped".into()));
        }
        let deadline = deadline.min(Instant::now() + CALL_TIMEOUT);
        let (answer, receiver) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command::Dial(Dial {
                address,
                deadline,
                answer,
            }))
            .map_err(|_| Error::Busy("peer command queue unavailable".into()))?;
        let peer = loop {
            check_cancelled(cancelled)?;
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Busy("peer dial deadline".into()));
            }
            match receiver.recv_timeout(left.min(Self::DIAL_POLL)) {
                Ok(result) => break result?,
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Busy("peer network stopped".into()));
                }
            }
        };
        match self.peers_of(peer, 0, cancelled, deadline) {
            Ok(_) => Ok(peer),
            Err(busy @ (Error::Busy(_) | Error::PeerBusy)) => Err(busy),
            Err(error) => {
                let _ = self.commands.try_send(Command::Disconnect(peer));
                Err(error)
            }
        }
    }

    /// One bounded Peers request over an existing connection (or addresses the
    /// swarm already knows). `limit` is at most PEERS_MAX; 0 is a bare probe.
    pub fn peers_of(
        &self,
        peer: PeerId,
        limit: u32,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<GossipPeer>, Error> {
        if limit > PEERS_MAX {
            return Err(Error::Invalid("peers request limit exceeds 32".into()));
        }
        check_cancelled(cancelled)?;
        let kind = Kind::Peers { limit };
        request(
            &self.commands,
            &self.stop,
            (peer, Vec::new()),
            kind,
            deadline,
            Answer::Peers,
        )
    }
}
