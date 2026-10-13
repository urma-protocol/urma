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
    collections::{BTreeSet, HashMap},
    net::Ipv4Addr,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

/// State shared between the network thread and the owner: the gossip snapshot
/// the scheduler hands over, and public addresses peers observed for us.
#[derive(Default)]
pub(crate) struct Shared {
    gossip: Mutex<Vec<GossipPeer>>,
    observed: Mutex<Vec<Multiaddr>>,
    connected: Mutex<BTreeSet<PeerId>>,
}

impl Shared {
    const GOSSIP_MAX: usize = 256;
    const OBSERVED_MAX: usize = 8;
    const ENVELOPE: usize = 1024;

    fn set_gossip(&self, mut peers: Vec<GossipPeer>) {
        peers.truncate(Self::GOSSIP_MAX);
        if let Ok(mut gossip) = self.gossip.lock() {
            *gossip = peers;
        }
    }

    fn observed(&self) -> Vec<Multiaddr> {
        match self.observed.lock() {
            Ok(observed) => observed.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
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

    /// Keep the newest distinct public observations; others are discarded.
    pub(crate) fn observe(&self, address: Multiaddr) {
        if !is_public(&address) {
            return;
        }
        if let Ok(mut observed) = self.observed.lock() {
            if observed.contains(&address) {
                return;
            }
            if observed.len() == Self::OBSERVED_MAX {
                observed.remove(0);
            }
            observed.push(address);
        }
    }

    /// Answer a Peers request from the snapshot. Private and loopback addresses
    /// go only to loopback requesters; the requester never receives itself.
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
        let mut peers = Vec::new();
        for entry in snapshot.iter().filter(|entry| entry.peer_id != requester) {
            if peers.len() == limit {
                break;
            }
            let addrs: Vec<Multiaddr> = entry
                .addrs
                .iter()
                .filter(|address| loopback || is_public(address))
                .take(PEER_ADDRESSES_MAX)
                .cloned()
                .collect();
            if !addrs.is_empty() {
                peers.push(GossipPeer {
                    peer_id: entry.peer_id,
                    addrs,
                    last_seen: entry.last_seen,
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

/// Globally routable IP, or a DNS name other than localhost.
pub fn is_public(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || shared_address_space(ip))
        }
        Some(Protocol::Ip6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
        Some(
            Protocol::Dns(name)
            | Protocol::Dns4(name)
            | Protocol::Dns6(name)
            | Protocol::Dnsaddr(name),
        ) => name != "localhost" && !name.ends_with(".localhost"),
        _ => false,
    }
}

fn shared_address_space(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    first == 100 && (second & 0xc0) == 64
}

pub(crate) fn is_loopback(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_loopback(),
        Some(Protocol::Ip6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// `/ip4|ip6|dns|dns4|dns6/<host>/tcp/<port>[/p2p/<id>]` or
/// `/dnsaddr/<name>[/p2p/<id>]`. Returns the expected identity, if any.
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
        Reply::Busy => Err(Error::Busy("remote peer capacity".into())),
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
        if validate_dial(address)?.is_some_and(|named| named != peer) {
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
        DialError::Denied { cause } if cause.downcast_ref::<LimitDenied>().is_some() => {
            Error::Busy("peer dial denied by local connection limit".into())
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
            Err(Error::Busy(message)) => Err(Error::Busy(message)),
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
