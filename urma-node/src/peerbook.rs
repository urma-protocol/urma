//! Bounded peer book: explicit routing hints, configured seeds and addresses
//! learned from peers. Every entry is an untrusted hint, never chain evidence
//! or a statement of record availability. Nothing here resolves names, dials
//! or starts networking; the caller owns the directory, its lock and saves.

use crate::{
    Error,
    peer_gossip::{is_public, validate_gossip_address},
    peer_protocol::GossipPeer,
};
use bitcoin::BlockHash;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::{fs, io::ErrorKind, net::IpAddr, path::Path};
use urma_node_client::model::BookEntry as ListedEntry;

/// A syntactically validated routing hint with an explicit matching identity.
/// Validation establishes neither reachability nor trust in the named peer.
#[derive(Clone, Debug)]
pub struct PeerAddress {
    peer: PeerId,
    address: Multiaddr,
}

impl PeerAddress {
    /// Accept exactly IP4/IP6, nonzero TCP, and a terminal matching `/p2p`.
    /// Loopback and private addresses are allowed; unspecified, multicast and
    /// IPv4 broadcast destinations are refused. No resolution or dial occurs.
    pub fn new(peer: PeerId, address: Multiaddr) -> Result<Self, Error> {
        let mut protocols = address.iter();
        let valid_ip = match protocols.next() {
            Some(Protocol::Ip4(ip)) => usable(IpAddr::V4(ip)),
            Some(Protocol::Ip6(ip)) => usable(IpAddr::V6(ip)),
            _ => false,
        };
        if !valid_ip
            || !matches!(protocols.next(), Some(Protocol::Tcp(port)) if port != 0)
            || !matches!(protocols.next(), Some(Protocol::P2p(id)) if id == peer)
            || protocols.next().is_some()
        {
            return Err(Error::Invalid(
                "peer address requires a usable IP, nonzero TCP port and terminal matching peer ID"
                    .into(),
            ));
        }
        Ok(Self { peer, address })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub fn address(&self) -> &Multiaddr {
        &self.address
    }
}

pub use urma_node_client::model::BookOrigin as Origin;

/// One peer (or one not yet identified seed address). Addresses are stored
/// without a terminal `/p2p`; the identity lives in `peer_id` once learned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookEntry {
    pub peer_id: Option<PeerId>,
    pub addrs: Vec<Multiaddr>,
    pub origin: Origin,
    pub last_success: Option<u64>,
    pub failures: u32,
    pub banned_until: Option<u64>,
}

/// Counts reported in overlay status. `reached` entries succeeded and have
/// not failed since; `reached_ever` entries succeeded at least once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BookStats {
    pub seeds: u64,
    pub book: u64,
    pub reached: u64,
    pub reached_ever: u64,
    pub gossip: u64,
}

/// Who supplied an address: the operator, a peer's gossip, or a peer
/// identifying itself over a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Learned {
    Operator,
    Gossip,
    Identify,
}

pub struct PeerBook {
    chain_genesis: BlockHash,
    entries: Vec<BookEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedBook {
    version: u32,
    chain_genesis: String,
    entries: Vec<SavedEntry>,
}

/// The persisted entry: the served `ListedEntry` shape, but strict on load.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedEntry {
    peer_id: Option<String>,
    addrs: Vec<String>,
    origin: Origin,
    last_success: Option<u64>,
    failures: u32,
    banned_until: Option<u64>,
}

impl From<SavedEntry> for ListedEntry {
    fn from(saved: SavedEntry) -> Self {
        let SavedEntry {
            peer_id,
            addrs,
            origin,
            last_success,
            failures,
            banned_until,
        } = saved;
        Self {
            peer_id,
            addrs,
            origin,
            last_success,
            failures,
            banned_until,
        }
    }
}

/// Where an address points: a literal IP or a name resolved at dial time.
enum Host {
    Ip(IpAddr),
    Name,
}

impl PeerBook {
    pub const CAPACITY: usize = 1024;
    pub const ADDRESSES: usize = 4;
    /// Gossip entries per IPv4 /24 or IPv6 /48.
    pub const GROUP_LIMIT: usize = 2;
    const FILE_LIMIT: usize = 1024 * 1024;
    const VERSION: u32 = 2;
    const BACKOFF_SECONDS: u64 = 60;
    const BACKOFF_CAP: u64 = 86_400;
    /// Seeds are operator configuration, never banned like gossip: their
    /// backoff stops growing at ten minutes.
    pub const SEED_BACKOFF_CAP: u64 = 600;

    pub fn empty(chain_genesis: BlockHash) -> Self {
        Self {
            chain_genesis,
            entries: Vec::new(),
        }
    }

    /// Load a bounded regular JSON file for the caller's explicit network.
    /// Only `NotFound` yields an empty book; any invalid file, including an
    /// older format version, is refused whole and preserved untouched.
    pub fn load(path: &Path, chain_genesis: BlockHash) -> Result<Self, Error> {
        let mut book = Self::empty(chain_genesis);
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(book),
            Err(error) => return Err(error.into()),
        };
        let limit = u64::try_from(Self::FILE_LIMIT).map_err(|e| Error::Invalid(e.to_string()))?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(Error::Invalid(
                "peer book must be a regular file of at most 1 MiB".into(),
            ));
        }
        let bytes = urma_io::read_regular(path, Self::FILE_LIMIT).map_err(io_source)?;
        let saved: SavedBook = serde_json::from_slice(&bytes)?;
        if saved.version != Self::VERSION {
            return Err(Error::Invalid("unsupported peer book version".into()));
        }
        let saved_genesis: BlockHash = saved
            .chain_genesis
            .parse()
            .map_err(|_| Error::Invalid("invalid peer book chain genesis".into()))?;
        if saved_genesis != chain_genesis {
            return Err(Error::Invalid("peer book belongs to another chain".into()));
        }
        if saved.entries.len() > Self::CAPACITY {
            return Err(Error::Busy("peer book has too many entries".into()));
        }
        for saved in saved.entries {
            let entry = restore(saved)?;
            if book.overlaps(&entry) {
                return Err(Error::Invalid("duplicate saved peer or address".into()));
            }
            book.entries.push(entry);
        }
        Ok(book)
    }

    /// Atomically replace a bounded snapshot sorted by identity then address.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let mut entries: Vec<SavedEntry> = self.entries.iter().map(persist).collect();
        entries.sort_by(|a, b| (&a.peer_id, &a.addrs).cmp(&(&b.peer_id, &b.addrs)));
        let saved = SavedBook {
            version: Self::VERSION,
            chain_genesis: self.chain_genesis.to_string(),
            entries,
        };
        let bytes = serde_json::to_vec(&saved)?;
        if bytes.len() > Self::FILE_LIMIT {
            return Err(Error::Invalid("peer book exceeds 1 MiB".into()));
        }
        urma_io::write_replace(path, &bytes).map_err(io_source)
    }

    pub fn entries(&self) -> &[BookEntry] {
        &self.entries
    }

    /// Add one address. A terminal `/p2p` names the peer; without it the
    /// entry stays unidentified until a dial succeeds. Gossip only accepts
    /// public literal IPs under the group cap; manual and seed accept any
    /// usable address including loopback and names. Returns whether memory
    /// changed; capacity is made by evicting the worst gossip entry only.
    pub fn add(&mut self, address: Multiaddr, origin: Origin) -> Result<bool, Error> {
        let learned = match origin {
            Origin::Gossip => Learned::Gossip,
            Origin::Seed | Origin::Manual => Learned::Operator,
        };
        self.insert(address, origin, learned)
    }

    /// Learned addresses never relabel an existing entry: an address already
    /// in the book is left alone, and only identify (not gossip) may add an
    /// address to a known peer. Identities are learned only by `succeeded`.
    fn insert(
        &mut self,
        address: Multiaddr,
        origin: Origin,
        learned: Learned,
    ) -> Result<bool, Error> {
        let (address, peer) = split(address)?;
        if origin == Origin::Gossip {
            self.admit_gossip(&address)?;
        }
        if let Some(index) = self.position_of_address(&address) {
            if learned != Learned::Operator {
                return Ok(false);
            }
            let entry = &mut self.entries[index];
            if peer.is_some() && entry.peer_id.is_some() && entry.peer_id != peer {
                return Err(Error::Invalid("address already names another peer".into()));
            }
            let upgraded = origin > entry.origin || (entry.peer_id.is_none() && peer.is_some());
            entry.origin = entry.origin.max(origin);
            entry.peer_id = entry.peer_id.or(peer);
            return Ok(upgraded);
        }
        if let Some(index) = peer.and_then(|peer| self.position_of_peer(peer)) {
            if learned == Learned::Gossip {
                return Ok(false);
            }
            let entry = &mut self.entries[index];
            if entry.addrs.len() == Self::ADDRESSES {
                return Err(Error::Busy("peer already has four addresses".into()));
            }
            entry.addrs.push(address);
            entry.origin = entry.origin.max(origin);
            return Ok(true);
        }
        self.make_room(origin)?;
        self.entries.push(BookEntry {
            peer_id: peer,
            addrs: vec![address],
            origin,
            last_success: None,
            failures: 0,
            banned_until: None,
        });
        Ok(true)
    }

    /// Merge one peer's gossip under the caps. The local identity and peers
    /// this archive found omitting records are never stored from gossip.
    /// Returns how many addresses changed memory; refusals are skipped.
    pub fn merge(&mut self, peers: &[GossipPeer], local: PeerId, omitting: &[String]) -> usize {
        self.learn(peers, local, omitting, Learned::Gossip)
    }

    /// Peers that identified themselves over a connection: like gossip, but a
    /// known peer may gain the addresses it reported for itself.
    pub fn merge_identified(
        &mut self,
        peers: &[GossipPeer],
        local: PeerId,
        omitting: &[String],
    ) -> usize {
        self.learn(peers, local, omitting, Learned::Identify)
    }

    fn learn(
        &mut self,
        peers: &[GossipPeer],
        local: PeerId,
        omitting: &[String],
        learned: Learned,
    ) -> usize {
        let mut changed = 0;
        for peer in peers {
            let id = peer.peer_id;
            if id == local || omitting.contains(&id.to_string()) {
                continue;
            }
            let mut addresses = Vec::new();
            for address in peer.addrs.iter().take(Self::ADDRESSES) {
                let Ok((address, named)) = split(address.clone()) else {
                    continue;
                };
                if named.is_none_or(|named| named == id) && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            if self.position_of_peer(id).is_none() {
                changed += self.insert_learned_peer(id, addresses);
                continue;
            }
            if learned != Learned::Identify {
                continue;
            }
            for address in addresses {
                let address = address.with(Protocol::P2p(id));
                if let Ok(true) = self.insert(address, Origin::Gossip, learned) {
                    changed += 1;
                }
            }
        }
        changed
    }

    /// A peer new to the book enters once with every learned address that
    /// passes the gossip filter and group cap and is not already in the book.
    fn insert_learned_peer(&mut self, id: PeerId, addresses: Vec<Multiaddr>) -> usize {
        let mut admitted = Vec::new();
        for address in addresses {
            if self.position_of_address(&address).is_none() && self.admit_gossip(&address).is_ok() {
                admitted.push(address);
            }
        }
        if admitted.is_empty() || self.make_room(Origin::Gossip).is_err() {
            return 0;
        }
        let count = admitted.len();
        self.entries.push(BookEntry {
            peer_id: Some(id),
            addrs: admitted,
            origin: Origin::Gossip,
            last_success: None,
            failures: 0,
            banned_until: None,
        });
        count
    }

    /// A dial through `address` reached `peer`. Resets failures and records
    /// the success; an unidentified literal-IP entry learns the identity. An
    /// entry that turns out to be this node is dropped: the book never holds
    /// ourselves.
    pub fn succeeded(&mut self, address: &Multiaddr, peer: PeerId, local: PeerId, now: u64) {
        let Ok((address, _)) = split(address.clone()) else {
            return;
        };
        let Some(index) = self.position_of_address(&address) else {
            return;
        };
        if peer == local {
            self.entries.remove(index);
            return;
        }
        let learnable = matches!(host(&address), Some(Host::Ip(_)));
        let known_elsewhere = self
            .position_of_peer(peer)
            .is_some_and(|other| other != index);
        let entry = &mut self.entries[index];
        entry.last_success = Some(now);
        entry.failures = 0;
        entry.banned_until = None;
        if entry.peer_id.is_none() && learnable && !known_elsewhere {
            entry.peer_id = Some(peer);
        }
    }

    /// A dial through `address` failed: back off 60 s × 2^(failures−1), so the
    /// first failure waits 60 s, capped at one day (ten minutes for seeds).
    pub fn failed(&mut self, address: &Multiaddr, now: u64) {
        let Ok((address, _)) = split(address.clone()) else {
            return;
        };
        let Some(index) = self.position_of_address(&address) else {
            return;
        };
        self.fail_entry(index, now);
    }

    /// A peer misbehaved during sync: back its entry off like a failed dial.
    /// Returns whether the book holds that peer.
    pub fn failed_peer(&mut self, peer: PeerId, now: u64) -> bool {
        let Some(index) = self.position_of_peer(peer) else {
            return false;
        };
        self.fail_entry(index, now);
        true
    }

    fn fail_entry(&mut self, index: usize, now: u64) {
        let entry = &mut self.entries[index];
        entry.failures = entry.failures.checked_add(1).unwrap_or(u32::MAX);
        let cap = match entry.origin {
            Origin::Seed => Self::SEED_BACKOFF_CAP,
            Origin::Gossip | Origin::Manual => Self::BACKOFF_CAP,
        };
        let delay = 2u64
            .checked_pow(entry.failures - 1)
            .and_then(|factor| factor.checked_mul(Self::BACKOFF_SECONDS))
            .map_or(cap, |delay| delay.min(cap));
        entry.banned_until = Some(now.checked_add(delay).unwrap_or(u64::MAX));
    }

    /// Up to `count` dial addresses for non-seed entries that are not banned,
    /// connected or omitting. Never-tried entries (picked at random) alternate
    /// with tried ones (oldest backoff expiry first), so fresh gossip cannot
    /// starve peers that were reached before.
    pub fn candidates(
        &self,
        now: u64,
        connected: &[PeerId],
        omitting: &[String],
        count: usize,
    ) -> Vec<Multiaddr> {
        let eligible = |entry: &&BookEntry| {
            entry.origin != Origin::Seed
                && entry.banned_until.is_none_or(|until| until <= now)
                && entry.peer_id.is_none_or(|peer| {
                    !connected.contains(&peer) && !omitting.contains(&peer.to_string())
                })
        };
        let (mut fresh, mut tried): (Vec<&BookEntry>, Vec<&BookEntry>) = self
            .entries
            .iter()
            .filter(eligible)
            .partition(|entry| entry.last_success.is_none() && entry.failures == 0);
        fresh.shuffle(&mut rand::thread_rng());
        tried.sort_by_key(|entry| (entry.banned_until, entry.failures));
        let mut fresh = fresh.into_iter();
        let mut tried = tried.into_iter();
        let mut picked = Vec::new();
        while picked.len() < count {
            let (next_fresh, next_tried) = (fresh.next(), tried.next());
            if next_fresh.is_none() && next_tried.is_none() {
                break;
            }
            picked.extend(next_fresh.into_iter().chain(next_tried));
        }
        picked.truncate(count);
        picked.into_iter().filter_map(dial_address).collect()
    }

    /// Seed dial addresses in random order, skipping seeds known to be this
    /// node's omitters and, given `now`, seeds still backing off. A ban beyond
    /// the seed cap (persisted under an older policy) counts as expired.
    pub fn seeds(&self, omitting: &[String], now: Option<u64>) -> Vec<Multiaddr> {
        let ready = |until: u64, now: u64| until <= now || until - now > Self::SEED_BACKOFF_CAP;
        let mut seeds: Vec<Multiaddr> = self
            .entries
            .iter()
            .filter(|entry| entry.origin == Origin::Seed)
            .filter(|entry| {
                now.is_none_or(|now| entry.banned_until.is_none_or(|until| ready(until, now)))
            })
            .filter(|entry| {
                entry
                    .peer_id
                    .is_none_or(|peer| !omitting.contains(&peer.to_string()))
            })
            .filter_map(dial_address)
            .collect();
        seeds.shuffle(&mut rand::thread_rng());
        seeds
    }

    /// Identified IP/TCP addresses for record, commit and inventory sources,
    /// one per peer, excluding peers this archive found omitting records.
    pub fn sync_addresses(&self, omitting: &[String]) -> Vec<PeerAddress> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let peer = entry.peer_id?;
                if omitting.contains(&peer.to_string()) {
                    return None;
                }
                entry.addrs.iter().find_map(|address| {
                    PeerAddress::new(peer, address.clone().with(Protocol::P2p(peer))).ok()
                })
            })
            .collect()
    }

    /// Verified, identified peers with public literal-IP addresses, most
    /// recently successful first, for answering a Peers request.
    pub fn gossip(&self, limit: usize, omitting: &[String]) -> Vec<GossipPeer> {
        let mut verified: Vec<(&BookEntry, PeerId, u64)> = self
            .entries
            .iter()
            .filter_map(|entry| Some((entry, entry.peer_id?, entry.last_success?)))
            .filter(|(_, peer, _)| !omitting.contains(&peer.to_string()))
            .collect();
        verified.sort_by_key(|(_, _, seen)| std::cmp::Reverse(*seen));
        verified
            .into_iter()
            .filter_map(|(entry, peer_id, last_seen)| {
                let addrs: Vec<Multiaddr> =
                    entry.addrs.iter().filter(|a| public(a)).cloned().collect();
                (!addrs.is_empty()).then_some(GossipPeer {
                    peer_id,
                    addrs,
                    last_seen,
                })
            })
            .take(limit)
            .collect()
    }

    pub fn stats(&self) -> BookStats {
        let count = |keep: &dyn Fn(&BookEntry) -> bool| {
            u64::try_from(self.entries.iter().filter(|entry| keep(entry)).count())
                .unwrap_or(u64::MAX)
        };
        BookStats {
            seeds: count(&|entry| entry.origin == Origin::Seed),
            book: count(&|_| true),
            reached: count(&|entry| entry.failures == 0 && entry.last_success.is_some()),
            reached_ever: count(&|entry| entry.last_success.is_some()),
            gossip: count(&|entry| entry.origin == Origin::Gossip),
        }
    }

    /// Bounded JSON snapshot for the local control API.
    pub fn listing(&self) -> Vec<ListedEntry> {
        let mut entries: Vec<ListedEntry> = self
            .entries
            .iter()
            .map(|entry| persist(entry).into())
            .collect();
        entries.sort_by(|a, b| (&a.peer_id, &a.addrs).cmp(&(&b.peer_id, &b.addrs)));
        entries.truncate(Self::CAPACITY);
        entries
    }

    /// Remove a peer's entry from memory without persisting.
    pub fn remove(&mut self, peer: PeerId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.peer_id != Some(peer));
        self.entries.len() != before
    }

    fn position_of_address(&self, address: &Multiaddr) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.addrs.contains(address))
    }

    fn position_of_peer(&self, peer: PeerId) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.peer_id == Some(peer))
    }

    fn overlaps(&self, candidate: &BookEntry) -> bool {
        candidate
            .peer_id
            .is_some_and(|peer| self.position_of_peer(peer).is_some())
            || candidate
                .addrs
                .iter()
                .any(|address| self.position_of_address(address).is_some())
    }

    /// Gossip may only name public literal IPs, two entries per network group.
    fn admit_gossip(&self, address: &Multiaddr) -> Result<(), Error> {
        let Some(Host::Ip(ip)) = host(address) else {
            return Err(Error::Invalid(
                "gossip addresses must be literal IPs".into(),
            ));
        };
        validate_gossip_address(address)?;
        if !is_public(address) {
            return Err(Error::Invalid("gossip named a non-public address".into()));
        }
        let neighbours = self
            .entries
            .iter()
            .filter(|entry| entry.origin == Origin::Gossip)
            .filter(|entry| entry.addrs.iter().any(|known| same_group(known, ip)))
            .count();
        if neighbours >= Self::GROUP_LIMIT && self.position_of_address(address).is_none() {
            return Err(Error::Busy("gossip network group is full".into()));
        }
        Ok(())
    }

    /// At capacity, evict the gossip entry with most failures, then the oldest
    /// success (never-successful first). Manual and seed are never evicted.
    fn make_room(&mut self, origin: Origin) -> Result<(), Error> {
        if self.entries.len() < Self::CAPACITY {
            return Ok(());
        }
        let worst = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.origin == Origin::Gossip)
            .max_by_key(|(_, entry)| {
                (
                    entry.failures,
                    std::cmp::Reverse(entry.last_success.unwrap_or(0)),
                )
            })
            .map(|(index, _)| index);
        match worst {
            Some(index)
                if origin != Origin::Gossip
                    || self.entries[index].failures > 0
                    || self.entries[index].last_success.is_none() =>
            {
                self.entries.remove(index);
                Ok(())
            }
            _ => Err(Error::Busy("peer book is full".into())),
        }
    }
}

/// Validate a dialable address and split off a terminal `/p2p`. Accepted:
/// IP4/IP6/DNS/DNS4/DNS6 + nonzero TCP, or DNSADDR alone; then optional `/p2p`.
fn split(address: Multiaddr) -> Result<(Multiaddr, Option<PeerId>), Error> {
    let invalid = || Error::Invalid("peer book address shape is not dialable".into());
    let mut bare = Multiaddr::empty();
    let mut protocols = address.iter();
    let first = protocols.next().ok_or_else(invalid)?;
    let named_only = matches!(first, Protocol::Dnsaddr(_));
    match &first {
        Protocol::Ip4(ip) if usable(IpAddr::V4(*ip)) => (),
        Protocol::Ip6(ip) if usable(IpAddr::V6(*ip)) => (),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => (),
        _ => return Err(invalid()),
    }
    bare.push(first);
    if !named_only {
        match protocols.next() {
            Some(Protocol::Tcp(port)) if port != 0 => bare.push(Protocol::Tcp(port)),
            _ => return Err(invalid()),
        }
    }
    let peer = match protocols.next() {
        None => None,
        Some(Protocol::P2p(peer)) => Some(peer),
        Some(_) => return Err(invalid()),
    };
    if protocols.next().is_some() {
        return Err(invalid());
    }
    Ok((bare, peer))
}

fn host(address: &Multiaddr) -> Option<Host> {
    match address.iter().next()? {
        Protocol::Ip4(ip) => Some(Host::Ip(IpAddr::V4(ip))),
        Protocol::Ip6(ip) => Some(Host::Ip(IpAddr::V6(ip))),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
            Some(Host::Name)
        }
        _ => None,
    }
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

/// A globally routable literal IP: the only address gossip may carry. Names
/// and non-public ranges come only from an operator (manual or seed).
fn public(address: &Multiaddr) -> bool {
    matches!(host(address), Some(Host::Ip(_))) && is_public(address)
}

/// IPv4 /24 or IPv6 /48 equality.
fn same_group(address: &Multiaddr, ip: IpAddr) -> bool {
    match (host(address), ip) {
        (Some(Host::Ip(IpAddr::V4(known))), IpAddr::V4(ip)) => {
            known.octets()[..3] == ip.octets()[..3]
        }
        (Some(Host::Ip(IpAddr::V6(known))), IpAddr::V6(ip)) => {
            known.segments()[..3] == ip.segments()[..3]
        }
        _ => false,
    }
}

fn dial_address(entry: &BookEntry) -> Option<Multiaddr> {
    let address = entry.addrs.first()?.clone();
    Some(match entry.peer_id {
        Some(peer) => address.with(Protocol::P2p(peer)),
        None => address,
    })
}

fn persist(entry: &BookEntry) -> SavedEntry {
    SavedEntry {
        peer_id: entry.peer_id.map(|peer| peer.to_string()),
        addrs: entry.addrs.iter().map(Multiaddr::to_string).collect(),
        origin: entry.origin,
        last_success: entry.last_success,
        failures: entry.failures,
        banned_until: entry.banned_until,
    }
}

fn restore(saved: SavedEntry) -> Result<BookEntry, Error> {
    let peer_id = saved
        .peer_id
        .map(|peer| peer.parse::<PeerId>())
        .transpose()
        .map_err(|_| Error::Invalid("invalid saved peer ID".into()))?;
    if saved.addrs.is_empty() || saved.addrs.len() > PeerBook::ADDRESSES {
        return Err(Error::Invalid(
            "saved peer needs one to four addresses".into(),
        ));
    }
    let mut addrs = Vec::new();
    for address in saved.addrs {
        let parsed: Multiaddr = address
            .parse()
            .map_err(|_| Error::Invalid("invalid saved peer address".into()))?;
        let (bare, named) = split(parsed)?;
        if named.is_some() || addrs.contains(&bare) {
            return Err(Error::Invalid("saved peer address is not canonical".into()));
        }
        if saved.origin == Origin::Gossip && !public(&bare) {
            return Err(Error::Invalid("saved gossip address is not public".into()));
        }
        addrs.push(bare);
    }
    Ok(BookEntry {
        peer_id,
        addrs,
        origin: saved.origin,
        last_success: saved.last_success,
        failures: saved.failures,
        banned_until: saved.banned_until,
    })
}

fn io_source(error: urma_io::Error) -> Error {
    Error::Source(Box::new(error))
}
