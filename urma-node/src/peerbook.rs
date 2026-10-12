//! Bounded, explicitly saved routing hints. A saved peer identity or address is
//! untrusted data, not chain evidence or a statement of record availability.
//! No operation resolves names, dials peers, supplies seeds or starts networking.
//! The caller owns the directory and coordinates its lock and explicit saves.

use crate::Error;
use bitcoin::BlockHash;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::ErrorKind, path::Path};

const FILE_LIMIT: usize = 256 * 1024;
const PEER_LIMIT: usize = 256;
const ADDRESS_LIMIT: usize = 4;
const VERSION: u32 = 1;

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
            Some(Protocol::Ip4(ip)) => {
                !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
            }
            Some(Protocol::Ip6(ip)) => !ip.is_unspecified() && !ip.is_multicast(),
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

/// Origin belongs to each address. Learning cannot downgrade a manual entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Manual,
    Learned,
}

/// At most 256 peers with four distinct addresses per peer. Mutations affect
/// memory only; callers choose when and where to atomically save the snapshot.
pub struct PeerBook {
    chain_genesis: BlockHash,
    peers: BTreeMap<PeerId, Vec<(PeerAddress, Origin)>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedBook {
    version: u32,
    chain_genesis: String,
    entries: Vec<SavedAddress>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAddress {
    peer_id: String,
    address: String,
    origin: Origin,
}

impl PeerBook {
    /// Load a bounded regular JSON file for the caller's explicit network.
    /// Only `NotFound` yields an empty book; invalid existing files are refused
    /// in their entirety and preserved. A missing file creates nothing.
    pub fn load(path: &Path, chain_genesis: BlockHash) -> Result<Self, Error> {
        let mut book = Self {
            chain_genesis,
            peers: BTreeMap::new(),
        };
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(book),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            return Err(Error::Invalid("peer book must be a regular file".into()));
        }
        if metadata.len() > FILE_LIMIT as u64 {
            return Err(Error::Invalid("peer book exceeds 256 KiB".into()));
        }
        let bytes = urma_io::read_regular(path, FILE_LIMIT).map_err(io_source)?;
        let saved: SavedBook = serde_json::from_slice(&bytes)?;
        if saved.version != VERSION {
            return Err(Error::Invalid("unsupported peer book version".into()));
        }
        let saved_genesis: BlockHash = saved
            .chain_genesis
            .parse()
            .map_err(|_| Error::Invalid("invalid peer book chain genesis".into()))?;
        if saved_genesis != chain_genesis {
            return Err(Error::Invalid("peer book belongs to another chain".into()));
        }
        if saved.entries.len() > PEER_LIMIT * ADDRESS_LIMIT {
            return Err(Error::Busy("peer book has too many addresses".into()));
        }
        for entry in saved.entries {
            let peer = entry
                .peer_id
                .parse()
                .map_err(|_| Error::Invalid("invalid saved peer ID".into()))?;
            let address = entry
                .address
                .parse()
                .map_err(|_| Error::Invalid("invalid saved peer address".into()))?;
            let address = PeerAddress::new(peer, address)?;
            if book.peers.get(&peer).is_some_and(|addresses| {
                addresses
                    .iter()
                    .any(|(known, _)| known.address == address.address)
            }) {
                return Err(Error::Invalid("duplicate saved peer address".into()));
            }
            book.insert(address, entry.origin)?;
        }
        Ok(book)
    }

    /// Return whether memory changed. A manual duplicate upgrades a learned
    /// address; a learned duplicate preserves manual origin. Capacity refusal
    /// does not evict entries or change memory, and never writes a file.
    pub fn insert(&mut self, address: PeerAddress, origin: Origin) -> Result<bool, Error> {
        if let Some(addresses) = self.peers.get_mut(&address.peer) {
            if let Some((_, known_origin)) = addresses
                .iter_mut()
                .find(|(known, _)| known.address == address.address)
            {
                if *known_origin == Origin::Learned && origin == Origin::Manual {
                    *known_origin = Origin::Manual;
                    return Ok(true);
                }
                return Ok(false);
            }
            if addresses.len() == ADDRESS_LIMIT {
                return Err(Error::Busy("peer already has four addresses".into()));
            }
            addresses.push((address, origin));
        } else {
            if self.peers.len() == PEER_LIMIT {
                return Err(Error::Busy("peer book already has 256 peers".into()));
            }
            self.peers.insert(address.peer, vec![(address, origin)]);
        }
        Ok(true)
    }

    /// Snapshot sorted by peer ID string, then canonical address string.
    pub fn entries(&self) -> Vec<(PeerAddress, Origin)> {
        let mut entries: Vec<_> = self.peers.values().flatten().cloned().collect();
        entries.sort_by_cached_key(|(address, _)| {
            (address.peer.to_string(), address.address.to_string())
        });
        entries
    }

    /// Remove all addresses for a peer from memory without persisting.
    pub fn remove(&mut self, peer: PeerId) -> bool {
        self.peers.remove(&peer).is_some()
    }

    /// Atomically replace a bounded snapshot using `urma_io`. The destination
    /// directory must exist; the caller owns its lock. New files use the private
    /// temporary file supplied by that I/O API. No file handle is retained.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let saved = SavedBook {
            version: VERSION,
            chain_genesis: self.chain_genesis.to_string(),
            entries: self
                .entries()
                .into_iter()
                .map(|(address, origin)| SavedAddress {
                    peer_id: address.peer.to_string(),
                    address: address.address.to_string(),
                    origin,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&saved)?;
        if bytes.len() > FILE_LIMIT {
            return Err(Error::Invalid("peer book exceeds 256 KiB".into()));
        }
        urma_io::write_replace(path, &bytes).map_err(io_source)
    }
}

fn io_source(error: urma_io::Error) -> Error {
    Error::Source(Box::new(error))
}
