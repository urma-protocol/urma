//! Untrusted selective exchange, separate from the authenticated local control
//! API. Transport identity proves which peer answered, not chain membership,
//! record validity or completeness. URMA V0 records and proofs are unchanged.
use crate::model::RecordPackage;
use bitcoin::{BlockHash, Txid, Wtxid};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "/urma/node/record/4";
pub const VERSION: u32 = 4;
pub const REQUEST_LIMIT: usize = 1024;
pub const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;
/// Raw parent bytes, matching the local RPC 16M-hex admission cap.
pub const PARENT_LIMIT: usize = 8 * 1024 * 1024;
/// Widest inventory request, in heights (to_height - from_height).
pub const INVENTORY_SPAN: u64 = 4096;
/// Most placements in one inventory page.
pub const INVENTORY_ENTRIES: u32 = 512;
/// Encoded inventory response frame, enforced by both writer and reader.
pub const INVENTORY_LIMIT: usize = 256 * 1024;
/// Most peers in one gossip reply; `limit: 0` is a bare chain probe.
pub const PEERS_MAX: u32 = 32;
/// Most addresses gossiped per peer.
pub const PEER_ADDRESSES_MAX: usize = 4;
/// Encoded peers response frame, enforced by both writer and reader.
pub const PEERS_LIMIT: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Kind {
    Record {
        txid: Txid,
    },
    /// Retained raw transaction by TXID; untrusted, never a placement claim.
    Parent {
        txid: Txid,
    },
    /// Placements in fully scanned selected blocks, (height, position) order.
    Inventory {
        from_height: u64,
        to_height: u64,
        after: Option<Placement>,
        limit: u32,
    },
    /// Routing hints the answering node has recently reached; untrusted.
    Peers {
        limit: u32,
    },
}

/// A gossiped routing hint: base58 peer identity, its addresses and the Unix
/// second the answering node last reached it. Never chain or record evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipPeer {
    #[serde(with = "base58_peer")]
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub last_seen: u64,
}

/// A PeerId on the wire is its base58 string, parsed strictly on receipt.
mod base58_peer {
    use libp2p::PeerId;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(peer: &PeerId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(peer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PeerId, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// One transaction's position in a block the answering node fully scanned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub height: u64,
    pub block_hash: BlockHash,
    pub position: u32,
    pub txid: Txid,
    pub wtxid: Wtxid,
}

/// Complete only for scanned blocks at or below `scanned_through` in range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPage {
    pub scanned_through: Option<u64>,
    pub entries: Vec<Placement>,
    pub more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub chain_genesis: BlockHash,
    pub kind: Kind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub chain_genesis: BlockHash,
    pub kind: Kind,
    pub result: Reply,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "package",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Reply {
    Record(Box<RecordPackage>),
    /// Lowercase hex of at most PARENT_LIMIT raw bytes.
    Parent(String),
    Inventory(InventoryPage),
    Peers(Vec<GossipPeer>),
    /// Unknown in this peer's selected retained snapshot, never global absence.
    Missing,
    WrongNetwork,
    UnsupportedVersion,
    Busy,
    TooLarge,
    /// Malformed request parameters, such as an inventory range or limit.
    Refused,
}
