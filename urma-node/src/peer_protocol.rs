//! Untrusted selective exchange, separate from the authenticated local control
//! API. Transport identity proves which peer answered, not chain membership,
//! record validity or completeness. URMA V0 records and proofs are unchanged.
use crate::model::RecordPackage;
use bitcoin::{BlockHash, Txid, Wtxid};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "/urma/node/record/3";
pub const VERSION: u32 = 3;
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
    /// Unknown in this peer's selected retained snapshot, never global absence.
    Missing,
    WrongNetwork,
    UnsupportedVersion,
    Busy,
    TooLarge,
    /// Malformed request parameters, such as an inventory range or limit.
    Refused,
}
