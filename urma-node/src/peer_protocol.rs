//! Untrusted selective exchange, separate from the authenticated local control
//! API. Transport identity proves which peer answered, not chain membership,
//! record validity or completeness. URMA V0 records and proofs are unchanged.
use crate::model::RecordPackage;
use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "/urma/node/record/2";
pub const VERSION: u32 = 2;
pub const REQUEST_LIMIT: usize = 512;
pub const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;
/// Raw parent bytes, matching the local RPC 16M-hex admission cap.
pub const PARENT_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Record,
    /// Retained raw transaction by TXID; untrusted, never a placement claim.
    Parent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub chain_genesis: BlockHash,
    pub kind: Kind,
    pub txid: Txid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub chain_genesis: BlockHash,
    pub txid: Txid,
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
    /// Unknown in this peer's selected retained snapshot, never global absence.
    Missing,
    WrongNetwork,
    UnsupportedVersion,
    Busy,
    TooLarge,
}
