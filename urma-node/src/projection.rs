//! Shared application views over the owning archive. These are local index
//! results, not portable cryptographic proofs or claims of interval completeness.
use crate::model::ArchiveStatus;
use bitcoin::{BlockHash, Wtxid};
use serde::{Deserialize, Serialize};

pub const MAX_WIRE_PAGE: u32 = 128;

/// Opaque consistency token for this engine instance and archive revision.
/// Restart, reorg, or any committed archive event invalidates old cursors.
/// A consumer must discard a partial traversal on a stale-cursor error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexSnapshot {
    pub instance: String,
    pub revision: u64,
}

/// Continuation within one snapshot, ordered by selected height and position.
/// The token is not an authorization capability or evidence of completeness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireCursor {
    pub snapshot: IndexSnapshot,
    pub height: u64,
    pub position: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRecord {
    pub block_hash: BlockHash,
    pub wtxid: Wtxid,
    pub entry: urma_wire::index::Entry,
}

/// Selected, locally admitted Wire records, including selective admissions.
/// `next == None` means the local result set ended, not that a peer or the chain
/// contains no other records. Coverage is reported separately in `archive`.
/// Bytes/author/TXID originate from prior archive admission; this response does
/// not carry inclusion proofs. Untrusted recipients must obtain and verify the
/// corresponding RecordPackage against their own chain view instead.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePage {
    pub snapshot: IndexSnapshot,
    pub archive: ArchiveStatus,
    pub records: Vec<WireRecord>,
    pub next: Option<WireCursor>,
}
