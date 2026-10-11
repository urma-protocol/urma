use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};
use urma_chain::observation::Chain;

pub const API_VERSION: u32 = 1;
pub const SCAN_RULES_VERSION: u32 = 1;

/// Transport data, never trusted merely because it came from another node.
/// The receiver selects the header independently before verifying this proof.
/// `commit` authenticates the exact prevout through its TXID; this package does
/// NOT assert the commit's inclusion, ordering, or witness authenticity. Names
/// must obtain independently anchored commit placement before applying a record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPackage {
    pub version: u32,
    pub chain_genesis: BlockHash,
    pub block: ChainPoint,
    pub reveal: urma_chain::inclusion::TransactionProof,
    pub commit: Vec<u8>,
}

/// Local evidence at one archive generation. Selective admission establishes
/// membership and the URMA proof, never a full-block scan or interval coverage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordReceipt {
    pub generation: u64,
    pub block: ChainPoint,
    pub position: u32,
    pub txid: bitcoin::Txid,
    pub wtxid: bitcoin::Wtxid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchivedRecord {
    pub receipt: RecordReceipt,
    pub package: RecordPackage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainPoint {
    pub height: u64,
    pub hash: BlockHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retention {
    Pruned,
    Unpruned,
}

/// The application start is independent of the chain genesis and header anchor.
/// There is deliberately no implicit tip-minus-N or checkpoint-based default.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveConfig {
    pub chain: Chain,
    pub application_start: ChainPoint,
    pub retention: Retention,
}

/// A capability issued by this archive for a particular selected block.
/// The epoch changes on a reorg; a worker cannot commit using an old ticket.
#[derive(Clone, Copy, Debug)]
pub struct ScanTicket {
    pub(crate) generation: u64,
    pub(crate) point: ChainPoint,
}

impl ScanTicket {
    pub fn point(self) -> ChainPoint {
        self.point
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveStatus {
    pub api_version: u32,
    pub chain_genesis: BlockHash,
    pub application_start: ChainPoint,
    pub retention: Retention,
    pub generation: u64,
    pub selected_tip: Option<ChainPoint>,
    /// Contiguous fully scanned and dependency-resolved prefix from app start.
    /// This does not assert full consensus validation or local object retention.
    pub indexed_through: Option<ChainPoint>,
    pub scanned_blocks: u64,
    pub unresolved_dependencies: u64,
    pub stored_transactions: u64,
    pub scan_rules_version: u32,
}
