use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};
use urma_chain::observation::Chain;

pub const API_VERSION: u32 = 1;
pub const SCAN_RULES_VERSION: u32 = 1;

/// Acknowledges a local pin operation at its commit point. This is not a
/// promise of current chain selection, object availability forever, or peer trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinReceipt {
    pub root: bitcoin::Txid,
    pub pinned: bool,
}

/// Explicit local cache maintenance. Counts removed child records, not raw
/// transactions or bytes; unpruned archives return zero without eviction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneReceipt {
    pub records_removed: u64,
}

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

/// A successful complete reconstruction, distinct from interval coverage.
/// Counts describe the current archive snapshot. A reorg can leave all bytes
/// available locally while some memberships no longer belong to the selected chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectStatus {
    pub root: bitcoin::Txid,
    pub verified_generation: u64,
    pub payload_bytes: u64,
    pub members_total: u64,
    pub members_local: u64,
    /// Previously verified placements still selected, independent of eviction.
    pub members_selected: u64,
    pub pinned: bool,
}

impl ObjectStatus {
    pub fn locally_complete(&self) -> bool {
        self.members_total > 0 && self.members_local == self.members_total
    }

    pub fn selected_complete(&self) -> bool {
        self.locally_complete() && self.members_selected == self.members_total
    }
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
    /// Highest height whose prefix from app start lies in current peer coverage.
    pub peer_synced_through: Option<ChainPoint>,
    /// Selected placements a covering peer did not list, found by a later scan.
    pub peer_omissions: u64,
    /// Selected records admitted selectively whose block has not been scanned.
    pub unaudited_records: u64,
}

/// Historical receipt of one atomic cache maintenance step. Later admissions,
/// pins and reorgs can change usage. Protected evidence and SQLite/WAL overhead
/// are outside this metric; disabled enforcement does not imply an empty archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheReceipt {
    pub enabled: bool,
    pub limit_bytes: u64,
    pub before_bytes: u64,
    pub remaining_bytes: u64,
    pub removed_records: u64,
    pub removed_transactions: u64,
    pub over_budget: bool,
}

/// Operator-reported service state. Every `last_*_error` describes the latest
/// attempt of that worker; `*_at` is when it was recorded, in Unix seconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub archive: ArchiveStatus,
    pub last_sync_error: Option<String>,
    pub last_sync_error_at: Option<u64>,
    pub last_retention_error: Option<String>,
    pub last_retention_error_at: Option<u64>,
    pub last_names_error: Option<String>,
    pub last_names_error_at: Option<u64>,
    pub last_dependency_error: Option<String>,
    pub last_dependency_error_at: Option<u64>,
    pub last_inventory_error: Option<String>,
    pub last_inventory_error_at: Option<u64>,
    pub last_discovery_error: Option<String>,
    pub last_discovery_error_at: Option<u64>,
    pub commit_sources: Vec<CommitSourceStatus>,
    pub cache_limit_bytes: u64,
    pub last_cache_error: Option<String>,
    pub last_cache_error_at: Option<u64>,
    pub last_cache_maintenance: Option<CacheReceipt>,
    pub overlay: Option<OverlayStatus>,
    pub retention_configured: bool,
    pub record_sources_configured: u64,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSourceStatus {
    pub label: String,
    pub last_error: Option<String>,
    pub last_error_at: Option<u64>,
}

/// Public overlay facts; never secrets. Counters cover this service run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayStatus {
    pub peer_id: String,
    pub listen: Option<String>,
    pub peer_book: u64,
    pub connected: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub peers: Vec<OverlayPeerStatus>,
    pub discovery: Option<DiscoveryStatus>,
}

/// Peer book and discovery counters. `reached` counts entries whose last dial
/// succeeded, `reached_ever` entries with any past successful dial; a dial
/// proves an identity answered, not honesty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryStatus {
    pub seeds: u64,
    pub book: u64,
    pub reached: u64,
    pub reached_ever: u64,
    pub gossip: u64,
    pub last_seed_round_error: Option<String>,
    pub last_seed_round_error_at: Option<u64>,
    pub last_gossip_error: Option<String>,
    pub last_gossip_error_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPeerStatus {
    pub label: String,
    pub cursor: u64,
    pub synced_through: Option<u64>,
    pub last_error: Option<String>,
    pub last_error_at: Option<u64>,
}
