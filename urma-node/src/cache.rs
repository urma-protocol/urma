//! Soft limits for reclaimable local multipart evidence, not disk quotas.
use serde::Serialize;

pub const DEFAULT_CACHE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_CACHE_RECORDS: usize = 128;
pub const MAX_CACHE_TRANSACTIONS: usize = 512;

/// Historical receipt of one atomic maintenance step. Later admissions, pins
/// and reorgs can change usage. Protected evidence and SQLite/WAL overhead are
/// outside this metric; disabled enforcement does not imply an empty archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CacheMaintenance {
    pub enabled: bool,
    pub limit_bytes: u64,
    pub before_bytes: u64,
    pub remaining_bytes: u64,
    pub removed_records: u64,
    pub removed_transactions: u64,
    pub over_budget: bool,
}
