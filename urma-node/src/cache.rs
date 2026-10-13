//! Soft limits for reclaimable local multipart evidence, not disk quotas.
//! Each maintenance step returns a `model::CacheReceipt`.

pub const DEFAULT_CACHE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_CACHE_RECORDS: usize = 128;
pub const MAX_CACHE_TRANSACTIONS: usize = 512;
