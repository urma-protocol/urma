use crate::format::Urma;
pub struct Limits;
impl Limits {
    pub const INPUT_BYTES: usize = 16 * 1024 * 1024;
    pub const RECORDS: usize = Self::INPUT_BYTES / Urma::CHUNK_BYTES;
    pub const CONTAINER_BYTES: usize = 12 + Self::RECORDS * (4 + Urma::PRIVATE_RECORD_BYTES);
    pub const OBJECTS: usize = 64;
}

use crate::error::{Context, Error};
use serde_json::Value;
use std::path::Path;

pub fn confirmations(value: &Value) -> Result<i64, Error> {
    match value.get("confirmations") {
        Some(number) => number.as_i64().context("invalid confirmations"),
        None => Ok(0),
    }
}

pub fn output_parent(path: &Path) -> &Path {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent,
        None => Path::new("."),
    }
}

#[derive(Clone, Copy)]
pub enum RpcScope<'a> {
    Node,
    Wallet(&'a str),
}
impl<'a> From<Option<&'a str>> for RpcScope<'a> {
    fn from(wallet: Option<&'a str>) -> Self {
        match wallet {
            Some(name) => Self::Wallet(name),
            None => Self::Node,
        }
    }
}
#[derive(Clone, Copy)]
pub enum ScanEnd {
    Tip,
    Height(u64),
}
#[derive(Clone, Copy)]
pub enum RevealSelection {
    All,
    First(usize),
}
impl RevealSelection {
    pub fn count(self, total: usize) -> usize {
        match self {
            Self::All => total,
            Self::First(count) => count.min(total),
        }
    }
}
#[derive(Clone, Copy)]
pub enum TxPresence {
    Missing,
    Observed(i64),
}
impl TxPresence {
    pub fn confirmed(self) -> bool {
        match self {
            Self::Missing => false,
            Self::Observed(count) => count > 0,
        }
    }
}

#[derive(Clone, Copy)]
pub enum MempoolPresence {
    Absent,
    Present,
}
impl From<Option<usize>> for RevealSelection {
    fn from(count: Option<usize>) -> Self {
        match count {
            Some(n) => Self::First(n),
            None => Self::All,
        }
    }
}
pub const MAX_OBJECTS: usize = Limits::OBJECTS;
pub const MAX_DIRECTORY_RECORDS: usize = MAX_OBJECTS * Limits::RECORDS;
pub const LITECOIN_NETWORK: &str = "litecoin-testnet";
pub const LITECOIN_GENESIS: &str =
    "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0";
pub const LITECOIN_RPC_PORT: u16 = 19332;
pub const LITECOIN_RETURN_LITOSHIS: u64 = 1_000;
pub const LITECOIN_MAX_FEE_LITOSHIS: u64 = 500_000;
pub const LITECOIN_MAX_SCAN_BLOCKS: u64 = 10_000;
pub const LITECOIN_MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
pub const LITECOIN_MAX_JOURNAL_BYTES: usize = 4_000_000;
pub const RELAY_MAX_BUDGET_SATS: u64 = 500_000;
pub const SOURCE_MAX_BLOCK_BYTES: usize = 4_000_000;
pub const SOURCE_MAX_JSON_BYTES: usize = 1_000_000;
pub const SOURCE_MAX_UTXOS: usize = 1_000;
pub const SOURCE_MAX_SCAN_BLOCKS: u64 = 10_000;
pub const SOURCE_MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
pub const BITCOIN_RETURN_SATS: u64 = 1_000;
pub const BITCOIN_MAX_FEE_SATS: u64 = 500_000;
pub const BITCOIN_MAX_FEE_RATE: u64 = 100;
