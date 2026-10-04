use urma_core::format::Urma;
pub struct Limits;
impl Limits {
    pub const INPUT_BYTES: usize = 16 * 1024 * 1024;
    pub const RECORDS: usize = Self::INPUT_BYTES / Urma::CHUNK_BYTES;
    pub const CONTAINER_BYTES: usize = 12 + Self::RECORDS * (4 + Urma::PRIVATE_RECORD_BYTES);
    pub const OBJECTS: usize = 64;
}

use crate::error::{Context, Error};
use serde_json::Value;

pub fn confirmations(value: &Value) -> Result<i64, Error> {
    match value.get("confirmations") {
        Some(number) => number.as_i64().context("invalid confirmations"),
        None => Ok(0),
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
pub const LITECOIN_GENESIS: &str = urma_chain::observation::Chain::LITECOIN_TESTNET_GENESIS;
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

pub const PUBLIC_METHODS: [&str; 10] = [
    "getblockhash",
    "getblockchaininfo",
    "getrawtransaction",
    "getblockheader",
    "getblock",
    "getrawmempool",
    "gettxout",
    "addressutxos",
    "testmempoolaccept",
    "sendrawtransaction",
];
pub const ABSENT_TRANSACTION: &str = "transaction not found on selected network";
pub const ABSENT_RECORD: &str = "transaction or block not found on selected network";
pub const MAX_PROVIDERS: usize = 8;
pub const TIP_RACE_WIDTH: usize = 2;
pub const PROVIDER_BREAKER_FAILURES: u32 = 3;
pub const PROVIDER_BREAKER_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
pub const PROVIDER_RETRY_DEFAULT: std::time::Duration = std::time::Duration::from_secs(60);
pub const PROVIDER_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);
pub const PROVIDER_PACING: std::time::Duration = std::time::Duration::from_millis(300);
pub const RPC_GATEWAY_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
pub const RPC_GATEWAY_WINDOW_REQUESTS: u8 = 5;
pub const ELECTRUM_PROTOCOL: &str = "1.4";
pub const ELECTRUM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const ELECTRUM_MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
pub const ELECTRUM_PROBE_METHODS: [&str; 5] = [
    "server.features",
    "blockchain.transaction.id_from_pos",
    "blockchain.transaction.get",
    "blockchain.scripthash.get_balance",
    "blockchain.scripthash.listunspent",
];

pub fn method_timeout(method: &str) -> std::time::Duration {
    match method {
        "getblock" => std::time::Duration::from_secs(60),
        "getrawmempool" | "addressutxos" => std::time::Duration::from_secs(30),
        _ => std::time::Duration::from_secs(12),
    }
}

pub const STANDARD_TX_WEIGHT: u64 = 400_000;
pub const PUBLICATION_BUFFER_WEIGHT: u64 = 7_960_000;
pub const PUBLICATION_PENDING_COMMITS: usize = 24;
pub const PUBLICATION_COMMIT_VBYTES: u64 = 90_000;
pub const LITECOIN_DUST_RELAY_FEE: u64 = 30_000;

pub const P2P_PROTOCOL_VERSION: u32 = 70015;
pub const P2P_USER_AGENT: &str = "/urma:0.2.2/";
pub const P2P_MIN_PEERS: usize = 4;
pub const P2P_MAX_PEERS: usize = 8;
pub const P2P_CONNECT_ATTEMPTS_PER_ROUND: usize = 16;
pub const P2P_CONNECT_TIMEOUT_SECS: u64 = 5;
pub const P2P_HANDSHAKE_TIMEOUT_SECS: u64 = 15;
pub const P2P_READ_TIMEOUT_SECS: u64 = 20;
pub const P2P_BLOCK_TIMEOUT_SECS: u64 = 60;
pub const P2P_MAX_PAYLOAD_BYTES: usize = 8_000_000;
pub const P2P_MAX_HEADERS_PER_MESSAGE: usize = 2000;
pub const P2P_MAX_INVENTORY: usize = 50_000;
pub const P2P_MAX_ADDRESSES: usize = 1000;
pub const P2P_ADDRESS_POOL: usize = 1000;
pub const P2P_HEADER_CACHE_MAX: usize = 1_000_000;
pub const P2P_HEADER_CACHE_REVALIDATE: usize = 2016;
pub const P2P_BLOCK_CACHE_BYTES: usize = 64 * 1024 * 1024;
pub const P2P_TIP_REFRESH_SECS: u64 = 20;
pub const P2P_MAX_FUTURE_SECS: u32 = 7200;
pub const P2P_MEDIAN_TIME_SPAN: usize = 11;
pub const P2P_LIMITED_PEER_DEPTH: u64 = 288;
pub const P2P_IDLE_POLL_MILLIS: u64 = 250;
pub const P2P_LOCATOR_LINEAR: usize = 10;
pub const P2P_LITECOIN_NODE_MWEB: u64 = 1 << 24;

pub struct Checkpoint {
    pub height: u64,
    pub header: &'static str,
    pub next_hash: &'static str,
}

pub const LITECOIN_MAINNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 3_187_295,
    header: "14000020931d31f868aaaad00ab3d07bfb30e1adf261e843ea1efe367ea85ed4d50b0beccbee28d90e5dc1495e97786a8dc63e6b741e1ca8ef6226323ed5039c5d74fa7e73d7bd6adda82e1930924a09",
    next_hash: "17976eb8639d9274e2f0b96314aa4cd259c976eecd7100c1c3bbf7c2ad31ed7a",
};

pub const LITECOIN_TESTNET_CHECKPOINT: Checkpoint = Checkpoint {
    height: 4_904_927,
    header: "000000206a866190a6c8e920929c51bc5b3318eb8fb68bd411ae365a5d922f33059816bc6c23b147db3e44528fd06f87e19e876788df08f5323a1ad46f2c863910ef02762125c06affff0f1ec0003c2f",
    next_hash: "ed607657d250aa0a76e6a6e6c451bfa313f93c727a0bb96ba371e9007200e843",
};

pub fn publication_return(chain: urma_chain::observation::Chain) -> u64 {
    use urma_chain::observation::Chain;
    match chain {
        Chain::LitecoinTestnet | Chain::LitecoinMainnet => 110 * LITECOIN_DUST_RELAY_FEE / 1000,
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => 1000,
    }
}
