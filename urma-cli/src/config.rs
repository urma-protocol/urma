use crate::gateway_host::{LinkScheme, PublicPort};
use crate::gateway_http::HttpLimits;
use crate::gateway_route::Freshness;
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;
use urma_chain::observation::Chain;
use urma_runtime::error::{Context, Error, ensure};
use urma_runtime::node::NodeConfig;
use urma_web::config::Limits;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) log_level: LogLevel,
    pub(crate) rpc_url: Option<String>,
    pub(crate) node_auth_file: Option<PathBuf>,
    pub(crate) vault: Option<PathBuf>,
    pub(crate) unlock_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogLevel {
    #[default]
    Info,
    Warn,
    Debug,
}

impl LogLevel {
    pub(crate) fn filter(self) -> tracing_subscriber::filter::LevelFilter {
        use tracing_subscriber::filter::LevelFilter;
        match self {
            Self::Info => LevelFilter::INFO,
            Self::Warn => LevelFilter::WARN,
            Self::Debug => LevelFilter::DEBUG,
        }
    }
}

pub(crate) fn log_directory() -> Result<PathBuf, Error> {
    let state = match std::env::var_os("XDG_STATE_HOME") {
        Some(value) if PathBuf::from(&value).is_absolute() => PathBuf::from(value),
        Some(value) => {
            tracing::warn!(path = ?value, "ignoring relative XDG_STATE_HOME");
            home()?.join(".local/state")
        }
        None => home()?.join(".local/state"),
    };
    Ok(state.join("urma/logs"))
}

fn data_directory() -> Result<PathBuf, Error> {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(value) if PathBuf::from(&value).is_absolute() => Ok(PathBuf::from(value)),
        Some(value) => {
            tracing::warn!(path = ?value, "ignoring relative XDG_DATA_HOME");
            Ok(home()?.join(".local/share"))
        }
        None => Ok(home()?.join(".local/share")),
    }
}

pub(crate) struct StoreChoice(pub(crate) Option<PathBuf>);

pub(crate) fn web_store(requested: StoreChoice) -> Result<PathBuf, Error> {
    match requested.0 {
        Some(path) => Ok(path),
        None => match std::env::var_os("URMA_WEB_STORE") {
            Some(path) => Ok(PathBuf::from(path)),
            None => Ok(data_directory()?.join("urma/web-store")),
        },
    }
}

pub(crate) struct IndexChoice {
    pub(crate) path: Option<PathBuf>,
    pub(crate) registry: Option<bitcoin::Txid>,
}

pub(crate) fn names_index(choice: IndexChoice, network: &str) -> Result<PathBuf, Error> {
    match choice.path {
        Some(path) => Ok(path),
        None => match choice.registry {
            Some(registry) => Ok(registry_index(
                &names_directory(NamesDirChoice(None))?,
                network,
                registry,
            )),
            None => Err(Error::Missing(
                "name the registry with --registry GENESIS_TXID or the index with --index".into(),
            )),
        },
    }
}

pub(crate) struct NamesDirChoice(pub(crate) Option<PathBuf>);

pub(crate) fn names_directory(requested: NamesDirChoice) -> Result<PathBuf, Error> {
    match requested.0 {
        Some(path) => Ok(path),
        None => match std::env::var_os("URMA_NAMES_DIR") {
            Some(path) => Ok(PathBuf::from(path)),
            None => Ok(data_directory()?.join("urma/names")),
        },
    }
}

pub(crate) fn registry_index(directory: &Path, network: &str, registry: bitcoin::Txid) -> PathBuf {
    directory.join(network).join(format!("{registry}.json"))
}

pub(crate) struct GatewayChoice {
    pub(crate) bind: Option<SocketAddr>,
    pub(crate) scheme: Option<LinkScheme>,
    pub(crate) public_port: Option<u16>,
    pub(crate) store: Option<PathBuf>,
    pub(crate) names_dir: Option<PathBuf>,
    pub(crate) rescan_seconds: Option<u64>,
    pub(crate) max_bytes: Option<usize>,
    pub(crate) workers: Option<usize>,
}

pub(crate) struct GatewaySettings {
    pub(crate) bind: SocketAddr,
    pub(crate) scheme: LinkScheme,
    pub(crate) public_port: PublicPort,
    pub(crate) store: PathBuf,
    pub(crate) names_dir: PathBuf,
    pub(crate) rescan: Duration,
    pub(crate) scan_blocks: u64,
    pub(crate) max_bytes: usize,
    pub(crate) workers: usize,
    pub(crate) http: HttpLimits,
    pub(crate) max_age: u64,
    pub(crate) fetch_wait: Duration,
    pub(crate) fetch_retry: Duration,
    pub(crate) fetch_queue: usize,
    pub(crate) cache_bytes: usize,
    pub(crate) freshness: Freshness,
}

impl GatewaySettings {
    const WORKERS: usize = 8;
    const RESCAN_SECONDS: u64 = 30;
    const MAX_INDEX_LAG_BLOCKS: u64 = 2;
    const MAX_SCAN_AGE: Duration = Duration::from_secs(600);
}

pub(crate) fn gateway(choice: GatewayChoice) -> Result<GatewaySettings, Error> {
    let workers = match choice.workers {
        Some(count) => count,
        None => GatewaySettings::WORKERS,
    };
    ensure!((1..=256).contains(&workers), "--workers must be 1..256");
    let rescan = match choice.rescan_seconds {
        Some(seconds) => seconds,
        None => GatewaySettings::RESCAN_SECONDS,
    };
    ensure!(rescan >= 1, "--rescan-seconds must be at least 1");
    ensure!(
        Duration::from_secs(rescan) < GatewaySettings::MAX_SCAN_AGE,
        "--rescan-seconds must stay under {}, the age at which a names index stops being current",
        GatewaySettings::MAX_SCAN_AGE.as_secs()
    );
    Ok(GatewaySettings {
        bind: match choice.bind {
            Some(address) => address,
            None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
        },
        scheme: match choice.scheme {
            Some(scheme) => scheme,
            None => LinkScheme::Https,
        },
        public_port: match choice.public_port {
            Some(port) => PublicPort::Explicit(port),
            None => PublicPort::Default,
        },
        store: web_store(StoreChoice(choice.store))?,
        names_dir: names_directory(NamesDirChoice(choice.names_dir))?,
        rescan: Duration::from_secs(rescan),
        scan_blocks: 1000,
        max_bytes: match choice.max_bytes {
            Some(bytes) => bytes,
            None => Limits::DEFAULT.max_package_bytes,
        },
        workers,
        http: HttpLimits {
            head_bytes: 16 * 1024,
            max_headers: 64,
            target_bytes: 8 * 1024,
            io_timeout: Duration::from_secs(15),
            head_timeout: Duration::from_secs(20),
            accept_backoff: Duration::from_millis(250),
            linger: Duration::from_secs(2),
            linger_bytes: 64 * 1024,
        },
        max_age: 60,
        fetch_wait: Duration::from_secs(8),
        fetch_retry: Duration::from_secs(60),
        fetch_queue: 32,
        cache_bytes: 256 * 1024 * 1024,
        freshness: Freshness {
            max_lag: GatewaySettings::MAX_INDEX_LAG_BLOCKS,
            max_age: GatewaySettings::MAX_SCAN_AGE,
            retry: Duration::from_secs(rescan),
        },
    })
}

pub(crate) fn names_watch_interval() -> std::time::Duration {
    std::time::Duration::from_secs(15)
}

pub(crate) fn home() -> Result<PathBuf, Error> {
    Ok(std::env::var_os("HOME")
        .context("HOME is unset; set HOME to your user directory")?
        .into())
}

pub(crate) fn load() -> Result<Settings, Error> {
    let path = match std::env::var_os("URMA_CONFIG") {
        Some(path) => PathBuf::from(path),
        None => home()?.join(".config/urma/config.json"),
    };
    if !path.try_exists()? {
        return Ok(Settings::default());
    }
    Ok(serde_json::from_slice(
        &urma_runtime::storage::read_bounded(&path, 16_384)?,
    )?)
}

pub(crate) fn chain(testnet: bool) -> Result<Chain, Error> {
    if testnet {
        return Ok(Chain::LitecoinTestnet);
    }
    let name = match std::env::var_os("URMA_NETWORK") {
        Some(name) => name,
        None => return Ok(Chain::LitecoinMainnet),
    };
    match name.to_str().context("URMA_NETWORK must be UTF-8")? {
        "litecoin-mainnet" => Ok(Chain::LitecoinMainnet),
        "litecoin-testnet" => Ok(Chain::LitecoinTestnet),
        "bitcoin-regtest" => Ok(Chain::BitcoinRegtest),
        "bitcoin-testnet4" => Ok(Chain::BitcoinTestnet4),
        other => Err(Error::Invalid(format!("invalid URMA_NETWORK {other}"))),
    }
}

pub(crate) fn connection(chain: Chain) -> Result<Connection, Error> {
    let settings = load()?;
    let rpc = select(
        std::env::var_os("URMA_RPC_URL")
            .map(|value| {
                value
                    .into_string()
                    .map_err(|invalid| Error::Invalid(format!("non-UTF-8 RPC URL {invalid:?}")))
            })
            .transpose()?,
        settings.rpc_url,
    );
    let auth = select(
        std::env::var_os("URMA_NODE_AUTH_FILE").map(PathBuf::from),
        settings.node_auth_file,
    );
    match (rpc, auth) {
        (Some(rpc_url), Some(cookie_file)) => Ok(Connection::Local(NodeConfig {
            chain,
            rpc_url,
            cookie_file,
        })),
        (None, None) => Ok(Connection::Public),
        (Some(rpc), None) => Err(Error::Invalid(format!(
            "local node {rpc} needs node_auth_file in config"
        ))),
        (None, Some(auth)) => Err(Error::Invalid(format!(
            "local auth {} needs rpc_url in config",
            auth.display()
        ))),
    }
}

pub(crate) fn credentials() -> Result<(PathBuf, PathBuf), Error> {
    let settings = load()?;
    let vault = path_setting("URMA_VAULT", settings.vault, ".local/share/urma/vault.urma")?;
    let unlock = path_setting(
        "URMA_UNLOCK_FILE",
        settings.unlock_file,
        ".config/urma/unlock",
    )?;
    ensure!(
        vault.try_exists()?,
        "no identity vault; run urma key create --help"
    );
    ensure!(
        unlock.try_exists()?,
        "identity is locked; configure unlock_file in ~/.config/urma/config.json or set URMA_UNLOCK_FILE"
    );
    Ok((vault, unlock))
}

pub(crate) enum Connection {
    Local(NodeConfig),
    Public,
}

fn select<T>(first: Option<T>, second: Option<T>) -> Option<T> {
    match first {
        Some(value) => Some(value),
        None => second,
    }
}

fn path_setting(name: &str, setting: Option<PathBuf>, default: &str) -> Result<PathBuf, Error> {
    match select(std::env::var_os(name).map(PathBuf::from), setting) {
        Some(path) => Ok(path),
        None => Ok(home()?.join(default)),
    }
}

pub(crate) fn git_limits() -> Result<urma_git::inventory::Limits, Error> {
    match std::env::var_os("URMA_GIT_LIMITS") {
        Some(path) => Ok(serde_json::from_slice(
            &urma_runtime::storage::read_bounded(&PathBuf::from(path), 4096)?,
        )?),
        None => Ok(urma_git::inventory::Limits::default()),
    }
}

pub(crate) fn expert_node() -> Result<NodeConfig, Error> {
    match connection(chain(false)?)? {
        Connection::Local(node) => Ok(node),
        Connection::Public => Err(Error::Missing(
            "this expert command needs a local node configured with rpc_url and node_auth_file"
                .into(),
        )),
    }
}

pub(crate) enum Output {
    Human,
    Json,
}

pub(crate) fn output() -> Result<Output, Error> {
    match std::env::var_os("URMA_OUTPUT") {
        None => Ok(Output::Human),
        Some(value) => match value.to_str().context("URMA_OUTPUT must be UTF-8")? {
            "json" => Ok(Output::Json),
            "human" => Ok(Output::Human),
            other => Err(Error::Invalid(format!(
                "unsupported URMA_OUTPUT {other}; use human or json"
            ))),
        },
    }
}

pub(crate) fn archive_key() -> Result<PathBuf, Error> {
    path_setting("URMA_ARCHIVE_KEY", None, ".local/share/urma/archive.key")
}

pub(crate) struct KeyLocation(pub(crate) Option<PathBuf>);

pub(crate) fn key_location(location: KeyLocation) -> Result<PathBuf, Error> {
    match location.0 {
        Some(path) => Ok(path),
        None => archive_key(),
    }
}

pub(crate) fn require_archive_key() -> Result<PathBuf, Error> {
    let path = archive_key()?;
    ensure!(
        path.try_exists()?,
        "no private recovery key at {}; run urma key recovery-generate, or configure URMA_ARCHIVE_KEY",
        path.display()
    );
    Ok(path)
}

static VERBOSITY: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub(crate) fn set_verbosity(level: u8) {
    VERBOSITY.store(level, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn verbosity() -> u8 {
    VERBOSITY.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) struct PublicationOutput(pub Option<PathBuf>);

pub(crate) fn publication_directory(
    repo: &std::path::Path,
    requested: PublicationOutput,
) -> Result<PathBuf, Error> {
    match requested.0 {
        Some(path) => Ok(path),
        None => Ok(repo.join(".urma-plan")),
    }
}

pub(crate) fn publication_poll_interval() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

pub(crate) fn publication_tip_interval() -> std::time::Duration {
    std::time::Duration::from_secs(2)
}

pub(crate) fn web_watch_interval() -> std::time::Duration {
    std::time::Duration::from_secs(10)
}

pub(crate) struct FeeCeiling(pub Option<u64>);

pub(crate) fn publication_fee_ceiling(requested: FeeCeiling, estimate: u64) -> u64 {
    match requested.0 {
        Some(limit) => limit,
        None => estimate,
    }
}
