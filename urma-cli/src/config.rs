use serde::Deserialize;
use std::path::PathBuf;
use urma_chain::observation::Chain;
use urma_runtime::error::{Context, Error, ensure};
use urma_runtime::node::NodeConfig;

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
            Some(registry) => {
                let directory = match std::env::var_os("URMA_NAMES_DIR") {
                    Some(path) => PathBuf::from(path),
                    None => data_directory()?.join("urma/names"),
                };
                Ok(directory.join(network).join(format!("{registry}.json")))
            }
            None => Err(Error::Missing(
                "name the registry with --registry GENESIS_TXID or the index with --index".into(),
            )),
        },
    }
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
