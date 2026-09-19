use serde::Deserialize;
use std::path::PathBuf;
use urma::error::{Context, Error, ensure};
use urma_chain::observation::Chain;
use urma_runtime::node::NodeConfig;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) rpc_url: Option<String>,
    pub(crate) node_auth_file: Option<PathBuf>,
    pub(crate) vault: Option<PathBuf>,
    pub(crate) unlock_file: Option<PathBuf>,
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
    Ok(serde_json::from_slice(&urma::storage::read_bounded(
        &path, 16_384,
    )?)?)
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
        Some(path) => Ok(serde_json::from_slice(&urma::storage::read_bounded(
            &PathBuf::from(path),
            4096,
        )?)?),
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

pub(crate) struct FeeCeiling(pub Option<u64>);

pub(crate) fn publication_fee_ceiling(requested: FeeCeiling, estimate: u64) -> u64 {
    match requested.0 {
        Some(limit) => limit,
        None => estimate,
    }
}
