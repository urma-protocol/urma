use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, multiaddr::Protocol};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use urma_chain::observation::Chain;
use urma_node::{
    config,
    engine::Engine,
    model::ArchiveConfig,
    peer::{OverlayCommitSource, PeerNetwork, PeerSource},
    peer_discovery::Discovery,
    peer_sync::{OverlayInfo, PeerSync},
    peerbook::{Origin, PeerAddress, PeerBook},
    retrieval::RecordSource,
    service::{Service, create_token},
    source::{CommitSources, LitecoinSource, LocalRpcCommitSource, PublicCommitSource},
};
use urma_runtime::{
    endpoints,
    p2p::{Anchor, HeaderBootstrap, context_headers},
};

/// `i64::MAX` as an unsigned CLI bound: byte counts are stored as SQLite INTEGER.
const MAX_ARG: u64 = 9_223_372_036_854_775_807;

#[derive(Parser)]
#[command(about = "Optional URMA archive service")]
struct Arguments {
    #[arg(long)]
    data: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open local state without any network operation.
    Status,
    /// Create a new private service token (no wallet keys involved).
    CreateToken { path: PathBuf },
    /// Create a separate transport identity; never a wallet or decryption key.
    CreatePeerKey { path: PathBuf },
    /// Run the authenticated loopback service in the foreground.
    Serve {
        #[arg(long, default_value = "127.0.0.1:28331")]
        listen: SocketAddr,
        #[arg(long)]
        token_file: PathBuf,
        /// Opt into the checkpoint-relative Litecoin source; offline by default.
        #[arg(long)]
        p2p: bool,
        /// Explicit trusted anchor and authenticated preceding header context.
        #[arg(long, requires = "p2p")]
        header_bootstrap: Option<PathBuf>,
        /// Litecoin peer to sync headers/blocks from (repeatable); replaces DNS seeds.
        #[arg(long = "chain-peer", requires = "p2p", value_name = "ADDR")]
        chain_peer: Vec<SocketAddr>,
        /// Loopback cookie RPC for missing commit parents; no default endpoint.
        #[arg(long, requires_all = ["p2p", "commit_rpc_cookie"])]
        commit_rpc_url: Option<String>,
        /// RPC cookie file authenticating --commit-rpc-url; no other RPC auth.
        #[arg(long, requires_all = ["p2p", "commit_rpc_url"])]
        commit_rpc_cookie: Option<PathBuf>,
        /// Never send missing commit TXIDs to the chain's default public providers.
        #[arg(long, requires = "p2p")]
        no_commit_public: bool,
        /// Opt into the URMA overlay using an explicitly created transport key.
        #[arg(long)]
        peer_key: Option<PathBuf>,
        /// Optional URMA peer listener, separate from the local control API.
        #[arg(long, requires = "peer_key")]
        urma_listen: Option<SocketAddr>,
        /// Explicit IP/TCP/p2p routing hint; saved in this archive's peer book.
        #[arg(long, requires = "peer_key")]
        urma_peer: Vec<libp2p::Multiaddr>,
        /// Extra bootstrap seed (repeatable); saved with seed origin.
        #[arg(long, requires = "peer_key")]
        urma_seed: Vec<libp2p::Multiaddr>,
        /// Do not add this chain's built-in DNS seeds.
        #[arg(long, requires = "peer_key")]
        no_seeds: bool,
        /// Public IP/TCP address peers should dial; advertised through identify.
        #[arg(long, requires = "peer_key")]
        urma_announce: Vec<libp2p::Multiaddr>,
        /// Soft reclaimable cache target (not a SQLite/WAL or total archive quota).
        #[arg(long, default_value_t = urma_node::cache::DEFAULT_CACHE_BYTES, value_parser = clap::value_parser!(u64).range(..=MAX_ARG))]
        cache_bytes: u64,
        /// Maximum payload per background object attempt (not a protocol limit).
        #[arg(long, default_value_t = 64 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..))]
        max_object_bytes: u64,
        #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..))]
        max_object_nodes: u32,
        #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..))]
        object_timeout_seconds: u64,
    },
}

fn main() -> std::process::ExitCode {
    if let Err(error) = run() {
        eprintln!("urma-node: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn open_chain_source(
    args: &Arguments,
    chain: Chain,
    height: u64,
) -> Result<LitecoinSource, Box<dyn std::error::Error>> {
    let Command::Serve {
        header_bootstrap,
        chain_peer: pinned,
        ..
    } = &args.command
    else {
        return Err("the chain source belongs to serve".into());
    };
    let pinned = pinned.clone();
    let bootstrap = match header_bootstrap {
        Some(path) => Some(read_header_bootstrap(path, chain, height)?),
        None => None,
    };
    // Ownership and bootstrap validation both precede mutable cache access.
    let cache = args.data.join("headers");
    std::fs::create_dir_all(&cache)?;
    Ok(match bootstrap {
        Some(bootstrap) => LitecoinSource::open_bootstrap(&cache, bootstrap, pinned)?,
        None => LitecoinSource::open(chain, &cache, Anchor::embedded(chain)?, pinned)?,
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();
    if let Command::CreateToken { path } = &args.command {
        create_token(path)?;
        return Ok(());
    }
    if let Command::CreatePeerKey { path } = &args.command {
        create_peer_key(path)?;
        return Ok(());
    }
    let config: ArchiveConfig = serde_json::from_slice(&urma_io_read_config(&args.config)?)?;
    let synchronize = matches!(&args.command, Command::Serve { p2p: true, .. });
    let chain = config.chain;
    let application_height = config.application_start.height;
    let mut engine = Engine::open(&args.data, config, None)?;
    if synchronize {
        let source = open_chain_source(&args, chain, application_height)?;
        engine = engine.with_source(Arc::new(source))?;
    }
    let commit_source = connect_commit_source(&args.command, chain);
    let engine = Arc::new(engine);
    match args.command {
        Command::Status => println!("{}", serde_json::to_string_pretty(&engine.status()?)?),
        Command::Serve {
            listen,
            token_file,
            max_object_bytes,
            cache_bytes,
            max_object_nodes,
            object_timeout_seconds,
            peer_key,
            urma_listen,
            urma_peer,
            urma_seed,
            no_seeds,
            urma_announce,
            no_commit_public,
            ..
        } => {
            let token = read_token(&token_file)?;
            let retain =
                synchronize && engine.status()?.retention == urma_node::model::Retention::Unpruned;
            let mut service = bind_service(listen, token, engine.clone(), cache_bytes)?;
            // Only the standalone binary owns process signals. The callback
            // requests the same cooperative stop as authenticated HTTP shutdown;
            // worker and overlay joins still happen on this foreground path.
            // Inherited dispositions (e.g. SIGHUP ignored under nohup) are
            // replaced, so all three signals always request this stop.
            let shutdown = service.shutdown_handle();
            ctrlc::set_handler(move || shutdown.request())?;
            if retain {
                let scratch = args.data.join("scratch");
                private_directory(&scratch)?;
                service = service.with_retention(
                    scratch,
                    urma_runtime::multipart::RecoveryLimits {
                        max_payload_bytes: max_object_bytes,
                        max_nodes: max_object_nodes,
                        attempts: 1,
                        timeout: std::time::Duration::from_secs(object_timeout_seconds),
                    },
                )?;
            }
            // Control auth/configuration and archive ownership precede any
            // overlay startup. Without --peer-key this path does no key/book I/O.
            let overlay = OverlayOptions {
                key: peer_key,
                listen: urma_listen,
                manual: urma_peer,
                seeds: urma_seed,
                builtin_seeds: !no_seeds,
                announce: urma_announce,
                commit_parents: synchronize,
            };
            let (service, network, overlay) =
                attach_overlay(service, &args.data, &engine, chain, overlay)?;
            let public = (synchronize && !no_commit_public).then(|| args.data.join("providers"));
            let service = attach_commit_sources(service, chain, commit_source, overlay, public)?;
            eprintln!(
                "URMA Node listening at {} (authenticated loopback)",
                service.address()?
            );
            let outcome = service.run(synchronize);
            let network_outcome = match network {
                Some(network) => shutdown_overlay(network),
                None => Ok(()),
            };
            outcome?;
            network_outcome?;
        }
        Command::CreateToken { .. } | Command::CreatePeerKey { .. } => unreachable!(),
    }
    Ok(())
}

fn connect_commit_source(command: &Command, chain: Chain) -> Option<LocalRpcCommitSource> {
    let Command::Serve {
        commit_rpc_url: Some(rpc_url),
        commit_rpc_cookie: Some(cookie_file),
        ..
    } = command
    else {
        return None;
    };
    Some(LocalRpcCommitSource::new(
        chain,
        rpc_url.clone(),
        cookie_file.clone(),
    ))
}

fn bind_service(
    listen: SocketAddr,
    token: String,
    engine: Arc<Engine>,
    cache_bytes: u64,
) -> Result<Service, Box<dyn std::error::Error>> {
    Ok(Service::bind(listen, token, engine)?.with_cache_limit(cache_bytes)?)
}

struct OverlayOptions {
    key: Option<PathBuf>,
    listen: Option<SocketAddr>,
    manual: Vec<Multiaddr>,
    seeds: Vec<Multiaddr>,
    builtin_seeds: bool,
    announce: Vec<Multiaddr>,
    commit_parents: bool,
}

/// Manual hints, then built-in and explicit seeds, merged into the saved book.
fn load_book(
    path: &Path,
    engine: &Engine,
    chain: Chain,
    options: &OverlayOptions,
) -> Result<PeerBook, Box<dyn std::error::Error>> {
    let mut book = PeerBook::load(path, engine.status()?.chain_genesis)?;
    let mut changed = false;
    for address in &options.manual {
        changed |= book.add(address.clone(), Origin::Manual)?;
    }
    let builtin = match options.builtin_seeds {
        true => config::seeds(chain)?,
        false => Vec::new(),
    };
    for seed in builtin.into_iter().chain(options.seeds.iter().cloned()) {
        changed |= book.add(seed, Origin::Seed)?;
    }
    if changed {
        book.save(path)?;
    }
    Ok(book)
}

type Overlay = (
    Service,
    Option<Arc<PeerNetwork>>,
    Option<OverlayCommitSource>,
);

fn attach_overlay(
    service: Service,
    data: &Path,
    engine: &Arc<Engine>,
    chain: Chain,
    options: OverlayOptions,
) -> Result<Overlay, Box<dyn std::error::Error>> {
    let Some(path) = &options.key else {
        return Ok((service, None, None));
    };
    let identity = read_peer_key(path)?;
    let book_path = data.join("peers.json");
    let book = load_book(&book_path, engine, chain, &options)?;
    let listener = options.listen.map(|socket| {
        let mut address = Multiaddr::empty();
        address.push(match socket.ip() {
            IpAddr::V4(ip) => Protocol::Ip4(ip),
            IpAddr::V6(ip) => Protocol::Ip6(ip),
        });
        address.push(Protocol::Tcp(socket.port()));
        address
    });
    let network = Arc::new(PeerNetwork::start(
        Arc::clone(engine),
        identity,
        listener,
        options.announce,
    )?);
    let peers = book.sync_addresses(&engine.omitting_peers()?);
    let book_size = book.stats().book;
    let book = Arc::new(Mutex::new(book));
    let sources = peers
        .iter()
        .cloned()
        .map(|address| -> Arc<dyn RecordSource + Send + Sync> { Arc::new(network.source(address)) })
        .collect();
    let service = service.with_record_sources(sources)?;
    let service = match options.commit_parents {
        true => service
            .with_peer_sync(peer_sync(&network, &peers, book_size)?)?
            .with_discovery(Discovery::new(Arc::clone(&network), book, book_path))?,
        false => service,
    };
    eprintln!(
        "URMA peer identity {} listener {:?}",
        network.peer_id(),
        network.listen_address()
    );
    let overlay = options
        .commit_parents
        .then(|| network.commit_source(chain, peers));
    Ok((service, Some(network), overlay))
}

/// Inventory peers come from the same peer-book entries as record and commit
/// sources, one per peer identity; the first address of a peer wins.
fn peer_sync(
    network: &Arc<PeerNetwork>,
    peers: &[PeerAddress],
    book_size: u64,
) -> Result<PeerSync, Box<dyn std::error::Error>> {
    let mut entries: Vec<(String, PeerSource)> = Vec::new();
    for address in peers {
        let label = address.peer_id().to_string();
        if entries.iter().any(|(known, _source)| *known == label) {
            continue;
        }
        entries.push((label, network.source(address.clone())));
    }
    let shared = Arc::clone(network);
    Ok(PeerSync {
        peers: entries,
        info: OverlayInfo {
            peer_id: network.peer_id().to_string(),
            listen: network.listen_address().map(|address| address.to_string()),
            peer_book: book_size,
            connected: Arc::new(move || shared.connected_peers()),
        },
    })
}

/// The service owned the only other handle; it is released when run returns.
fn shutdown_overlay(network: Arc<PeerNetwork>) -> Result<(), urma_node::Error> {
    match Arc::try_unwrap(network) {
        Ok(network) => network.shutdown(),
        Err(shared) => Err(urma_node::Error::Busy(format!(
            "overlay still shared by {} handles after service stop",
            Arc::strong_count(&shared)
        ))),
    }
}

fn attach_commit_sources(
    service: Service,
    chain: Chain,
    local: Option<LocalRpcCommitSource>,
    overlay: Option<OverlayCommitSource>,
    public: Option<PathBuf>,
) -> Result<Service, Box<dyn std::error::Error>> {
    let mut sources = CommitSources::new(chain);
    if let Some(local) = local {
        sources.push("local-rpc".into(), Box::new(local));
    }
    if let Some(overlay) = overlay {
        sources.push("overlay".into(), Box::new(overlay));
    }
    let has_public = !endpoints::defaults(chain).is_empty();
    if let Some(cache) = public.filter(|_cache| has_public) {
        private_directory(&cache)?;
        sources.push(
            "public".into(),
            Box::new(PublicCommitSource::new(chain, cache)),
        );
    }
    if sources.is_empty() {
        return Ok(service);
    }
    Ok(service.with_commit_sources(sources)?)
}

fn private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists
                && std::fs::symlink_metadata(path)?.is_dir() =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn create_peer_key(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let mut bytes = key.to_protobuf_encoding()?;
    let result = urma_io::write_new(path, &bytes);
    bytes.fill(0);
    result?;
    Ok(())
}

fn read_peer_key(
    path: &std::path::Path,
) -> Result<libp2p::identity::Keypair, Box<dyn std::error::Error>> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err("peer key must be a regular private file".into());
    }
    let bytes = urma_io::read_private(path, 4096)?;
    let key = libp2p::identity::Keypair::from_protobuf_encoding(&bytes)?;
    if key.key_type() != libp2p::identity::KeyType::Ed25519 {
        return Err("peer identity must be Ed25519".into());
    }
    Ok(key)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderBootstrapFile {
    version: u32,
    chain: urma_chain::observation::Chain,
    height: u64,
    header: String,
    ancestors: Vec<String>,
}

fn read_header_bootstrap(
    path: &std::path::Path,
    chain: urma_chain::observation::Chain,
    application_height: u64,
) -> Result<HeaderBootstrap, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("header bootstrap exceeds 1 MiB".into());
    }
    let input: HeaderBootstrapFile = serde_json::from_slice(&bytes)?;
    if input.version != 1 || input.chain.genesis()? != chain.genesis()? {
        return Err("header bootstrap version or chain mismatch".into());
    }
    if input.height > application_height {
        return Err("application start precedes the supplied header anchor".into());
    }
    let count = usize::try_from(input.height.min(u64::try_from(context_headers(chain))?))?;
    if input.ancestors.len() != count {
        return Err(format!("header bootstrap needs exactly {count} ancestors").into());
    }
    fn header(raw: &str) -> Result<bitcoin::block::Header, Box<dyn std::error::Error>> {
        if raw.len() != 160 {
            return Err("bootstrap header must be exactly 80 bytes encoded as hex".into());
        }
        Ok(bitcoin::consensus::deserialize(&hex::decode(raw)?)?)
    }
    let anchor = header(&input.header)?;
    let ancestors = input
        .ancestors
        .iter()
        .map(|raw| header(raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HeaderBootstrap::new(
        chain,
        input.height,
        anchor,
        ancestors,
    )?)
}

fn urma_io_read_config(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(std::io::Error::other("config exceeds 64 KiB"));
    }
    Ok(bytes)
}

fn read_token(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err("invalid service token file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("service token must not be accessible by group or others".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    if bytes.len() > 128 {
        return Err("service token size limit".into());
    }
    Ok(std::str::from_utf8(&bytes)?.trim().to_string())
}

#[cfg(test)]
mod bootstrap_config_tests {
    use super::*;
    use serde_json::{Value, json};
    use urma_chain::observation::Chain;

    fn input() -> Value {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        json!({"version":1,"chain":"bitcoin-regtest","height":0,
            "header":hex::encode(bitcoin::consensus::serialize(&genesis.header)),"ancestors":[]})
    }

    fn read(value: Value, application_height: u64) -> Result<HeaderBootstrap, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        read_header_bootstrap(&path, Chain::BitcoinRegtest, application_height)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn bootstrap_file_binds_version_chain_height_and_genesis() {
        let bootstrap = read(input(), 0).unwrap();
        assert_eq!(bootstrap.height(), 0);
        assert_eq!(
            bootstrap.chain().genesis().unwrap(),
            Chain::BitcoinRegtest.genesis().unwrap()
        );
        assert!(bootstrap.ancestors().is_empty());
        for (field, value, expected) in [
            ("version", json!(2), "version or chain mismatch"),
            (
                "chain",
                json!("litecoin-testnet"),
                "version or chain mismatch",
            ),
            ("height", json!(1), "application start precedes"),
            ("unexpected", json!(true), "unknown field"),
        ] {
            let mut invalid = input();
            invalid[field] = value;
            assert!(read(invalid, 0).unwrap_err().contains(expected));
        }
        let mut invalid = input();
        let mut header =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
        header.nonce ^= 1;
        invalid["header"] = json!(hex::encode(bitcoin::consensus::serialize(&header)));
        assert!(read(invalid, 0).unwrap_err().contains("genesis"));
    }

    #[test]
    fn bootstrap_file_requires_exact_header_encoding_and_context_count() {
        for encoded in ["00".repeat(79), "00".repeat(81), "zz".repeat(80)] {
            let mut invalid = input();
            invalid["header"] = json!(encoded);
            assert!(read(invalid, 0).is_err());
        }
        let mut invalid = input();
        invalid["height"] = json!(1);
        assert!(
            read(invalid, 1)
                .unwrap_err()
                .contains("exactly 1 ancestors")
        );
        let mut invalid = input();
        invalid["ancestors"] = json!([invalid["header"].clone()]);
        assert!(
            read(invalid, 0)
                .unwrap_err()
                .contains("exactly 0 ancestors")
        );
    }

    #[test]
    fn bootstrap_input_size_is_bounded_before_json_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bootstrap.json");
        std::fs::write(&path, vec![b' '; 1_048_577]).unwrap();
        assert!(
            read_header_bootstrap(&path, Chain::BitcoinRegtest, 0)
                .unwrap_err()
                .to_string()
                .contains("exceeds 1 MiB")
        );
    }

    #[test]
    fn explicit_bootstrap_requires_p2p_and_legacy_serve_flags_remain_optional() {
        let base = [
            "urma-node",
            "--data",
            "data",
            "--config",
            "config",
            "serve",
            "--token-file",
            "token",
        ];
        let offline = Arguments::try_parse_from(base).unwrap();
        assert!(matches!(
            offline.command,
            Command::Serve {
                p2p: false,
                header_bootstrap: None,
                ..
            }
        ));
        let mut explicit = base.to_vec();
        explicit.extend(["--header-bootstrap", "bootstrap.json"]);
        assert!(Arguments::try_parse_from(&explicit).is_err());
        explicit.push("--p2p");
        let strict = Arguments::try_parse_from(explicit).unwrap();
        assert!(matches!(
            strict.command,
            Command::Serve {
                p2p: true,
                header_bootstrap: Some(_),
                ..
            }
        ));
        let mut legacy = base.to_vec();
        legacy.push("--p2p");
        assert!(matches!(
            Arguments::try_parse_from(legacy).unwrap().command,
            Command::Serve {
                p2p: true,
                header_bootstrap: None,
                ..
            }
        ));
        let (local, fly) = ("127.0.0.1:19335", "137.66.3.26:19335");
        let mut pinned = base.to_vec();
        pinned.extend(["--chain-peer", local, "--chain-peer", fly]);
        assert!(Arguments::try_parse_from(&pinned).is_err());
        pinned.push("--p2p");
        let peers: Vec<SocketAddr> = vec![local.parse().unwrap(), fly.parse().unwrap()];
        assert!(matches!(Arguments::try_parse_from(pinned).unwrap().command,
            Command::Serve { chain_peer, .. } if chain_peer == peers));
    }
}

#[cfg(test)]
mod peer_config_tests {
    use super::*;

    #[test]
    fn peer_identity_is_explicit_private_stable_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer.key");
        assert!(read_peer_key(&path).is_err());
        assert!(!path.exists());
        create_peer_key(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let id = read_peer_key(&path).unwrap().public().to_peer_id();
        assert_eq!(read_peer_key(&path).unwrap().public().to_peer_id(), id);
        assert!(create_peer_key(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_peer_key(&path).is_err());
        }
    }

    #[test]
    fn invalid_transport_keys_are_refused_without_replacement() {
        let dir = tempfile::tempdir().unwrap();
        for bytes in [vec![], vec![1, 2, 3], vec![0; 4097]] {
            let path = dir.path().join("invalid.key");
            urma_io::write_replace(&path, &bytes).unwrap();
            assert!(read_peer_key(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        assert!(read_peer_key(dir.path()).is_err());
    }

    #[test]
    fn overlay_flags_require_explicit_identity_and_do_not_imply_chain_sync() {
        let base = [
            "urma-node",
            "--data",
            "data",
            "--config",
            "config",
            "serve",
            "--token-file",
            "token",
        ];
        assert!(matches!(
            Arguments::try_parse_from(base).unwrap().command,
            Command::Serve {
                peer_key: None,
                urma_listen: None,
                p2p: false,
                ..
            }
        ));
        let mut listener = base.to_vec();
        listener.extend(["--urma-listen", "127.0.0.1:0"]);
        assert!(Arguments::try_parse_from(&listener).is_err());
        listener.extend(["--peer-key", "transport.key"]);
        assert!(matches!(
            Arguments::try_parse_from(&listener).unwrap().command,
            Command::Serve {
                peer_key: Some(_),
                urma_listen: Some(_),
                p2p: false,
                ..
            }
        ));
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let address = format!("/ip4/127.0.0.1/tcp/3210/p2p/{peer}");
        let mut remote = base.to_vec();
        remote.extend(["--urma-peer", &address]);
        assert!(Arguments::try_parse_from(&remote).is_err());
        remote.extend(["--peer-key", "transport.key"]);
        assert!(Arguments::try_parse_from(remote).is_ok());
        assert_eq!(i64::try_from(MAX_ARG).unwrap(), i64::MAX);
        for (value, expected) in [("0", 0), ("9223372036854775807", MAX_ARG)] {
            let mut cache = base.to_vec();
            cache.extend(["--cache-bytes", value]);
            assert!(matches!(Arguments::try_parse_from(cache).unwrap().command,
                Command::Serve { cache_bytes, p2p: false, .. } if cache_bytes == expected));
        }
        for value in ["-1", "9223372036854775808", "not-a-number"] {
            let mut cache = base.to_vec();
            cache.extend(["--cache-bytes", value]);
            assert!(Arguments::try_parse_from(cache).is_err());
        }
        for option in [
            "--max-object-bytes",
            "--max-object-nodes",
            "--object-timeout-seconds",
        ] {
            let mut invalid = base.to_vec();
            invalid.extend([option, "0", "--peer-key", "transport.key"]);
            assert!(Arguments::try_parse_from(invalid).is_err());
        }
    }
}
