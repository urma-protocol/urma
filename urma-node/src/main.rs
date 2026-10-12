use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use urma_node::{
    engine::Engine,
    model::ArchiveConfig,
    service::{Service, create_token},
    source::LitecoinSource,
};
use urma_runtime::p2p::{Anchor, HeaderBootstrap, context_headers};

#[derive(Parser)]
#[command(about = "Optional URMA archive service (development branch)")]
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
        /// Maximum payload per background object attempt (not a protocol limit).
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_object_bytes: u64,
        #[arg(long, default_value_t = 4096)]
        max_object_nodes: u32,
        #[arg(long, default_value_t = 15)]
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();
    if let Command::CreateToken { path } = &args.command {
        create_token(path)?;
        return Ok(());
    }
    let config: ArchiveConfig = serde_json::from_slice(&urma_io_read_config(&args.config)?)?;
    let synchronize = matches!(&args.command, Command::Serve { p2p: true, .. });
    let chain = config.chain;
    let application_height = config.application_start.height;
    let mut engine = Engine::open(&args.data, config, None)?;
    if synchronize {
        let bootstrap = match &args.command {
            Command::Serve {
                header_bootstrap: Some(path),
                ..
            } => Some(read_header_bootstrap(path, chain, application_height)?),
            _ => None,
        };
        // Ownership and bootstrap validation both precede mutable cache access.
        let cache = args.data.join("headers");
        std::fs::create_dir_all(&cache)?;
        let source = match bootstrap {
            Some(bootstrap) => LitecoinSource::open_bootstrap(&cache, bootstrap, Vec::new())?,
            None => LitecoinSource::open(chain, &cache, Anchor::embedded(chain)?, Vec::new())?,
        };
        engine = engine.with_source(Arc::new(source))?;
    }
    let engine = Arc::new(engine);
    match args.command {
        Command::Status => println!("{}", serde_json::to_string_pretty(&engine.status()?)?),
        Command::Serve {
            listen,
            token_file,
            max_object_bytes,
            max_object_nodes,
            object_timeout_seconds,
            ..
        } => {
            let token = read_token(&token_file)?;
            let retain =
                synchronize && engine.status()?.retention == urma_node::model::Retention::Unpruned;
            let mut service = Service::bind(listen, token, engine)?;
            if retain {
                let scratch = args.data.join("scratch");
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                match builder.create(&scratch) {
                    Ok(()) => (),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::AlreadyExists
                            && std::fs::symlink_metadata(&scratch)?.is_dir() =>
                    {
                        ()
                    }
                    Err(e) => return Err(e.into()),
                }
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
            eprintln!(
                "URMA Node listening at {} (authenticated loopback)",
                service.address()?
            );
            service.run(synchronize)?;
        }
        Command::CreateToken { .. } => unreachable!(),
    }
    Ok(())
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
    let count = input.height.min(u64::try_from(context_headers(chain))?) as usize;
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
    }
}
