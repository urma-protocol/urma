use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use urma_node::{
    engine::Engine,
    model::ArchiveConfig,
    service::{Service, create_token},
    source::LitecoinSource,
};
use urma_runtime::p2p::Anchor;

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
    let mut engine = Engine::open(&args.data, config, None)?;
    if synchronize {
        let cache = args.data.join("headers");
        std::fs::create_dir_all(&cache)?;
        engine = engine.with_source(Arc::new(LitecoinSource::open(
            chain,
            &cache,
            Anchor::embedded(chain)?,
            Vec::new(),
        )?))?;
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
