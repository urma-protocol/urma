//! Explicit local control client. No archive, daemon or chain source is opened.
use bitcoin::{BlockHash, Txid};
use clap::{Parser, Subcommand};
use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
};
use urma_names::name::Name;
use urma_node::{Error, client::Client, model::ChainPoint};

#[derive(Parser)]
#[command(about = "Control an explicitly configured authenticated loopback URMA node")]
struct Args {
    #[arg(long)]
    endpoint: SocketAddr,
    #[arg(long)]
    token_file: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Object {
        root: Txid,
    },
    Pin {
        root: Txid,
    },
    Unpin {
        root: Txid,
    },
    Prune,
    OverlayOmissions,
    OverlayBook,
    NamesStatus {
        genesis: Txid,
    },
    NamesRegister {
        genesis: Txid,
        #[arg(value_parser = parse_height)]
        height: u64,
        hash: BlockHash,
    },
    NamesStep {
        genesis: Txid,
    },
    NamesResolve {
        genesis: Txid,
        #[arg(value_parser = parse_name)]
        name: Name,
    },
}

fn parse_height(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("height must be a decimal integer from 0 through i64::MAX".into());
    }
    let height = text
        .parse::<u64>()
        .map_err(|_| "height must be a decimal integer from 0 through i64::MAX".to_owned())?;
    if height > i64::MAX as u64 {
        return Err("height must be a decimal integer from 0 through i64::MAX".into());
    }
    Ok(height)
}

fn parse_name(text: &str) -> Result<Name, String> {
    Name::parse(text).map_err(|error| error.to_string())
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if !std::fs::symlink_metadata(&args.token_file)?.is_file() {
        return Err(io::Error::other("token file must be a regular private file").into());
    }
    let bytes = urma_io::read_private(&args.token_file, 256)?;
    let token = std::str::from_utf8(&bytes)?.trim();
    // The existing constructor checks loopback and exactly 64 hexadecimal bytes
    // before any connection. No endpoint, token or command is inferred from env.
    let client = Client::new(args.endpoint, token.to_owned())?;
    let value = (|| -> Result<serde_json::Value, Error> {
        Ok(match args.command {
            Command::Status => client.status_json()?,
            Command::Object { root } => serde_json::to_value(client.object_status(root)?)?,
            Command::Pin { root } => serde_json::to_value(client.set_pin(root, true)?)?,
            Command::Unpin { root } => serde_json::to_value(client.set_pin(root, false)?)?,
            Command::Prune => serde_json::to_value(client.prune_cache()?)?,
            Command::OverlayOmissions => serde_json::to_value(client.overlay_omissions()?)?,
            Command::OverlayBook => serde_json::to_value(client.overlay_book()?)?,
            Command::NamesStatus { genesis } => {
                serde_json::to_value(client.names_status(genesis)?)?
            }
            Command::NamesRegister {
                genesis,
                height,
                hash,
            } => {
                serde_json::to_value(client.register_names(genesis, ChainPoint { height, hash })?)?
            }
            Command::NamesStep { genesis } => serde_json::to_value(client.names_step(genesis)?)?,
            Command::NamesResolve { genesis, name } => {
                serde_json::to_value(client.names_resolve(genesis, &name)?)?
            }
        })
    })()
    // JSON type errors can quote remote string values. Do not echo a token
    // even if a malformed response reflects the Authorization value back.
    .map_err(|error| io::Error::other(error.to_string().replace(token, "[redacted]")))?;
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("urma-node-control: {error}");
            ExitCode::FAILURE
        }
    }
}
