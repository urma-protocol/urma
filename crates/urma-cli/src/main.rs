#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
mod archive_cli;
mod key_cli;
mod litecoin_cli;
mod public_cli;
mod scaffold;
use clap::{Parser, Subcommand};
use serde_json::Value;
use urma::error::Error;

#[derive(Parser)]
#[command(
    version,
    about = "URMA reusable libraries and application tools; unfinished commands report unsupported"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Git {
        #[command(subcommand)]
        command: scaffold::GitCommand,
    },
    Wire {
        #[command(subcommand)]
        command: public_cli::PublicCommand,
    },
    Archive {
        #[command(subcommand)]
        command: archive_cli::Command,
    },
    Capture {
        #[command(subcommand)]
        command: scaffold::CaptureCommand,
    },
    Key {
        #[command(subcommand)]
        command: key_cli::KeyCommand,
    },
    Wallet {
        #[command(subcommand)]
        command: scaffold::WalletCommand,
    },
}

pub(crate) fn print_json(value: Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::Archive { command } => archive_cli::run(command),
        Command::Wire { command } => print_json(public_cli::run(command)?),
        Command::Git { command } => scaffold::git(command),
        Command::Capture { command } => scaffold::capture(command),
        Command::Wallet { command } => print_json(scaffold::wallet(command)?),
        Command::Key { command } => {
            let report = key_cli::run(command)?;
            if report != Value::Null {
                print_json(report)?;
            }
            Ok(())
        }
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
