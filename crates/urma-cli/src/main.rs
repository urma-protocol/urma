#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
mod archive_cli;
mod capture_cli;
mod config;
mod files_cli;
mod git_cli;
mod git_publish_cli;
mod key_cli;
mod litecoin_cli;
mod node_cli;
mod public_cli;
mod wallet_cli;
mod wire_live_cli;
use clap::{Parser, Subcommand};
use serde_json::Value;
use urma::error::Error;

#[derive(Parser)]
#[command(
    name = "urma",
    version,
    about = "Publish, recover and use URMA content",
    after_help = "Litecoin mainnet by default. Add --testnet for Litecoin testnet.\n\nStart here:\n  urma git clone <TXID>\n  urma git clone <TXID> --testnet\n  urma wallet address\n\nNo node options needed. Advanced configuration: see CLI.md."
)]
struct Cli {
    #[arg(short = 'v', global = true, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3), help = "Verbosity: 1 summary details, 2 plan details, 3 transaction diagnostics")]
    verbosity: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Publish and clone committed Git snapshots")]
    Git {
        #[command(subcommand)]
        command: git_cli::GitCommand,
    },
    #[command(about = "Publish public text and read your local feed")]
    Wire {
        #[command(subcommand)]
        command: public_cli::PublicCommand,
    },
    #[command(about = "Encrypt and recover files, directories and collections")]
    Archive {
        #[command(subcommand)]
        command: files_cli::Command,
    },
    #[command(about = "Preserve captured originals and their context")]
    Capture {
        #[command(subcommand)]
        command: capture_cli::Command,
    },
    #[command(about = "Manage your identities and recovery backups")]
    Key {
        #[command(subcommand)]
        command: key_cli::KeyCommand,
    },
    #[command(about = "Show your address, funds and fee estimates")]
    Wallet {
        #[command(subcommand)]
        command: wallet_cli::WalletCommand,
    },
    #[command(about = "Low-level protocol tools for developers")]
    Expert {
        #[command(subcommand)]
        command: archive_cli::Command,
    },
}

pub(crate) fn progress(message: String) {
    eprintln!("{message}");
}

pub(crate) fn print_report(value: Value) -> Result<(), Error> {
    if value.is_null() {
        return Ok(());
    }
    match config::output()? {
        config::Output::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        config::Output::Human => render_report("", &value, 0),
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    config::set_verbosity(cli.verbosity);
    match cli.command {
        Command::Archive { command } => print_report(files_cli::run(command)?),
        Command::Expert { command } => archive_cli::run(command),
        Command::Wire { command } => print_report(public_cli::run(command)?),
        Command::Git { command } => print_report(git_cli::run(command)?),
        Command::Capture { command } => print_report(capture_cli::run(command)?),
        Command::Wallet { command } => print_report(wallet_cli::run(command)?),
        Command::Key { command } => {
            let report = key_cli::run(command)?;
            if report != Value::Null {
                print_report(report)?;
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

fn render_report(label: &str, value: &Value, depth: usize) {
    let indent = "  ".repeat(depth);
    let label = label.replace('_', " ");
    match value {
        Value::Null => {}
        Value::Object(fields) => {
            if !label.is_empty() {
                println!("{indent}{label}:");
            }
            for (key, value) in fields {
                if matches!(key.as_str(), "commit" | "reveal" | "record_hex") && value.is_string() {
                    println!(
                        "{indent}  {}: retained in plan/proof files",
                        key.replace('_', " ")
                    );
                } else {
                    render_report(key, value, depth + usize::from(!label.is_empty()));
                }
            }
        }
        Value::Array(items) => {
            println!("{indent}{label}: {} entries", items.len());
            if items.len() <= 10 && depth < 3 {
                for (index, item) in items.iter().enumerate() {
                    render_report(&format!("{}", index + 1), item, depth + 1);
                }
            }
        }
        Value::String(text) => println!("{indent}{label}: {}", terminal_text(text)),
        Value::Bool(value) => println!("{indent}{label}: {}", if *value { "yes" } else { "no" }),
        Value::Number(number) => println!("{indent}{label}: {number}"),
    }
}

fn terminal_text(text: &str) -> String {
    let mut safe = String::new();
    for character in text.chars() {
        safe.extend(character.escape_debug());
    }
    safe
}

pub(crate) fn approve_publication(label: &str, id: &str, fee: u64, yes: bool) -> Result<(), Error> {
    use std::io::{IsTerminal, Write};
    eprintln!("{label}\nPlan: {id}\nTotal fee: {fee} base units.");
    if yes {
        return Ok(());
    }
    urma::error::ensure!(
        std::io::stdin().is_terminal(),
        "publication needs approval; review the plan, then run this command with --yes"
    );
    eprint!("Publish this exact plan? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    urma::error::ensure!(
        matches!(answer.trim(), "y" | "Y" | "yes"),
        "publication cancelled; nothing submitted"
    );
    Ok(())
}

pub(crate) fn detail(level: u8, message: String) {
    if config::verbosity() >= level {
        eprintln!("{message}");
    }
}
