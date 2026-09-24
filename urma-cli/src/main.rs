#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
mod archive_cli;
mod capture_cli;
mod common_cli;
mod config;
mod files_cli;
mod funding_cli;
mod git_cli;
mod git_follow_cli;
mod git_progress;
mod git_publish_cli;
mod git_terminal;
mod key_cli;
mod litecoin_cli;
mod logging;
mod names_approval;
mod names_cli;
mod names_flow;
mod node_cli;
mod public_cli;
mod wallet_cli;
mod web_cli;
mod wire_live_cli;
use clap::{Parser, Subcommand};
use serde_json::Value;
use urma_runtime::error::Error;

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
    #[command(about = "Register, approve and resolve names in URMANAM1 registries")]
    Names {
        #[command(subcommand)]
        command: names_cli::NamesCommand,
    },
    #[command(about = "Pack, publish and fetch URMAWEB1 site publications")]
    Web {
        #[command(subcommand)]
        command: web_cli::WebCommand,
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
    tracing::info!(target: "urma_cli", message = ?console::strip_ansi_codes(&message));
    git_terminal::suspend(|| eprintln!("{message}"));
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
    let log = logging::install(cli.verbosity, || git_terminal::LogWriter(std::io::stderr()))?;
    progress(format!("Log: {}", log.display()));
    let started = std::time::Instant::now();
    tracing::info!(target: "urma_cli", command = command_name(&cli.command), version = env!("CARGO_PKG_VERSION"), "Command started");
    let result = execute(cli.command);
    match result {
        Ok(()) => {
            tracing::info!(target: "urma_cli", elapsed_seconds = started.elapsed().as_secs_f64(), "Command completed");
            Ok(())
        }
        Err(error) => {
            tracing::error!(target: "urma_cli", %error, elapsed_seconds = started.elapsed().as_secs_f64(), "Command failed");
            Err(error)
        }
    }
}

fn command_name(command: &Command) -> &'static str {
    use git_cli::GitCommand;
    match command {
        Command::Git { command } => match command {
            GitCommand::Prepare(_) => "git prepare",
            GitCommand::Publish(_) => "git publish",
            GitCommand::Resume(_) => "git resume",
            GitCommand::Watch(_) => "git watch",
            GitCommand::Clone { .. } => "git clone",
            GitCommand::Recover(_) => "git recover",
            GitCommand::Verify { .. } => "git verify",
            GitCommand::Inspect { .. } => "git inspect",
            GitCommand::Review { .. } => "git review",
        },
        Command::Archive { .. } => "archive",
        Command::Capture { .. } => "capture",
        Command::Expert { .. } => "expert",
        Command::Wire { .. } => "wire",
        Command::Names { .. } => "names",
        Command::Web { .. } => "web",
        Command::Wallet { .. } => "wallet",
        Command::Key { .. } => "key",
    }
}

fn execute(command: Command) -> Result<(), Error> {
    match command {
        Command::Archive { command } => print_report(files_cli::run(command)?),
        Command::Expert { command } => archive_cli::run(command),
        Command::Wire { command } => print_report(public_cli::run(command)?),
        Command::Names { command } => print_report(names_cli::run(command)?),
        Command::Web { command } => print_report(web_cli::run(command)?),
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
            if is_terminal() {
                eprintln!("{}: {error}", console::style("error").red().bold());
            } else {
                eprintln!("error: {error}");
            }
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

pub(crate) fn is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
        && !std::env::var_os("URMA_OUTPUT")
            .iter()
            .any(|value| value == "json")
}

pub(crate) fn approve_publication(label: &str, id: &str, fee: u64, yes: bool) -> Result<(), Error> {
    use std::io::{IsTerminal, Write};
    if is_terminal() {
        eprintln!(
            "{}\n  {}: {}\n  {}: {}",
            console::style(label).bold(),
            console::style("Plan").dim(),
            console::style(id).cyan(),
            console::style("Total fee").dim(),
            console::style(format!("{fee} base units")).yellow().bold()
        );
    } else {
        eprintln!("{label}\nPlan: {id}\nTotal fee: {fee} base units.");
    }
    if yes {
        return Ok(());
    }
    urma_runtime::error::ensure!(
        std::io::stdin().is_terminal(),
        "publication needs approval; review the plan, then run this command with --yes"
    );
    let confirmed = if is_terminal() {
        git_terminal::confirm(&dialoguer::console::Term::stderr())
            .map_err(|error| Error::Io(std::io::Error::other(error)))?
    } else {
        eprint!("Publish this exact plan? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        git_terminal::accepted(&answer)
    };
    urma_runtime::error::ensure!(confirmed, "publication cancelled; nothing submitted");
    Ok(())
}

pub(crate) fn detail(level: u8, message: String) {
    tracing::debug!(target: "urma_cli", message = ?console::strip_ansi_codes(&message));
    if config::verbosity() >= level {
        eprintln!("{message}");
    }
}

pub(crate) fn stage<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    tracing::info!(target: "urma_cli", stage = label, "Stage started");
    let result = stage_inner(label, operation);
    tracing::info!(target: "urma_stage", "{}: {:.2}s (finished)", label.trim_end_matches('.'), started.elapsed().as_secs_f64());
    result
}

fn stage_inner<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    if is_terminal() && config::verbosity() == 0 {
        let spinner = git_terminal::Stage::new(label);
        let result = operation();
        tracing::debug!(target: "urma_cli", "{}", spinner.finish(label));
        result
    } else {
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };
        progress(label.to_owned());
        let started = Instant::now();
        let (sender, receiver) = mpsc::channel::<()>();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                loop {
                    match receiver.recv_timeout(Duration::from_secs(10)) {
                        Ok(()) => break,
                        Err(cause @ mpsc::RecvTimeoutError::Disconnected) => {
                            tracing::warn!(reason = %cause, "Progress stage finished");
                            break;
                        }
                        Err(cause @ mpsc::RecvTimeoutError::Timeout) => {
                            tracing::warn!(target: "urma_timer", reason = %cause, "Progress timer tick");
                            progress(format!("{label} ({}s elapsed)", started.elapsed().as_secs()));
                        }
                    }
                }
            });
            let result = operation();
            match sender.send(()) {
                Ok(()) => (),
                Err(cause) => {
                    tracing::warn!(%cause, "progress timer stopped before stage completion")
                }
            }
            result
        })
    }
}
