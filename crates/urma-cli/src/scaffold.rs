use crate::{key_cli::VaultAccess, public_cli::PublicChain};
use bitcoin::{BlockHash, Txid};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{num::NonZeroU64, path::PathBuf};
use urma::error::Error;
use urma_chain::observation::ChainId;
use urma_wallet::wallet::{FeeBudget, FeeRate};

#[derive(Subcommand)]
pub(crate) enum GitCommand {
    Inspect { root: Txid },
    Clone { root: Txid, directory: PathBuf },
    Prepare { repository: PathBuf },
    Publish { plan: PathBuf },
    Resume { plan: PathBuf },
}

#[derive(Subcommand)]
pub(crate) enum CaptureCommand {
    Ingest { input: PathBuf },
    Recover { destination: PathBuf },
}

#[derive(Subcommand)]
pub(crate) enum WalletCommand {
    Status,
    Address {
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long, value_enum)]
        chain: PublicChain,
    },
    Quote {
        #[arg(long)]
        genesis: BlockHash,
        #[arg(long)]
        vbytes: u64,
        #[arg(long)]
        rate: NonZeroU64,
        #[arg(long)]
        max_fee: u64,
    },
}

pub(crate) fn unsupported(operation: &str) -> Result<(), Error> {
    Err(Error::Unsupported(format!(
        "urma {operation}: unsupported stub; no operation performed"
    )))
}

pub(crate) fn git(command: GitCommand) -> Result<(), Error> {
    let operation = match command {
        GitCommand::Inspect { .. } => "git inspect",
        GitCommand::Clone { .. } => "git clone",
        GitCommand::Prepare { .. } => "git prepare",
        GitCommand::Publish { .. } => "git publish",
        GitCommand::Resume { .. } => "git resume",
    };
    unsupported(operation)
}
pub(crate) fn capture(command: CaptureCommand) -> Result<(), Error> {
    let operation = match command {
        CaptureCommand::Ingest { .. } => "capture ingest",
        CaptureCommand::Recover { .. } => "capture recover",
    };
    unsupported(operation)
}
pub(crate) fn wallet(command: WalletCommand) -> Result<Value, Error> {
    match command {
        WalletCommand::Address { access, chain } => {
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            Ok(
                json!({"author":signer.author().0.to_string(), "receive_address":urma_wallet::address::receive_address(&signer, chain.into())?, "balance_checked":false}),
            )
        }
        WalletCommand::Status => Err(Error::Unsupported(
            "urma wallet status: unsupported stub; no wallet connected".into(),
        )),
        WalletCommand::Quote {
            genesis,
            vbytes,
            rate,
            max_fee,
        } => {
            let budget = FeeBudget {
                chain: ChainId(genesis),
                rate: FeeRate(rate),
                maximum_base_units: max_fee,
            };
            let fee = budget.quote(vbytes)?;
            Ok(
                json!({"fee_base_units":fee,"genesis":genesis.to_string(),"estimate_only":true,"broadcast":false}),
            )
        }
    }
}
