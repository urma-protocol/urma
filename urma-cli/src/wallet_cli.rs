use crate::{key_cli::VaultAccess, node_cli::NodeArgs};
use clap::Subcommand;
use serde_json::{Value, json};
use std::num::NonZeroU64;
use urma_runtime::error::Error;
use urma_wallet::wallet::{FeeBudget, FeeRate};

#[derive(Subcommand)]
pub(crate) enum WalletCommand {
    #[command(about = "Show your receiving address and confirmed spendable balance")]
    Status {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "List confirmed spendable outputs for your active identity")]
    Utxos {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "Show your receiving address (offline)")]
    Address {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "Estimate a fee from virtual transaction size (offline)")]
    Quote {
        #[command(flatten)]
        node: NodeArgs,
        #[arg(help = "Estimated transaction virtual bytes")]
        vbytes: u64,
        #[arg(long, default_value = "1")]
        rate: NonZeroU64,
        #[arg(long, default_value_t = 100_000)]
        max_fee: u64,
    },
}

pub(crate) fn run(command: WalletCommand) -> Result<Value, Error> {
    match command {
        WalletCommand::Address { access, node } => {
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            Ok(
                json!({"author":signer.author().0.to_string(), "receive_address":urma_wallet::address::receive_address(&signer, node.chain()?)?, "balance_checked":false}),
            )
        }
        WalletCommand::Status { access, node } | WalletCommand::Utxos { access, node } => {
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            let runtime = node.connect()?;
            let utxos = runtime.available_utxos(&signer)?;
            let spendable = utxos.iter().try_fold(0u64, |total, coin| {
                total
                    .checked_add(coin.value)
                    .ok_or_else(|| Error::Capacity("balance overflow".into()))
            })?;
            Ok(
                json!({"author":signer.author().0.to_string(), "chain":node.chain()?, "receive_address":urma_wallet::address::receive_address(&signer, node.chain()?)?, "utxos":utxos, "spendable_confirmed_balance":spendable, "network_verified":true, "broadcast":false}),
            )
        }
        WalletCommand::Quote {
            node,
            vbytes,
            rate,
            max_fee,
        } => {
            let genesis = node.chain()?.genesis()?.0;
            let budget = FeeBudget {
                chain: node.chain()?.genesis()?,
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
