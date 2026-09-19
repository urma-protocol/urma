use crate::{key_cli::VaultAccess, node_cli::NodeArgs, public_cli::PublicChain};
use bitcoin::BlockHash;
use clap::Subcommand;
use serde_json::{Value, json};
use std::num::NonZeroU64;
use urma::error::Error;
use urma_chain::observation::ChainId;
use urma_wallet::wallet::{FeeBudget, FeeRate};

#[derive(Subcommand)]
pub(crate) enum WalletCommand {
    Status {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    Utxos {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
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

pub(crate) fn run(command: WalletCommand) -> Result<Value, Error> {
    match command {
        WalletCommand::Address { access, chain } => {
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            Ok(
                json!({"author":signer.author().0.to_string(), "receive_address":urma_wallet::address::receive_address(&signer, chain.into())?, "balance_checked":false}),
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
                json!({"author":signer.author().0.to_string(), "chain":urma_chain::observation::Chain::from(node.chain), "receive_address":urma_wallet::address::receive_address(&signer, node.chain.into())?, "utxos":utxos, "spendable_confirmed_balance":spendable, "network_verified":true, "broadcast":false}),
            )
        }
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
