use crate::{approve_publication, key_cli::VaultAccess, node_cli::NodeArgs};
use clap::Subcommand;
use serde_json::{Value, json};
use std::num::NonZeroU64;
use urma_runtime::{
    error::Error,
    transfer::{self, TransferRequest},
};
use urma_wallet::wallet::{FeeBudget, FeeRate};

fn send(
    access: &VaultAccess,
    node: &NodeArgs,
    to: &str,
    request: TransferRequest,
    yes: bool,
) -> Result<Value, Error> {
    let vault = access.open()?;
    let signer = vault.keyring().active()?;
    let runtime = node.connect()?;
    let prepared = transfer::prepare(&runtime, &signer, &request)?;
    let txid = prepared.transaction.compute_txid();
    approve_publication(
        &format!("Send {} base units to {to}", request.amount),
        &txid.to_string(),
        prepared.fee,
        yes,
    )?;
    let sent = transfer::submit(&runtime, &prepared)?;
    Ok(json!({
        "status": "broadcast",
        "txid": sent.to_string(),
        "to": to,
        "amount": request.amount,
        "fee": prepared.fee,
        "change": prepared.change,
        "chain": node.chain()?,
    }))
}

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
    #[command(about = "Send funds from your active identity to an address")]
    Send {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
        #[arg(long, help = "Destination address on the selected network")]
        to: String,
        #[arg(long, help = "Amount in base units (litoshis on Litecoin)")]
        amount: u64,
        #[arg(long, default_value = "1")]
        rate: NonZeroU64,
        #[arg(long, default_value_t = 10_000)]
        max_fee: u64,
        #[arg(short, long, help = "Approve the displayed transfer and fee")]
        yes: bool,
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
        WalletCommand::Send {
            access,
            node,
            to,
            amount,
            rate,
            max_fee,
            yes,
        } => send(
            &access,
            &node,
            &to,
            TransferRequest {
                destination: urma_wallet::address::destination_script(&to, node.chain()?)?,
                amount,
                rate,
                max_fee,
            },
            yes,
        ),
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
