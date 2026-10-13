use crate::{
    approve_publication,
    key_cli::{VaultAccess, account_path},
    node_cli::{NodeArgs, chain_name},
};
use clap::Subcommand;
use serde_json::{Value, json};
use std::num::NonZeroU64;
use urma_identity::root::Branch;
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
    #[command(about = "Show your designated receiving address (offline)")]
    Address {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "Export the account xpub and output descriptors (offline, no secrets)")]
    Export {
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
            let chain = node.chain()?;
            let root = vault.keyring().root();
            Ok(
                json!({"chain":chain_name(chain)?,"path":format!("{}/0/0", account_path(chain)),
                "designated_address":root.address(chain, Branch::External, 0)?,
                "balance_checked":false}),
            )
        }
        WalletCommand::Export { access, node } => {
            let vault = access.open()?;
            let chain = node.chain()?;
            let root = vault.keyring().root();
            let [external, internal] = root.descriptors(chain)?;
            Ok(
                json!({"chain":chain_name(chain)?,"path":account_path(chain),
                "fingerprint":root.fingerprint().to_string(),
                "account_xpub":root.account_xpub(chain)?.to_string(),
                "descriptors":{"external":external,"internal":internal},"secrets":false}),
            )
        }
        WalletCommand::Status { access, node } | WalletCommand::Utxos { access, node } => {
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            let runtime = node.connect()?;
            let spendable = runtime.spendable(&signer)?;
            let balance = spendable.outputs.iter().try_fold(0u64, |total, coin| {
                total
                    .checked_add(coin.value)
                    .ok_or_else(|| Error::Capacity("balance overflow".into()))
            })?;
            let verification = match spendable.verified {
                true => "each output checked live against the source",
                false => {
                    "reported unspents only; the set exceeds the per-output verification bound"
                }
            };
            Ok(
                json!({"author":signer.author().0.to_string(), "chain":node.chain()?, "receive_address":urma_wallet::address::receive_address(&signer, node.chain()?)?, "utxos":spendable.outputs, "spendable_confirmed_balance":balance, "reported_outputs":spendable.reported, "outputs_verified":spendable.verified, "verification":verification, "chain_evidence":runtime.inclusion_evidence(), "providers":runtime.provider_labels(), "network_verified":true, "broadcast":false}),
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
