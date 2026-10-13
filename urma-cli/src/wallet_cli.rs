use crate::{
    approve_publication,
    key_cli::{VaultAccess, account_path, funding_account},
    node_cli::{NodeArgs, chain_name},
};
use clap::Subcommand;
use serde_json::{Value, json};
use std::num::NonZeroU64;
use urma_runtime::{
    config,
    error::{Context, Error},
    transfer::{self, TransferRequest},
    wallet::WalletView,
};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    wallet::{FeeBudget, FeeRate},
};

fn send(
    access: &VaultAccess,
    node: &NodeArgs,
    to: &str,
    request: TransferRequest,
    yes: bool,
) -> Result<Value, Error> {
    let vault = access.open()?;
    let account = funding_account(&vault, node.chain()?)?;
    let runtime = node.connect()?;
    let prepared = transfer::prepare(&runtime, &account, &request)?;
    let txid = prepared.transaction.compute_txid();
    let mut inputs = Vec::new();
    let mut details = Vec::new();
    let mut lines = Vec::new();
    for input in &prepared.inputs {
        let (outpoint, previous) = input.funding.prevout()?;
        let path = format!(
            "{}/{}/{}",
            account_path(account.chain()),
            input.path.branch.index(),
            input.path.index
        );
        let address = account.address(input.path)?;
        let value = previous.value.to_sat();
        lines.push(format!(
            "Input {outpoint}: {value} base units from {path} ({address})"
        ));
        inputs.push(outpoint.to_string());
        details.push(json!({"outpoint":outpoint.to_string(),"value":value,
            "path":path,"address":address}));
    }
    let mut change = Value::Null;
    let mut note = String::from("No change output; the remainder is part of the fee");
    for output in prepared.change.iter() {
        let path = format!("{}/1/{}", account_path(account.chain()), output.path.index);
        let address = account.address(output.path)?;
        note = format!("Change {} base units to {path} ({address})", output.value);
        change = json!({"value":output.value,"path":path,"address":address});
    }
    lines.push(note);
    approve_publication(
        &format!("Send {} base units to {to}", request.amount),
        &txid.to_string(),
        prepared.fee,
        &lines,
        yes,
    )?;
    let sent = transfer::submit(&runtime, &prepared)?;
    Ok(json!({
        "status": "broadcast",
        "txid": sent.to_string(),
        "to": to,
        "amount": request.amount,
        "fee": prepared.fee,
        "inputs": inputs,
        "input_details": details,
        "change": change,
        "chain": chain_name(account.chain())?,
    }))
}

fn balance(view: &WalletView) -> Result<u64, Error> {
    view.coins.iter().try_fold(0u64, |total, coin| {
        total.checked_add(coin.value).context("balance overflow")
    })
}

fn status(account: &Account, node: &NodeArgs, utxos: bool) -> Result<Value, Error> {
    let runtime = node.connect()?;
    let view = runtime.wallet(account)?;
    let mut report = json!({"chain":chain_name(account.chain())?,
        "path":account_path(account.chain()),"designated_address":account.receive_address()?,
        "spendable_confirmed_balance":balance(&view)?,"outputs":view.coins.len(),
        "next_change_index":view.next_change,"reported_outputs":view.reported,
        "outputs_verified":view.verified,"skipped_outputs":view.skipped,
        "verification":format!("the largest {} outputs are checked live against the source; smaller ones are skipped and never spent", config::WALLET_VERIFY_OUTPUTS),
        "discovery":"BIP84 external and internal chains, gap limit 20",
        "chain_evidence":runtime.inclusion_evidence(),"providers":runtime.provider_labels(),
        "network_verified":true,"broadcast":false});
    if utxos {
        let mut rows = Vec::new();
        for coin in &view.coins {
            rows.push(
                json!({"outpoint":coin.outpoint.to_string(),"value":coin.value,
                "height":coin.height,"path":format!("{}/{}/{}", account_path(account.chain()),
                    coin.path.branch.index(), coin.path.index),
                "address":account.address(coin.path)?}),
            );
        }
        report["utxos"] = Value::Array(rows);
    }
    Ok(report)
}

fn next_receive(account: &Account, node: &NodeArgs) -> Result<Value, Error> {
    let view = node.connect()?.wallet(account)?;
    let index = view
        .coins
        .iter()
        .filter(|coin| coin.path.branch == Branch::External)
        .fold(1, |next, coin| next.max(coin.path.index + 1));
    let path = KeyPath::new(Branch::External, index);
    Ok(json!({"chain":chain_name(account.chain())?,
        "path":format!("{}/0/{index}", account_path(account.chain())),
        "address":account.address(path)?,"designated_address":account.receive_address()?,
        "basis":"first external index above every address holding a confirmed unspent coin",
        "network_verified":true,"balance_checked":true}))
}

#[derive(Subcommand)]
pub(crate) enum WalletCommand {
    #[command(about = "Show the account's designated address and confirmed spendable balance")]
    Status {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "List the account's confirmed spendable outputs")]
    Utxos {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "Show your designated receiving address (offline), or --next unused")]
    Address {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
        #[arg(
            long,
            help = "Next external address above every address holding a confirmed coin (network); a spent-out address can be offered again"
        )]
        next: bool,
    },
    #[command(about = "Export the account xpub and output descriptors (offline, no secrets)")]
    Export {
        #[command(flatten)]
        access: VaultAccess,
        #[command(flatten)]
        node: NodeArgs,
    },
    #[command(about = "Send funds from the account to an address")]
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

fn export(access: VaultAccess, node: NodeArgs) -> Result<Value, Error> {
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

fn quote(node: NodeArgs, vbytes: u64, rate: NonZeroU64, max_fee: u64) -> Result<Value, Error> {
    let genesis = node.chain()?.genesis()?;
    let budget = FeeBudget {
        chain: genesis,
        rate: FeeRate(rate),
        maximum_base_units: max_fee,
    };
    let fee = budget.quote(vbytes)?;
    Ok(json!({"fee_base_units":fee,"genesis":genesis.0.to_string(),
        "estimate_only":true,"broadcast":false}))
}

pub(crate) fn run(command: WalletCommand) -> Result<Value, Error> {
    match command {
        WalletCommand::Address { access, node, next } => {
            let account = funding_account(&access.open()?, node.chain()?)?;
            if next {
                return next_receive(&account, &node);
            }
            Ok(json!({"chain":chain_name(account.chain())?,
                "path":format!("{}/0/0", account_path(account.chain())),
                "designated_address":account.receive_address()?,"balance_checked":false}))
        }
        WalletCommand::Export { access, node } => export(access, node),
        WalletCommand::Status { access, node } => status(
            &funding_account(&access.open()?, node.chain()?)?,
            &node,
            false,
        ),
        WalletCommand::Utxos { access, node } => status(
            &funding_account(&access.open()?, node.chain()?)?,
            &node,
            true,
        ),
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
        } => quote(node, vbytes, rate, max_fee),
    }
}
