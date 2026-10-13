use crate::config;
use crate::error::{Context, Error, bail, ensure};
use crate::node::Node;
use crate::publish::{MempoolCheck, test_accept};
use crate::transaction::{signed_vsize, spending};
use crate::wallet::Selection;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, consensus::serialize};
use serde_json::json;
use std::num::NonZeroU64;
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    wallet::{FeeBudget, FeeRate, SpendRequest},
};

pub struct TransferRequest {
    pub destination: ScriptBuf,
    pub amount: u64,
    pub rate: NonZeroU64,
    pub max_fee: u64,
}

pub struct Change {
    pub value: u64,
    pub path: KeyPath,
}

pub struct Transfer {
    pub transaction: Transaction,
    pub fee: u64,
    pub change: Option<Change>,
}

fn output(value: u64, script: &ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script.clone(),
    }
}

fn quote(
    request: &TransferRequest,
    inputs: usize,
    change: Option<&ScriptBuf>,
) -> Result<u64, Error> {
    let mut draft = spending(
        &vec![OutPoint::null(); inputs],
        output(request.amount, &request.destination),
    );
    for script in change.iter() {
        draft.output.push(output(0, script));
    }
    signed_vsize(&draft)?
        .checked_mul(request.rate.get())
        .context("transfer fee overflow")
}

fn settle(
    request: &TransferRequest,
    account: &Account,
    selection: &Selection,
    retained: u64,
) -> Result<(u64, Option<Change>), Error> {
    let inputs = selection.inputs.len();
    let rest = selection
        .total
        .checked_sub(request.amount)
        .context("insufficient funding")?;
    let path = KeyPath::new(Branch::Internal, selection.next_change);
    let fee = quote(request, inputs, Some(&account.script(path)?))?;
    if rest >= fee.checked_add(retained).context("transfer fee overflow")? {
        let value = rest - fee;
        return Ok((fee, Some(Change { value, path })));
    }
    ensure!(
        rest >= quote(request, inputs, None)?,
        "insufficient funding"
    );
    Ok((rest, None))
}

pub fn prepare(
    node: &Node,
    account: &Account,
    request: &TransferRequest,
) -> Result<Transfer, Error> {
    let retained = config::publication_return(node.chain());
    ensure!(
        request.amount >= retained,
        "amount below the dust-safe minimum of {retained} base units"
    );
    ensure!(
        !request.destination.is_op_return(),
        "destination cannot be a data output"
    );
    let single = quote(request, 1, None)?;
    let per_input = quote(request, 2, None)?
        .checked_sub(single)
        .context("transfer fee underflow")?;
    let minimum = request
        .amount
        .checked_add(single)
        .context("transfer amount overflow")?;
    let selection = node.select_coins(account, minimum, per_input)?;
    let (fee, change) = settle(request, account, &selection, retained)?;
    ensure!(
        fee <= request.max_fee,
        "transfer fee {fee} exceeds the approved maximum {}",
        request.max_fee
    );
    let mut outpoints = Vec::new();
    let mut prevouts = Vec::new();
    let mut paths = Vec::new();
    for input in &selection.inputs {
        let (outpoint, previous) = input.funding.prevout()?;
        outpoints.push(outpoint);
        prevouts.push(previous);
        paths.push(input.path);
    }
    let mut unsigned = spending(&outpoints, output(request.amount, &request.destination));
    for change in change.iter() {
        unsigned
            .output
            .push(output(change.value, &account.script(change.path)?));
    }
    let signed = account.sign(
        &SpendRequest {
            transaction: &unsigned,
            prevouts: &prevouts,
            budget: FeeBudget {
                chain: node.chain().genesis()?,
                rate: FeeRate(request.rate),
                maximum_base_units: request.max_fee,
            },
        },
        &paths,
    )?;
    Ok(Transfer {
        transaction: signed,
        fee,
        change,
    })
}

pub fn submit(node: &Node, transfer: &Transfer) -> Result<Txid, Error> {
    let raw = hex::encode(serialize(&transfer.transaction));
    match test_accept(node, &raw)? {
        MempoolCheck::Allowed => {}
        MempoolCheck::Rejected(reason) => {
            bail!("node policy rejected the transfer: {reason}; nothing was broadcast")
        }
        MempoolCheck::Unavailable(reason) => {
            tracing::warn!(%reason, "transfer broadcast without mempool preflight");
        }
    }
    let txid = transfer.transaction.compute_txid();
    let answer = node.call("sendrawtransaction", &[json!(raw)])?;
    ensure!(
        answer == json!(txid),
        "broadcast returned an unexpected TXID"
    );
    Ok(txid)
}
