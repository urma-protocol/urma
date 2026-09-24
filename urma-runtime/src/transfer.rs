use crate::config;
use crate::error::{Context, Error, bail, ensure};
use crate::node::Node;
use crate::publish::{MempoolCheck, test_accept};
use crate::transaction::transaction;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness, consensus::serialize};
use serde_json::json;
use std::num::NonZeroU64;
use urma_identity::identity::IdentitySigner;
use urma_wallet::wallet::{FeeBudget, FeeRate, SpendRequest};

pub struct TransferRequest {
    pub destination: ScriptBuf,
    pub amount: u64,
    pub rate: NonZeroU64,
    pub max_fee: u64,
}

pub struct Transfer {
    pub transaction: Transaction,
    pub fee: u64,
    pub change: u64,
}

fn output(value: u64, script: &ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script.clone(),
    }
}

fn quote(request: &TransferRequest, own: &ScriptBuf, retained: u64) -> Result<u64, Error> {
    let mut draft = transaction(OutPoint::null(), output(request.amount, &request.destination));
    draft.output.push(output(retained, own));
    draft.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    let fee = u64::try_from(draft.vsize())?
        .checked_mul(request.rate.get())
        .context("transfer fee overflow")?;
    ensure!(
        fee <= request.max_fee,
        "transfer fee {fee} exceeds the approved maximum {}",
        request.max_fee
    );
    Ok(fee)
}

pub fn prepare(
    node: &Node,
    signer: &impl IdentitySigner,
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
    let own = urma_wallet::signing::script(signer)?;
    let fee = quote(request, &own, retained)?;
    let spent = request
        .amount
        .checked_add(fee)
        .context("transfer amount overflow")?;
    let minimum = spent.checked_add(retained).context("transfer amount overflow")?;
    let funding = node.select_funding(signer, minimum)?;
    let (outpoint, previous) = funding.prevout()?;
    let change = previous
        .value
        .to_sat()
        .checked_sub(spent)
        .context("insufficient funding")?;
    let mut unsigned = transaction(outpoint, output(request.amount, &request.destination));
    unsigned.output.push(output(change, &own));
    let signed = urma_wallet::signing::sign(
        signer,
        &SpendRequest {
            transaction: &unsigned,
            prevouts: std::slice::from_ref(&previous),
            budget: FeeBudget {
                chain: node.chain().genesis()?,
                rate: FeeRate(request.rate),
                maximum_base_units: request.max_fee,
            },
        },
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
