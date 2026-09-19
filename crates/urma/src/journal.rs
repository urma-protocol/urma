use crate::config::{BITCOIN_MAX_FEE_RATE, BITCOIN_MAX_FEE_SATS, BITCOIN_RETURN_SATS, Limits};
use crate::error::{Context, Error, ensure};
use crate::format::Urma;
use crate::transport::supported_network;
use crate::{container, envelope};
use bitcoin::{
    Address, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Witness, absolute,
    consensus::deserialize,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, str::FromStr};
pub use urma_wallet::funding::Funding;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u8,
    pub network: String,
    pub object_id: String,
    pub start_height: u64,
    pub input_bytes: usize,
    pub fee_sats: u64,
    pub commit_fee_sats: u64,
    pub reveal_fee_sats: u64,
    pub fee_rate_sat_vb: u64,
    pub funding: Funding,
    pub commit: String,
    pub reveals: Vec<String>,
    pub mining_address: String,
}

pub(crate) fn decode_transaction(raw: &str) -> Result<Transaction, Error> {
    ensure!(raw.len() <= 8_000_000, "raw transaction exceeds byte limit");
    deserialize(&hex::decode(raw)?).context("decode transaction")
}

fn validate_shape(tx: &Transaction) -> Result<(), Error> {
    ensure!(
        tx.version == Version::TWO && tx.lock_time == absolute::LockTime::ZERO,
        "unexpected transaction version or locktime"
    );
    ensure!(
        tx.input.len() == 1
            && tx.input[0].script_sig.is_empty()
            && tx.input[0].sequence == Sequence::ENABLE_RBF_NO_LOCKTIME,
        "unexpected transaction input structure"
    );
    ensure!(
        tx.weight().to_wu() <= 400_000,
        "transaction exceeds standard weight"
    );
    Ok(())
}

pub fn validate_plan(plan: &Plan) -> Result<Value, Error> {
    let network = supported_network(&plan.network)?;
    let payout = Address::from_str(&plan.mining_address)?.require_network(network)?;
    ensure!(
        payout.script_pubkey().is_p2tr(),
        "journal payout must be Taproot"
    );
    validate_transparent_plan(plan, &payout.script_pubkey(), true)
}

pub(crate) fn validate_transparent_plan(
    plan: &Plan,
    payout: &ScriptBuf,
    require_signed_commit: bool,
) -> Result<Value, Error> {
    validate_metadata(plan)?;
    let (outpoint, previous) = plan.funding.prevout()?;
    let commit = decode_transaction(&plan.commit)?;
    let commit_fee = validate_commit(
        plan,
        payout,
        &commit,
        outpoint,
        &previous,
        require_signed_commit,
    )?;
    let change = commit.output.last().context("commit change missing")?;
    let commit_id = commit.compute_txid();
    let (reveal_fee, reveal_ids, reveal_sizes) = validate_reveals(plan, payout, &commit)?;
    ensure!(
        reveal_fee == plan.reveal_fee_sats
            && commit_fee.checked_add(reveal_fee) == Some(plan.fee_sats),
        "journal total fees differ from signed transactions"
    );
    Ok(
        json!({"status": "valid", "network": plan.network, "object_id": plan.object_id,
        "input_bytes": plan.input_bytes, "start_height": plan.start_height, "total_chunks": plan.reveals.len(),
        "fee_rate_sat_vb": plan.fee_rate_sat_vb, "fee_sats": plan.fee_sats,
        "commit_fee_sats": commit_fee, "reveal_fee_sats": reveal_fee,
        "commit_txid": commit_id.to_string(), "reveal_txids": reveal_ids,
        "commit_vsize": commit.vsize(), "reveal_vsizes": reveal_sizes,
        "funding_txid": outpoint.txid.to_string(), "funding_vout": outpoint.vout,
        "funding_sats": previous.value.to_sat(), "change_sats": change.value.to_sat(),
        "payout_address": plan.mining_address, "chain_status_checked": false}),
    )
}

fn validate_metadata(plan: &Plan) -> Result<(), Error> {
    if plan.input_bytes > Limits::INPUT_BYTES {
        return Err(Error::Capacity("client input capacity exceeded".into()));
    }

    ensure!(
        plan.version == Urma::VERSION,
        "unsupported publication journal"
    );
    ensure!(
        (1..=Limits::RECORDS).contains(&plan.reveals.len()),
        "invalid reveal count"
    );
    ensure!(
        (1..=Limits::INPUT_BYTES).contains(&plan.input_bytes),
        "invalid input length"
    );
    ensure!(
        plan.input_bytes.div_ceil(Urma::CHUNK_BYTES) == plan.reveals.len(),
        "journal input length disagrees with reveal count"
    );
    ensure!(
        (1..=BITCOIN_MAX_FEE_RATE).contains(&plan.fee_rate_sat_vb),
        "invalid journal fee rate"
    );
    ensure!(
        plan.fee_sats <= BITCOIN_MAX_FEE_SATS,
        "journal exceeds client fee cap"
    );
    ensure!(
        hex::decode(&plan.object_id)?.len() == 32,
        "invalid journal object ID"
    );
    Ok(())
}
fn validate_commit(
    plan: &Plan,
    payout: &ScriptBuf,
    commit: &Transaction,
    outpoint: OutPoint,
    previous: &TxOut,
    require_signed_commit: bool,
) -> Result<u64, Error> {
    validate_shape(commit)?;
    ensure!(
        commit.input[0].previous_output == outpoint,
        "commit does not spend supplied funding"
    );
    ensure!(
        commit.output.len() == plan.reveals.len() + 1,
        "commit has unexpected outputs"
    );
    let change = commit.output.last().context("commit change missing")?;
    ensure!(
        change.script_pubkey == *payout && change.value.to_sat() >= BITCOIN_RETURN_SATS,
        "invalid commit change destination or value"
    );
    let output_sats = commit
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))
        .context("commit output sum overflow")?;
    let commit_fee = previous
        .value
        .to_sat()
        .checked_sub(output_sats)
        .context("commit spends more than funding")?;
    ensure!(
        commit_fee == plan.commit_fee_sats,
        "journal commit fee differs from signed transaction"
    );
    let mut worst_case = commit.clone();
    worst_case.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    ensure!(
        commit_fee == u64::try_from(worst_case.vsize())? * plan.fee_rate_sat_vb
            && commit_fee >= u64::try_from(commit.vsize())? * plan.fee_rate_sat_vb,
        "commit fee is inconsistent with selected rate"
    );

    verify_funding_signature(commit, previous, require_signed_commit)?;
    Ok(commit_fee)
}
fn verify_funding_signature(
    commit: &Transaction,
    previous: &TxOut,
    require_signed_commit: bool,
) -> Result<(), Error> {
    let secp = Secp256k1::verification_only();
    if require_signed_commit {
        let funding_witness: Vec<_> = commit.input[0].witness.iter().collect();
        ensure!(
            funding_witness.len() == 2,
            "invalid P2WPKH signature witness"
        );
        let signature = bitcoin::ecdsa::Signature::from_slice(funding_witness[0])?;
        ensure!(
            signature.sighash_type == EcdsaSighashType::All,
            "commit must sign all outputs"
        );
        let public = bitcoin::PublicKey::from_slice(funding_witness[1])?;
        ensure!(
            ScriptBuf::new_p2wpkh(&public.wpubkey_hash()?) == previous.script_pubkey,
            "funding key does not match previous output"
        );
        let sighash = SighashCache::new(commit).p2wpkh_signature_hash(
            0,
            &previous.script_pubkey,
            previous.value,
            EcdsaSighashType::All,
        )?;
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signature.signature,
            &public.inner,
        )
        .context("invalid commit signature")?;
    } else {
        ensure!(
            commit.input[0].witness.is_empty(),
            "draft commit must be unsigned"
        );
    }

    Ok(())
}
fn validate_reveals(
    plan: &Plan,
    payout: &ScriptBuf,
    commit: &Transaction,
) -> Result<(u64, Vec<String>, Vec<usize>), Error> {
    let mut seen = BTreeSet::new();
    let mut seen_chunks = BTreeSet::new();
    let mut discovery_tag = None;
    let mut reveal_fee = 0u64;
    let mut reveal_ids = Vec::new();
    let mut reveal_sizes = Vec::new();
    for raw in &plan.reveals {
        let reveal = decode_transaction(raw)?;
        validate_shape(&reveal)?;
        let source = reveal.input[0].previous_output;
        ensure!(
            source.txid == commit.compute_txid()
                && (usize::try_from(source.vout)?) < plan.reveals.len(),
            "reveal does not spend a commit media output"
        );
        ensure!(
            seen.insert(source.vout),
            "duplicate reveal spends the same commit output"
        );
        ensure!(
            reveal.output.len() == 1
                && reveal.output[0].value.to_sat() == BITCOIN_RETURN_SATS
                && reveal.output[0].script_pubkey == *payout,
            "invalid reveal payout"
        );
        let prevout = &commit.output[usize::try_from(source.vout)?];
        ensure!(
            prevout.script_pubkey.is_p2tr(),
            "commit media output is not Taproot"
        );
        let fee = prevout
            .value
            .to_sat()
            .checked_sub(BITCOIN_RETURN_SATS)
            .context("reveal spends more than commit output")?;
        ensure!(
            fee == u64::try_from(reveal.vsize())? * plan.fee_rate_sat_vb,
            "reveal fee differs from selected rate"
        );
        reveal_fee = reveal_fee
            .checked_add(fee)
            .context("reveal fee sum overflow")?;
        let record = envelope::verify_reveal(&reveal, commit)?.record;
        let header = container::inspect_header(&record)?;
        ensure!(
            header.id.as_slice() == hex::decode(&plan.object_id)?
                && usize::try_from(header.count)? == plan.reveals.len(),
            "reveal metadata differs from journal"
        );
        ensure!(seen_chunks.insert(header.index), "duplicate record index");
        let tag = header.discovery_tag;
        for previous_tag in discovery_tag.iter() {
            ensure!(*previous_tag == tag, "inconsistent discovery tags");
        }
        discovery_tag = Some(tag);
        reveal_ids.push(reveal.compute_txid().to_string());
        reveal_sizes.push(reveal.vsize());
    }
    Ok((reveal_fee, reveal_ids, reveal_sizes))
}
