use crate::config;
use crate::error::{Context, Error, ensure};
use crate::reveal;
use crate::transaction::{decode, signed_vsize, spending, transaction};
use crate::wallet::FundingInput;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, consensus::serialize};
use serde::{Deserialize, Serialize};
use urma_chain::observation::Chain;
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::MultipartRecord,
};
use urma_identity::identity::IdentitySigner;
use urma_wallet::{
    account::{Account, KeyPath},
    funding::Funding,
    wallet::{FeeBudget, SpendRequest, WalletError},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPlan {
    pub version: u8,
    pub chain: Chain,
    pub funding: Vec<Funding>,
    pub commit: String,
    pub reveal: String,
    pub fee_rate: u64,
}

pub fn prepare(
    record: &PublicRecord,
    author: &impl IdentitySigner,
    funding: Vec<Funding>,
    return_script: &ScriptBuf,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    prepare_bytes(
        &record.encode()?,
        author,
        funding,
        return_script,
        chain,
        fee_rate,
    )
}

pub fn prepare_multipart(
    record: &MultipartRecord,
    author: &impl IdentitySigner,
    funding: Vec<Funding>,
    return_script: &ScriptBuf,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    prepare_bytes(
        &record.encode()?,
        author,
        funding,
        return_script,
        chain,
        fee_rate,
    )
}

pub(crate) fn prevouts(funding: &[Funding]) -> Result<(Vec<OutPoint>, Vec<TxOut>, u64), Error> {
    let mut outpoints = Vec::new();
    let mut outputs = Vec::new();
    let mut total = 0u64;
    for source in funding {
        let (outpoint, previous) = source.prevout()?;
        total = total
            .checked_add(previous.value.to_sat())
            .context("funding sum overflow")?;
        outpoints.push(outpoint);
        outputs.push(previous);
    }
    Ok((outpoints, outputs, total))
}

pub fn prepare_bytes(
    record: &[u8],
    author: &impl IdentitySigner,
    funding: Vec<Funding>,
    return_script: &ScriptBuf,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    ensure!(
        (1..=100).contains(&fee_rate),
        "client fee rate must be 1..100 base units/vB"
    );
    ensure!(
        (1..=config::WALLET_MAX_INPUTS).contains(&funding.len()),
        "publication funding needs 1..{} inputs",
        config::WALLET_MAX_INPUTS
    );
    ensure!(
        return_script.is_p2wpkh(),
        "publication return requires native P2WPKH"
    );
    let (outpoints, _, available) = prevouts(&funding)?;
    let (script, info) =
        envelope::build_for_author(record, author.public_key().inner.x_only_public_key().0)?;
    let retained = config::publication_return(chain);
    let return_output = TxOut {
        value: Amount::from_sat(retained),
        script_pubkey: return_script.clone(),
    };
    let mut reveal = reveal::preview(return_output.clone(), &script, &info)?;
    let reveal_fee = reveal::fee(&reveal, fee_rate)?;
    let publication_output = TxOut {
        value: Amount::from_sat(retained + reveal_fee),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
    };
    let mut commit = spending(&outpoints, publication_output.clone());
    commit.output.push(return_output);
    let commit_fee = signed_vsize(&commit)?
        .checked_mul(fee_rate)
        .context("fee overflow")?;
    let total_fee = commit_fee.checked_add(reveal_fee).context("fee overflow")?;
    ensure!(
        total_fee <= 500_000,
        "client publication fee capacity exceeded"
    );
    let change = available
        .checked_sub(total_fee + retained)
        .context("insufficient funding")?;
    ensure!(change >= retained, "funding must leave native change");
    commit.output[1].value = Amount::from_sat(change);
    reveal.input[0].previous_output = OutPoint {
        txid: commit.compute_txid(),
        vout: 0,
    };
    let signature = author.sign_author(reveal::digest(&reveal, &publication_output, &script)?)?;
    reveal.input[0].witness = envelope::witness(signature.as_ref(), &script, &info)?;
    envelope::verify_reveal(&reveal, &commit)?;
    Ok(PublicPlan {
        version: Urma::VERSION,
        chain,
        funding,
        commit: hex::encode(serialize(&commit)),
        reveal: hex::encode(serialize(&reveal)),
        fee_rate,
    })
}

pub fn quote_record(
    record: &[u8],
    author: bitcoin::XOnlyPublicKey,
    return_script: &ScriptBuf,
    fee_rate: u64,
) -> Result<u64, Error> {
    ensure!((1..=100).contains(&fee_rate), "invalid fee rate");
    ensure!(return_script.is_p2wpkh(), "funding requires native P2WPKH");
    let (script, info) = envelope::build_for_author(record, author)?;
    let output = TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: return_script.clone(),
    };
    let reveal = reveal::preview(output.clone(), &script, &info)?;
    let mut commit = transaction(
        OutPoint::null(),
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        },
    );
    commit.output.push(output);
    signed_vsize(&commit)?
        .checked_add(u64::try_from(reveal.vsize())?)
        .and_then(|bytes| bytes.checked_mul(fee_rate))
        .context("quote fee overflow")
}

pub struct SignedPublicPair {
    pub plan: PublicPlan,
    pub fee: u64,
}

pub fn prepare_signed_bytes(
    record: &[u8],
    author: &impl IdentitySigner,
    funder: &Account,
    inputs: &[FundingInput],
    budget: FeeBudget,
) -> Result<SignedPublicPair, Error> {
    let chain = funder.chain();
    ensure!(
        budget.chain == chain.genesis()?,
        "funding budget chain mismatch"
    );
    let funding: Vec<Funding> = inputs.iter().map(|input| input.funding.clone()).collect();
    let paths: Vec<KeyPath> = inputs.iter().map(|input| input.path).collect();
    let (_, previous, available) = prevouts(&funding)?;
    let mut plan = prepare_bytes(
        record,
        author,
        funding,
        &funder.receive_script()?,
        chain,
        budget.rate.0.get(),
    )?;
    let commit = decode(
        &plan.commit,
        usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
    )?;
    let signed = funder.sign(
        &SpendRequest {
            transaction: &commit,
            prevouts: &previous,
            budget,
        },
        &paths,
    )?;
    let reveal = decode(
        &plan.reveal,
        usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
    )?;
    let outputs = signed.output[1]
        .value
        .to_sat()
        .checked_add(reveal.output[0].value.to_sat())
        .ok_or(WalletError::Overflow)?;
    let fee = available
        .checked_sub(outputs)
        .ok_or(WalletError::InsufficientFunds)?;
    if fee > budget.maximum_base_units {
        return Err(WalletError::BudgetExceeded.into());
    }
    plan.commit = hex::encode(serialize(&signed));
    Ok(SignedPublicPair { plan, fee })
}
