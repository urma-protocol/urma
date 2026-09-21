use crate::config;
use crate::error::{Context, Error, ensure};
use crate::reveal;
use crate::transaction::{decode, transaction};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Witness, consensus::serialize};
use serde::{Deserialize, Serialize};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::MultipartRecord,
};
use urma_identity::identity::IdentitySigner;

use urma_chain::observation::Chain;
use urma_wallet::{
    funding::Funding,
    wallet::{FeeBudget, SpendRequest, WalletError},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPlan {
    pub version: u8,
    pub chain: Chain,
    pub funding: Funding,
    pub commit: String,
    pub reveal: String,
    pub fee_rate: u64,
}

pub fn prepare(
    record: &PublicRecord,
    author: &impl IdentitySigner,
    funding: Funding,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    prepare_bytes(&record.encode()?, author, funding, chain, fee_rate)
}

pub fn prepare_multipart(
    record: &MultipartRecord,
    author: &impl IdentitySigner,
    funding: Funding,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    prepare_bytes(&record.encode()?, author, funding, chain, fee_rate)
}

pub fn prepare_bytes(
    record: &[u8],
    author: &impl IdentitySigner,
    funding: Funding,
    chain: Chain,
    fee_rate: u64,
) -> Result<PublicPlan, Error> {
    ensure!(
        (1..=100).contains(&fee_rate),
        "client fee rate must be 1..100 base units/vB"
    );
    let (outpoint, previous) = funding.prevout()?;
    let (script, info) =
        envelope::build_for_author(record, author.public_key().inner.x_only_public_key().0)?;
    let retained = config::publication_return(chain);
    let return_output = TxOut {
        value: Amount::from_sat(retained),
        script_pubkey: previous.script_pubkey.clone(),
    };
    let mut reveal = reveal::preview(return_output.clone(), &script, &info)?;
    let reveal_fee = reveal::fee(&reveal, fee_rate)?;
    let publication_output = TxOut {
        value: Amount::from_sat(retained + reveal_fee),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
    };
    let mut commit = transaction(outpoint, publication_output.clone());
    commit.output.push(return_output);
    commit.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    let commit_fee = u64::try_from(commit.vsize())?
        .checked_mul(fee_rate)
        .context("fee overflow")?;
    commit.input[0].witness = Witness::new();
    let total_fee = commit_fee.checked_add(reveal_fee).context("fee overflow")?;
    ensure!(
        total_fee <= 500_000,
        "client publication fee capacity exceeded"
    );
    let change = previous
        .value
        .to_sat()
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
    commit.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    u64::try_from(commit.vsize() + reveal.vsize())?
        .checked_mul(fee_rate)
        .context("quote fee overflow")
}

pub struct SignedPublicPair {
    pub plan: PublicPlan,
    pub fee: u64,
}

pub fn prepare_signed_bytes(
    record: &[u8],
    signer: &impl IdentitySigner,
    funding: Funding,
    chain: Chain,
    budget: FeeBudget,
) -> Result<SignedPublicPair, Error> {
    ensure!(
        budget.chain == chain.genesis()?,
        "funding budget chain mismatch"
    );
    let (_, previous) = funding.prevout()?;
    if previous.script_pubkey != urma_wallet::signing::script(signer)? {
        return Err(WalletError::WrongIdentity.into());
    }
    let mut plan = prepare_bytes(record, signer, funding, chain, budget.rate.0.get())?;
    let commit = decode(
        &plan.commit,
        usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
    )?;
    let signed = urma_wallet::signing::sign(
        signer,
        &SpendRequest {
            transaction: &commit,
            prevouts: std::slice::from_ref(&previous),
            budget,
        },
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
    let fee = previous
        .value
        .to_sat()
        .checked_sub(outputs)
        .ok_or(WalletError::InsufficientFunds)?;
    if fee > budget.maximum_base_units {
        return Err(WalletError::BudgetExceeded.into());
    }
    plan.commit = hex::encode(serialize(&signed));
    Ok(SignedPublicPair { plan, fee })
}
