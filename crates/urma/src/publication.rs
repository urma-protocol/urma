use crate::error::{Context, Error, ensure};
use crate::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::MultipartRecord,
    transport::Funding,
};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
};
use serde::{Deserialize, Serialize};
use urma_identity::identity::IdentitySigner;

pub use urma_chain::observation::Chain;

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

fn transaction(outpoint: OutPoint, output: TxOut) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![output],
    }
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
    let return_output = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: previous.script_pubkey.clone(),
    };
    let mut reveal = transaction(OutPoint::null(), return_output.clone());
    reveal.input[0].witness = envelope::witness(&[0; 64], &script, &info)?;
    let reveal_fee = u64::try_from(reveal.vsize())?
        .checked_mul(fee_rate)
        .context("fee overflow")?;
    let publication_output = TxOut {
        value: Amount::from_sat(1_000 + reveal_fee),
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
        .checked_sub(total_fee + 1_000)
        .context("insufficient funding")?;
    ensure!(change >= 1_000, "funding must leave native change");
    commit.output[1].value = Amount::from_sat(change);
    reveal.input[0].previous_output = OutPoint {
        txid: commit.compute_txid(),
        vout: 0,
    };
    let hash = SighashCache::new(&reveal).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(&publication_output)),
        TapLeafHash::from_script(&script, LeafVersion::TapScript),
        TapSighashType::Default,
    )?;
    let signature = author.sign_author(Message::from_digest(hash.to_byte_array()))?;
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

pub fn verify(
    commit: &[u8],
    reveal: &[u8],
) -> Result<(PublicRecord, envelope::ParsedEnvelope), Error> {
    let commit: Transaction = deserialize(commit)?;
    let reveal: Transaction = deserialize(reveal)?;
    let verified = envelope::verify_reveal(&reveal, &commit)?;
    Ok((PublicRecord::decode(&verified.record)?, verified))
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
    let mut reveal = transaction(OutPoint::null(), output.clone());
    reveal.input[0].witness = envelope::witness(&[0; 64], &script, &info)?;
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
