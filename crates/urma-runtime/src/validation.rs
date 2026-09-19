use crate::plan::PublicationPlan;
use bitcoin::{
    Transaction,
    consensus::deserialize,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
};
use urma::error::{Context, Error, ensure};

fn transaction(raw: &str) -> Result<Transaction, Error> {
    Ok(deserialize(&hex::decode(raw)?)?)
}

fn verify_commit(
    commit: &Transaction,
    previous: &bitcoin::TxOut,
    author: &str,
) -> Result<(), Error> {
    ensure!(
        commit.input.len() == 1 && commit.output.len() == 2,
        "invalid commit transaction shape"
    );
    let input = &commit.input[0];
    ensure!(
        input.script_sig.is_empty() && input.witness.len() == 2,
        "funding must be signed native P2WPKH"
    );
    let mut witness = input.witness.iter();
    let signature = bitcoin::ecdsa::Signature::from_slice(
        witness.next().context("missing funding signature")?,
    )?;
    let public =
        bitcoin::PublicKey::from_slice(witness.next().context("missing funding public key")?)?;
    ensure!(
        signature.sighash_type == bitcoin::sighash::EcdsaSighashType::All,
        "funding signature must commit all outputs"
    );
    ensure!(
        public.inner.x_only_public_key().0.to_string() == author,
        "author and funding identities differ"
    );
    let compressed = bitcoin::CompressedPublicKey::try_from(public)?;
    ensure!(
        previous.script_pubkey == bitcoin::ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash()),
        "funding public key mismatch"
    );
    let hash = SighashCache::new(commit).p2wpkh_signature_hash(
        0,
        &previous.script_pubkey,
        previous.value,
        signature.sighash_type,
    )?;
    Secp256k1::verification_only().verify_ecdsa(
        &Message::from_digest(hash.to_byte_array()),
        &signature.signature,
        &public.inner,
    )?;
    Ok(())
}

pub(crate) fn validate(plan: &PublicationPlan) -> Result<(), Error> {
    ensure!(
        plan.version == 1
            && !plan.records.is_empty()
            && plan.records.len() <= usize::try_from(PublicationPlan::MAX_RECORDS)?,
        "invalid publication plan version or size"
    );
    ensure!(
        plan.total_fee <= plan.maximum_fee && plan.maximum_fee > 0,
        "plan fee budget exceeded"
    );
    let mut total = 0u64;
    let mut previous_commit = String::new();
    let mut last = String::new();
    for (index, pair) in plan.records.iter().enumerate() {
        ensure!(
            pair.chain.genesis()? == plan.chain.genesis()?
                && pair.version == urma_core::format::Urma::VERSION,
            "plan record network or version mismatch"
        );
        ensure!(
            (1..=100).contains(&pair.fee_rate),
            "invalid record fee rate"
        );
        if index > 0 {
            ensure!(
                pair.funding.raw_transaction == previous_commit && pair.funding.vout == 1,
                "broken publication funding chain"
            );
        }
        let (outpoint, previous) = pair.funding.prevout()?;
        let commit = transaction(&pair.commit)?;
        let reveal = transaction(&pair.reveal)?;
        verify_commit(&commit, &previous, &plan.author)?;
        ensure!(
            commit.input[0].previous_output == outpoint,
            "commit does not spend declared funding"
        );
        let parsed = urma_core::envelope::verify_reveal(&reveal, &commit)?;
        ensure!(
            parsed.author.to_string() == plan.author,
            "record author mismatch"
        );
        ensure!(
            commit.output[1].script_pubkey == previous.script_pubkey
                && reveal.output[0].script_pubkey == previous.script_pubkey,
            "publication change destination mismatch"
        );
        let committed = commit.output[0]
            .value
            .to_sat()
            .checked_add(commit.output[1].value.to_sat())
            .context("commit output sum overflow")?;
        ensure!(
            committed <= previous.value.to_sat(),
            "commit spends more than declared funding"
        );
        let outputs = commit.output[1]
            .value
            .to_sat()
            .checked_add(reveal.output[0].value.to_sat())
            .context("output sum overflow")?;
        let fee = previous
            .value
            .to_sat()
            .checked_sub(outputs)
            .context("negative publication fee")?;
        total = total.checked_add(fee).context("fee sum overflow")?;
        previous_commit = pair.commit.clone();
        last = reveal.compute_txid().to_string();
    }
    ensure!(
        total == plan.total_fee && last == plan.root_txid,
        "plan fee or locator mismatch"
    );
    Ok(())
}
