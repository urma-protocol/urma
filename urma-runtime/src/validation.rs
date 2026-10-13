use crate::config;
use crate::error::{Context, Error, bail, ensure};
use crate::plan::PublicationPlan;
use crate::publication::PublicPlan;
use crate::transaction::decode;
use bitcoin::{CompressedPublicKey, OutPoint, ScriptBuf, Transaction, TxOut, ecdsa};
use std::collections::HashSet;
use urma_chain::observation::Chain;
use urma_core::{envelope, format::Urma};
use urma_wallet::{
    account::Account,
    signing::{FundingSignatureError, verify_p2wpkh_signature},
};

fn transaction(raw: &str) -> Result<Transaction, Error> {
    decode(raw, usize::MAX).map_err(|cause| match cause {
        Error::Context { cause, .. } => *cause,
        cause => cause,
    })
}

pub(crate) fn return_script(hex_script: &str) -> Result<ScriptBuf, Error> {
    let script = ScriptBuf::from(hex::decode(hex_script)?);
    ensure!(
        script.is_p2wpkh(),
        "publication return requires native P2WPKH"
    );
    Ok(script)
}

pub(crate) fn funded_by(hex_script: &str, funder: &Account) -> Result<bool, Error> {
    Ok(return_script(hex_script)? == funder.receive_script()?)
}

fn funding_error(cause: FundingSignatureError) -> Error {
    match cause {
        FundingSignatureError::SighashType => {
            Error::Invalid("funding signature must commit all outputs".into())
        }
        FundingSignatureError::PublicKeyMismatch => {
            Error::Invalid("funding public key mismatch".into())
        }
        FundingSignatureError::Sighash(cause) => cause.into(),
        FundingSignatureError::Signature(cause) => cause.into(),
    }
}

fn verify_input(commit: &Transaction, index: usize, previous: &TxOut) -> Result<(), Error> {
    let input = &commit.input[index];
    ensure!(
        input.script_sig.is_empty() && input.witness.len() == 2,
        "funding must be signed native P2WPKH"
    );
    let mut witness = input.witness.iter();
    let signature =
        ecdsa::Signature::from_slice(witness.next().context("missing funding signature")?)?;
    let key = witness.next().context("missing funding public key")?;
    ensure!(key.len() == 33, "funding public key must be compressed");
    let public = CompressedPublicKey::from_slice(key)?;
    verify_p2wpkh_signature(commit, index, previous, &signature, &public).map_err(funding_error)
}

fn verify_commit(commit: &Transaction, prevouts: &[(OutPoint, TxOut)]) -> Result<(), Error> {
    ensure!(
        commit.input.len() == prevouts.len() && commit.output.len() == 2,
        "invalid commit transaction shape"
    );
    let mut seen = HashSet::new();
    for (index, (input, (outpoint, previous))) in commit.input.iter().zip(prevouts).enumerate() {
        ensure!(
            input.previous_output == *outpoint && seen.insert(*outpoint),
            "commit does not spend declared funding"
        );
        verify_input(commit, index, previous)?;
    }
    Ok(())
}

fn verify_first_funding(pair: &PublicPlan) -> Result<(), Error> {
    ensure!(
        (1..=config::WALLET_MAX_INPUTS).contains(&pair.funding.len()),
        "first publication record needs 1..{} funding inputs",
        config::WALLET_MAX_INPUTS
    );
    Ok(())
}

fn verify_chained_funding(pair: &PublicPlan, previous_commit: &str) -> Result<(), Error> {
    let [chained] = pair.funding.as_slice() else {
        bail!("broken publication funding chain");
    };
    ensure!(
        chained.raw_transaction == previous_commit && chained.vout == 1,
        "broken publication funding chain"
    );
    Ok(())
}

fn declared_funding(pair: &PublicPlan) -> Result<Vec<(OutPoint, TxOut)>, Error> {
    let mut prevouts = Vec::new();
    for funding in &pair.funding {
        prevouts.push(funding.prevout()?);
    }
    Ok(prevouts)
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
    let return_script = return_script(&plan.return_script)?;
    let mut state = Validation::new();
    for pair in &plan.records {
        state.append(pair, plan.chain, &plan.author, &return_script)?;
    }
    state.finish(plan.total_fee, &plan.root_txid)
}

pub(crate) struct Validation {
    count: u32,
    total: u64,
    previous_commit: String,
    last: String,
}

impl Validation {
    pub(crate) fn new() -> Self {
        Self {
            count: 0,
            total: 0,
            previous_commit: String::new(),
            last: String::new(),
        }
    }

    pub(crate) fn append(
        &mut self,
        pair: &PublicPlan,
        chain: Chain,
        author: &str,
        return_script: &ScriptBuf,
    ) -> Result<Vec<u8>, Error> {
        ensure!(
            pair.chain.genesis()? == chain.genesis()? && pair.version == Urma::VERSION,
            "plan record network or version mismatch"
        );
        ensure!(
            (1..=100).contains(&pair.fee_rate),
            "invalid record fee rate"
        );
        match self.count {
            0 => verify_first_funding(pair)?,
            _ => verify_chained_funding(pair, &self.previous_commit)?,
        }
        let prevouts = declared_funding(pair)?;
        let commit = transaction(&pair.commit)?;
        let reveal = transaction(&pair.reveal)?;
        verify_commit(&commit, &prevouts)?;
        let parsed = envelope::verify_reveal(&reveal, &commit)?;
        verify_policy(&commit, &reveal, chain)?;
        ensure!(
            parsed.author.to_string() == author,
            "record author mismatch"
        );
        ensure!(
            commit.output[1].script_pubkey == *return_script
                && reveal.output[0].script_pubkey == *return_script,
            "publication return destination mismatch"
        );
        let mut available = 0u64;
        for (_, previous) in &prevouts {
            available = available
                .checked_add(previous.value.to_sat())
                .context("funding sum overflow")?;
        }
        let committed = commit.output[0]
            .value
            .to_sat()
            .checked_add(commit.output[1].value.to_sat())
            .context("commit output sum overflow")?;
        ensure!(
            committed <= available,
            "commit spends more than declared funding"
        );
        let outputs = commit.output[1]
            .value
            .to_sat()
            .checked_add(reveal.output[0].value.to_sat())
            .context("output sum overflow")?;
        let fee = available
            .checked_sub(outputs)
            .context("negative publication fee")?;
        self.total = self.total.checked_add(fee).context("fee sum overflow")?;
        self.previous_commit = pair.commit.clone();
        self.last = reveal.compute_txid().to_string();
        self.count = self.count.checked_add(1).context("record count overflow")?;
        Ok(parsed.record)
    }

    pub(crate) fn last_txid(&self) -> Result<bitcoin::Txid, Error> {
        Ok(self.last.parse()?)
    }

    pub(crate) fn finish(&self, total_fee: u64, root_txid: &str) -> Result<(), Error> {
        ensure!(
            self.total == total_fee && self.last == root_txid,
            "plan fee or locator mismatch"
        );
        Ok(())
    }
}

fn verify_policy(commit: &Transaction, reveal: &Transaction, chain: Chain) -> Result<(), Error> {
    ensure!(
        commit.weight().to_wu() <= config::STANDARD_TX_WEIGHT
            && reveal.weight().to_wu() <= config::STANDARD_TX_WEIGHT,
        "publication exceeds standard transaction weight"
    );
    let retained = config::publication_return(chain);
    ensure!(
        commit.output[0].value.to_sat() >= retained
            && commit.output[1].value.to_sat() >= retained
            && reveal.output[0].value.to_sat() >= retained,
        "publication output below configured dust-safe retained value"
    );
    Ok(())
}
