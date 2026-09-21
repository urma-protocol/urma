use crate::config;
use crate::error::{Context, Error, ensure};
use crate::transaction::transaction;
use bitcoin::{
    OutPoint, ScriptBuf, Transaction, TxOut,
    hashes::Hash,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo},
};
use urma_core::envelope;

pub(crate) fn preview(
    output: TxOut,
    script: &ScriptBuf,
    info: &TaprootSpendInfo,
) -> Result<Transaction, Error> {
    let mut reveal = transaction(OutPoint::null(), output);
    reveal.input[0].witness = envelope::witness(&[0; 64], script, info)?;
    ensure!(
        reveal.weight().to_wu() <= config::STANDARD_TX_WEIGHT,
        "reveal exceeds standard transaction weight"
    );
    Ok(reveal)
}

pub(crate) fn fee(reveal: &Transaction, rate: u64) -> Result<u64, Error> {
    u64::try_from(reveal.vsize())?
        .checked_mul(rate)
        .context("reveal fee overflow")
}

pub(crate) fn digest(
    reveal: &Transaction,
    previous: &TxOut,
    script: &ScriptBuf,
) -> Result<Message, Error> {
    let hash = SighashCache::new(reveal).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(previous)),
        TapLeafHash::from_script(script, LeafVersion::TapScript),
        TapSighashType::Default,
    )?;
    Ok(Message::from_digest(hash.to_byte_array()))
}
