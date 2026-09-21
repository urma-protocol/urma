use crate::wallet::{SpendRequest, WalletError};
use bitcoin::{
    CompressedPublicKey, ScriptBuf, Transaction, Witness,
    hashes::Hash,
    secp256k1::Message,
    sighash::{EcdsaSighashType, SighashCache},
};
use urma_identity::identity::IdentitySigner;

pub fn script(signer: &impl IdentitySigner) -> Result<ScriptBuf, WalletError> {
    let public = CompressedPublicKey::try_from(signer.public_key())
        .map_err(|cause| WalletError::Protocol(cause.into()))?;
    Ok(ScriptBuf::new_p2wpkh(&public.wpubkey_hash()))
}

pub fn sign(
    signer: &impl IdentitySigner,
    request: &SpendRequest<'_>,
) -> Result<Transaction, WalletError> {
    let tx = request.transaction;
    if tx.input.is_empty() || tx.input.len() != request.prevouts.len() {
        return Err(WalletError::InvalidFunding);
    }
    let mut seen = std::collections::HashSet::new();
    if tx
        .input
        .iter()
        .any(|input| !seen.insert(input.previous_output))
    {
        return Err(WalletError::InvalidFunding);
    }
    let expected = script(signer)?;
    let mut total = 0u64;
    for output in request.prevouts {
        if output.script_pubkey != expected {
            return Err(WalletError::WrongIdentity);
        }
        total = total
            .checked_add(output.value.to_sat())
            .ok_or(WalletError::Overflow)?;
    }
    let mut outputs = 0u64;
    for output in &tx.output {
        outputs = outputs
            .checked_add(output.value.to_sat())
            .ok_or(WalletError::Overflow)?;
    }
    let fee = total
        .checked_sub(outputs)
        .ok_or(WalletError::InsufficientFunds)?;
    if fee > request.budget.maximum_base_units {
        return Err(WalletError::BudgetExceeded);
    }
    let mut signed = tx.clone();
    for (index, previous) in request.prevouts.iter().enumerate() {
        if !tx.input[index].script_sig.is_empty() {
            return Err(WalletError::InvalidFunding);
        }
        let digest = SighashCache::new(tx)
            .p2wpkh_signature_hash(index, &expected, previous.value, EcdsaSighashType::All)
            .map_err(|cause| WalletError::Protocol(cause.into()))?;
        let signature = signer
            .sign_funding(Message::from_digest(digest.to_byte_array()))
            .map_err(WalletError::Identity)?;
        bitcoin::secp256k1::Secp256k1::new()
            .verify_ecdsa(
                &Message::from_digest(digest.to_byte_array()),
                &signature,
                &signer.public_key().inner,
            )
            .map_err(|cause| WalletError::Protocol(cause.into()))?;
        let signature = bitcoin::ecdsa::Signature::sighash_all(signature);
        signed.input[index].witness = Witness::p2wpkh(&signature, &signer.public_key().inner);
    }
    Ok(signed)
}

#[derive(Debug)]
pub enum FundingSignatureError {
    SighashType,
    PublicKeyMismatch,
    Sighash(bitcoin::sighash::P2wpkhError),
    Signature(bitcoin::secp256k1::Error),
}

impl std::fmt::Display for FundingSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SighashType => f.write_str("funding signature must commit all outputs"),
            Self::PublicKeyMismatch => f.write_str("funding public key mismatch"),
            Self::Sighash(cause) => std::fmt::Display::fmt(cause, f),
            Self::Signature(cause) => std::fmt::Display::fmt(cause, f),
        }
    }
}

impl std::error::Error for FundingSignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sighash(cause) => Some(cause),
            Self::Signature(cause) => Some(cause),
            _ => None,
        }
    }
}

pub fn verify_p2wpkh_signature(
    transaction: &Transaction,
    input_index: usize,
    previous: &bitcoin::TxOut,
    signature: &bitcoin::ecdsa::Signature,
    public: &CompressedPublicKey,
) -> Result<(), FundingSignatureError> {
    if signature.sighash_type != EcdsaSighashType::All {
        return Err(FundingSignatureError::SighashType);
    }
    if previous.script_pubkey != ScriptBuf::new_p2wpkh(&public.wpubkey_hash()) {
        return Err(FundingSignatureError::PublicKeyMismatch);
    }
    let hash = SighashCache::new(transaction)
        .p2wpkh_signature_hash(
            input_index,
            &previous.script_pubkey,
            previous.value,
            signature.sighash_type,
        )
        .map_err(FundingSignatureError::Sighash)?;
    bitcoin::secp256k1::Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(hash.to_byte_array()),
            &signature.signature,
            &public.0,
        )
        .map_err(FundingSignatureError::Signature)
}
