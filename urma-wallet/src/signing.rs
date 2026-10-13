use bitcoin::{
    CompressedPublicKey, ScriptBuf, Transaction,
    hashes::Hash,
    secp256k1::Message,
    sighash::{EcdsaSighashType, SighashCache},
};

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
