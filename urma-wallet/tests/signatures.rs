use bitcoin::{
    Amount, CompressedPublicKey, ScriptBuf, Transaction, TxIn, TxOut, absolute,
    hashes::Hash,
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use urma_wallet::signing::{FundingSignatureError, verify_p2wpkh_signature};

#[test]
fn signature_binds_transaction_amount_key_and_input_index() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let public = CompressedPublicKey(secret.public_key(&secp));
    let previous = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&public.wpubkey_hash()),
    };
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: previous.script_pubkey.clone(),
        }],
    };
    let hash = SighashCache::new(&transaction)
        .p2wpkh_signature_hash(
            0,
            &previous.script_pubkey,
            previous.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &secret),
    );
    assert!(verify_p2wpkh_signature(&transaction, 0, &previous, &signature, &public).is_ok());
    assert!(matches!(
        verify_p2wpkh_signature(&transaction, 1, &previous, &signature, &public),
        Err(FundingSignatureError::Sighash(_))
    ));
    let mut changed = previous.clone();
    changed.value = Amount::from_sat(10_001);
    assert!(matches!(
        verify_p2wpkh_signature(&transaction, 0, &changed, &signature, &public),
        Err(FundingSignatureError::Signature(_))
    ));
    let other = CompressedPublicKey(SecretKey::from_slice(&[8; 32]).unwrap().public_key(&secp));
    assert!(matches!(
        verify_p2wpkh_signature(&transaction, 0, &previous, &signature, &other),
        Err(FundingSignatureError::PublicKeyMismatch)
    ));
    let mut wrong_type = signature;
    wrong_type.sighash_type = EcdsaSighashType::None;
    assert!(matches!(
        verify_p2wpkh_signature(&transaction, 0, &previous, &wrong_type, &public),
        Err(FundingSignatureError::SighashType)
    ));
    transaction.output[0].value = Amount::from_sat(8_000);
    assert!(matches!(
        verify_p2wpkh_signature(&transaction, 0, &previous, &signature, &public),
        Err(FundingSignatureError::Signature(_))
    ));
}
