use bitcoin::{
    Amount, CompressedPublicKey, ScriptBuf, Transaction, TxIn, TxOut, Witness, absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use urma_chain::observation::Chain;
use urma_runtime::plan::PublicationPlan;
use urma_wallet::funding::Funding;

#[test]
fn publication_requires_signed_compressed_funding_and_matching_author() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let signer = Keypair::from_secret_key(&secp, &secret);
    let public = CompressedPublicKey(secret.public_key(&secp));
    let previous = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&public.wpubkey_hash()),
    };
    let funding = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![previous.clone()],
    };
    let mut pair = urma_runtime::publication::prepare(
        &urma_core::format::PublicRecord::Post("funding validation".into()),
        &signer,
        Funding {
            raw_transaction: hex::encode(serialize(&funding)),
            vout: 0,
        },
        Chain::BitcoinRegtest,
        1,
    )
    .unwrap();
    let mut commit: Transaction = deserialize(&hex::decode(&pair.commit).unwrap()).unwrap();
    let reveal: Transaction = deserialize(&hex::decode(&pair.reveal).unwrap()).unwrap();
    let hash = SighashCache::new(&commit)
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
    commit.input[0].witness = Witness::p2wpkh(&signature, &public.0);
    pair.commit = hex::encode(serialize(&commit));
    let plan = PublicationPlan {
        version: 1,
        chain: Chain::BitcoinRegtest,
        author: public.0.x_only_public_key().0.to_string(),
        root_txid: reveal.compute_txid().to_string(),
        total_fee: previous.value.to_sat()
            - commit.output[1].value.to_sat()
            - reveal.output[0].value.to_sat(),
        maximum_fee: 100_000,
        records: vec![pair],
    };
    plan.validate().unwrap();
    let mut wrong_author = plan.clone();
    wrong_author.author = "other author".into();
    assert_eq!(
        wrong_author.validate().unwrap_err().to_string(),
        "author and funding identities differ"
    );
    for mutation in 0..7 {
        let mut changed = commit.clone();
        match mutation {
            0 => changed.input[0].witness = Witness::new(),
            1 => {
                assert!(changed.output.pop().is_some());
            }
            2 => changed.input.clear(),
            3 => changed.input[0].script_sig = ScriptBuf::from_bytes(vec![0]),
            4 => changed.input[0].witness.push([0]),
            5 => {
                changed.input[0].witness = Witness::from_slice(&[
                    signature.to_vec(),
                    public.0.serialize_uncompressed().to_vec(),
                ])
            }
            6 => changed.output[0].value = Amount::from_sat(1),
            _ => unreachable!(),
        }
        let mut invalid = plan.clone();
        invalid.records[0].commit = hex::encode(serialize(&changed));
        assert!(invalid.validate().is_err(), "mutation {mutation}");
    }
}
