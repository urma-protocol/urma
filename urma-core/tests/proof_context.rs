use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo},
    transaction::Version,
};
use urma_core::{
    envelope,
    error::Error,
    multipart::{DataPart, MultipartRecord, VerifiedRecord},
};

struct Pair {
    signer: Keypair,
    record: MultipartRecord,
    script: ScriptBuf,
    info: TaprootSpendInfo,
    commit: Transaction,
    reveal: Transaction,
}

impl Pair {
    fn new() -> Result<Self, Error> {
        let secp = Secp256k1::new();
        let signer = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32])?);
        let record = MultipartRecord::Data(DataPart {
            index: 0,
            payload: b"proof context".to_vec(),
        });
        let (script, info) = envelope::build(&record.encode()?, &signer)?;
        let commit = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, signer.x_only_public_key().0, None),
                },
                TxOut {
                    value: Amount::from_sat(3_000),
                    script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
                },
            ],
        };
        let reveal = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: commit.compute_txid(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_500),
                script_pubkey: ScriptBuf::from_bytes([vec![0, 20], vec![4; 20]].concat()),
            }],
        };
        let mut pair = Self {
            signer,
            record,
            script,
            info,
            commit,
            reveal,
        };
        pair.sign_for(&pair.commit.output[1].clone())?;
        Ok(pair)
    }

    fn sign_for(&mut self, prevout: &TxOut) -> Result<(), Error> {
        let hash = SighashCache::new(&self.reveal).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(prevout)),
            TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
            TapSighashType::Default,
        )?;
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &self.signer);
        self.reveal.input[0].witness =
            envelope::witness(signature.as_ref(), &self.script, &self.info)?;
        Ok(())
    }
}

fn reveal_error(reveal: &Transaction, commit: &Transaction) -> Error {
    match envelope::verify_reveal(reveal, commit) {
        Ok(parsed) => panic!("unexpected accepted record: {:?}", parsed.record),
        Err(error) => error,
    }
}

#[test]
fn signed_nonzero_vout_uses_selected_output_instead_of_decoy_zero() -> Result<(), Error> {
    let pair = Pair::new()?;
    assert_ne!(pair.commit.output[0].value, pair.commit.output[1].value);
    assert_ne!(
        pair.commit.output[0].script_pubkey,
        pair.commit.output[1].script_pubkey
    );
    assert_eq!(pair.reveal.input[0].previous_output.vout, 1);
    let parsed = envelope::verify_reveal(&pair.reveal, &pair.commit)?;
    assert_eq!(parsed.record, pair.record.encode()?);
    let verified = VerifiedRecord::verify(pair.reveal.compute_txid(), &pair.reveal, &pair.commit)?;
    assert_eq!(verified.decode()?, pair.record);
    assert_eq!(
        envelope::verify_prevout(&pair.reveal, &pair.commit.output[1])?.record,
        parsed.record
    );
    assert!(envelope::verify_prevout(&pair.reveal, &pair.commit.output[0]).is_err());
    Ok(())
}

#[test]
fn swapped_commit_with_identical_outputs_is_rejected_by_recomputed_txid() -> Result<(), Error> {
    let pair = Pair::new()?;
    let mut alternate = pair.commit.clone();
    alternate.input[0].previous_output.txid = Txid::from_byte_array([9; 32]);
    assert_eq!(alternate.output, pair.commit.output);
    assert_ne!(alternate.compute_txid(), pair.commit.compute_txid());
    envelope::verify_reveal(&pair.reveal, &pair.commit)?;
    envelope::verify_prevout(&pair.reveal, &alternate.output[1])?;
    for error in [
        reveal_error(&pair.reveal, &alternate),
        VerifiedRecord::verify(pair.reveal.compute_txid(), &pair.reveal, &alternate).unwrap_err(),
    ] {
        match error {
            Error::Invalid(reason) => {
                assert_eq!(reason, "reveal does not spend the supplied commit")
            }
            other => panic!("wrong commit rejection: {other}"),
        }
    }
    Ok(())
}

#[test]
fn valid_signature_for_wrong_amount_cannot_override_actual_selected_prevout() -> Result<(), Error> {
    let mut pair = Pair::new()?;
    let mut claimed = pair.commit.output[1].clone();
    claimed.value += Amount::from_sat(1);
    pair.sign_for(&claimed)?;
    assert_eq!(
        pair.reveal.input[0].previous_output.txid,
        pair.commit.compute_txid()
    );
    assert!(pair.reveal.output[0].value < pair.commit.output[1].value);
    envelope::verify_prevout(&pair.reveal, &claimed)?;
    for error in [
        reveal_error(&pair.reveal, &pair.commit),
        VerifiedRecord::verify(pair.reveal.compute_txid(), &pair.reveal, &pair.commit).unwrap_err(),
    ] {
        match error {
            Error::Context { message, cause } => {
                assert_eq!(message, "invalid author signature");
                assert!(matches!(*cause, Error::Secp256k1(..)));
            }
            other => panic!("wrong amount rejection: {other}"),
        }
    }
    Ok(())
}

#[test]
fn valid_detached_prevout_proof_cannot_replace_actual_selected_script() -> Result<(), Error> {
    let mut pair = Pair::new()?;
    let detached = pair.commit.output[1].clone();
    pair.commit.output[1].script_pubkey = pair.commit.output[0].script_pubkey.clone();
    pair.reveal.input[0].previous_output.txid = pair.commit.compute_txid();
    pair.sign_for(&detached)?;
    assert_eq!(detached.value, pair.commit.output[1].value);
    assert!(pair.commit.output[1].script_pubkey.is_p2tr());
    envelope::verify_prevout(&pair.reveal, &detached)?;
    for error in [
        reveal_error(&pair.reveal, &pair.commit),
        VerifiedRecord::verify(pair.reveal.compute_txid(), &pair.reveal, &pair.commit).unwrap_err(),
    ] {
        match error {
            Error::Invalid(reason) => assert_eq!(reason, "invalid Taproot commitment"),
            other => panic!("wrong script rejection: {other}"),
        }
    }
    Ok(())
}

#[test]
fn signed_out_of_range_vout_is_refused_even_if_a_detached_output_proof_verifies()
-> Result<(), Error> {
    let mut pair = Pair::new()?;
    let detached = pair.commit.output[1].clone();
    for vout in [u32::try_from(pair.commit.output.len())?, u32::MAX] {
        pair.reveal.input[0].previous_output.vout = vout;
        pair.sign_for(&detached)?;
        assert_eq!(
            pair.reveal.input[0].previous_output.txid,
            pair.commit.compute_txid()
        );
        envelope::verify_prevout(&pair.reveal, &detached)?;
        for error in [
            reveal_error(&pair.reveal, &pair.commit),
            VerifiedRecord::verify(pair.reveal.compute_txid(), &pair.reveal, &pair.commit)
                .unwrap_err(),
        ] {
            match error {
                Error::Missing(reason) => assert_eq!(reason, "commit outpoint absent"),
                other => panic!("wrong vout rejection: {other}"),
            }
        }
    }
    Ok(())
}
