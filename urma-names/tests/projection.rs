use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{
    error::NamesError,
    observation_from_verified,
    payload::Payload,
    projection::observation_from_record,
    state::{Commit, Observation},
};

struct Proof {
    commit: Transaction,
    reveal: Transaction,
}

impl Proof {
    // Sign arbitrary record bytes without payload validation, so malformed
    // semantic payloads still have genuine Taproot and author proofs.
    fn signed(bytes: &[u8]) -> Self {
        Self::signed_by(bytes, 4)
    }

    fn signed_by(bytes: &[u8], seed: u8) -> Self {
        let secp = Secp256k1::new();
        let signer = Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
        let author = signer.x_only_public_key().0;
        let mut builder = Builder::new()
            .push_x_only_key(&author)
            .push_opcode(OP_CHECKSIG)
            .push_int(0)
            .push_opcode(OP_IF)
            .push_slice(Urma::MAGIC);
        for chunk in bytes.chunks(520) {
            builder = match chunk {
                [value @ 1..=16] => builder.push_int(i64::from(*value)),
                [0x81] => builder.push_int(-1),
                bytes => builder.push_slice(PushBytesBuf::try_from(bytes.to_vec()).unwrap()),
            };
        }
        let script = builder.push_opcode(OP_ENDIF).into_script();
        let info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, author)
            .unwrap();
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
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(3_000),
                    script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
                },
            ],
        };
        let mut reveal = Transaction {
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
        let hash = SighashCache::new(&reveal)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&commit.output[1])),
                TapLeafHash::from_script(&script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &signer);
        reveal.input[0].witness = envelope::witness(signature.as_ref(), &script, &info).unwrap();
        Self { commit, reveal }
    }

    fn verified(&self) -> VerifiedRecord {
        VerifiedRecord::verify(self.reveal.compute_txid(), &self.reveal, &self.commit).unwrap()
    }

    fn location(&self) -> Commit {
        Commit {
            txid: self.commit.compute_txid(),
            vout: 1,
            height: 41,
            position: 3,
        }
    }
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/names")
}

fn claim_bytes() -> Vec<u8> {
    fs::read(vectors().join("claim.record")).unwrap()
}

#[test]
fn signed_corpus_matches_the_previous_observation_construction() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(vectors().join("manifest.json")).unwrap()).unwrap();
    let (mut valid, mut invalid, mut foreign) = (0, 0, 0);
    for case in manifest["cases"].as_array().unwrap() {
        let raw = fs::read(vectors().join(case["record"]["file"].as_str().unwrap())).unwrap();
        let proof = Proof::signed(&raw);
        let record = proof.verified();
        assert_eq!(record.record_bytes(), raw);
        let result = observation_from_verified(&record, &proof.reveal, 42, 7, proof.location());
        let primitive = observation_from_record(
            &raw,
            record.txid(),
            record.author(),
            42,
            7,
            proof.location(),
        );
        match (&result, &primitive) {
            (Ok(wrapper), Ok(parsed)) => assert_eq!(wrapper, parsed, "{}", case["name"]),
            (Err(wrapper), Err(parsed)) => {
                assert!(
                    matches!(parsed, NamesError::Protocol(_)),
                    "{}",
                    case["name"]
                );
                assert_eq!(wrapper.to_string(), parsed.to_string(), "{}", case["name"]);
            }
            _ => panic!("primitive/wrapper disagreement: {}", case["name"]),
        }
        match case["outcome"].as_str().unwrap() {
            "valid" => {
                let parsed = envelope::verify_reveal(&proof.reveal, &proof.commit).unwrap();
                let expected = Observation {
                    txid: proof.reveal.compute_txid(),
                    author: parsed.author,
                    record_sha256: Sha256::digest(&parsed.record).into(),
                    payload: Payload::from_record(&PublicRecord::decode(&parsed.record).unwrap())
                        .unwrap(),
                    height: 42,
                    position: 7,
                    commit: proof.location(),
                };
                assert_eq!(result.unwrap(), Some(expected), "{}", case["name"]);
                valid += 1;
            }
            "invalid" => {
                assert!(
                    matches!(result, Err(NamesError::Protocol(_))),
                    "{}",
                    case["name"]
                );
                invalid += 1;
            }
            "foreign" => {
                assert!(result.unwrap().is_none(), "{}", case["name"]);
                foreign += 1;
            }
            other => panic!("unknown outcome {other}"),
        }
    }
    assert_eq!((valid, invalid, foreign), (14, 37, 2));
}

#[test]
fn non_names_kinds_and_other_profiles_are_omitted() {
    for kind in [
        RecordKind::Private,
        RecordKind::Post,
        RecordKind::Container,
        RecordKind::Reply,
        RecordKind::Profile,
        RecordKind::Avatar,
        RecordKind::DataPart,
        RecordKind::LeafManifest,
        RecordKind::RootManifest,
        RecordKind::WirePost,
        RecordKind::WireReply,
    ] {
        let proof = Proof::signed(&kind.prefix());
        let record = proof.verified();
        assert!(
            observation_from_record(
                &kind.prefix(),
                record.txid(),
                record.author(),
                42,
                7,
                proof.location()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            observation_from_verified(&record, &proof.reveal, 42, 7, proof.location())
                .unwrap()
                .is_none()
        );
    }
    for profile in [*b"URMANAM2", *b"PROFILE1", [0; 8]] {
        let raw = PublicRecord::ProfileRecord {
            profile,
            payload: vec![0xff],
        }
        .encode()
        .unwrap();
        let proof = Proof::signed(&raw);
        let record = proof.verified();
        assert!(
            observation_from_record(
                &raw,
                record.txid(),
                record.author(),
                42,
                7,
                proof.location()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            observation_from_verified(&record, &proof.reveal, 42, 7, proof.location())
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn signed_truncated_or_oversized_profile_records_are_errors() {
    let mut oversized = RecordKind::ProfileRecord.prefix().to_vec();
    oversized.extend_from_slice(&Payload::PROFILE);
    oversized.resize(Urma::MAX_PUBLIC_BYTES + 1, 0);
    for raw in [RecordKind::ProfileRecord.prefix().to_vec(), oversized] {
        let proof = Proof::signed(&raw);
        let record = proof.verified();
        assert!(matches!(
            observation_from_record(
                &raw,
                record.txid(),
                record.author(),
                42,
                7,
                proof.location()
            ),
            Err(NamesError::Protocol(_))
        ));
        assert!(matches!(
            observation_from_verified(&record, &proof.reveal, 42, 7, proof.location()),
            Err(NamesError::Protocol(_))
        ));
    }
}

#[test]
fn mismatched_reveal_or_commit_outpoint_is_rejected_before_classification() {
    for raw in [
        claim_bytes(),
        PublicRecord::Post("other kind".into()).encode().unwrap(),
        PublicRecord::ProfileRecord {
            profile: *b"PROFILE1",
            payload: vec![0xff],
        }
        .encode()
        .unwrap(),
        RecordKind::ProfileRecord.prefix().to_vec(),
    ] {
        let proof = Proof::signed(&raw);
        let record = proof.verified();
        let mut wrong_reveal = proof.reveal.clone();
        wrong_reveal.output[0].value = Amount::from_sat(1);
        let error =
            observation_from_verified(&record, &wrong_reveal, 42, 7, proof.location()).unwrap_err();
        assert!(error.to_string().contains("TXID differs"));
        for commit in [
            Commit {
                txid: Txid::all_zeros(),
                ..proof.location()
            },
            Commit {
                vout: 0,
                ..proof.location()
            },
        ] {
            let error =
                observation_from_verified(&record, &proof.reveal, 42, 7, commit).unwrap_err();
            assert!(error.to_string().contains("commit outpoint"));
        }
        for count in [0, 2] {
            let mut reveal = proof.reveal.clone();
            reveal.input.resize(count, proof.reveal.input[0].clone());
            assert!(observation_from_verified(&record, &reveal, 42, 7, proof.location()).is_err());
        }
    }
}

#[test]
fn payload_and_author_come_only_from_the_verified_record() {
    let proof = Proof::signed(&claim_bytes());
    let record = proof.verified();
    let expected =
        observation_from_verified(&record, &proof.reveal, 42, 7, proof.location()).unwrap();
    let replacement = Proof::signed_by(&fs::read(vectors().join("renew.record")).unwrap(), 5);
    assert_ne!(replacement.verified().author(), record.author());
    let mut reveal = proof.reveal.clone();
    reveal.input[0].witness = replacement.reveal.input[0].witness.clone();
    assert_eq!(reveal.compute_txid(), record.txid());
    assert!(VerifiedRecord::verify(record.txid(), &reveal, &proof.commit).is_err());
    assert_eq!(
        observation_from_verified(&record, &reveal, 42, 7, proof.location()).unwrap(),
        expected
    );
    reveal.input[0].witness = Witness::new();
    assert_eq!(
        observation_from_verified(&record, &reveal, 42, 7, proof.location()).unwrap(),
        expected
    );
}

#[test]
fn location_metadata_is_preserved_without_claiming_inclusion_or_window_validity() {
    let proof = Proof::signed(&claim_bytes());
    let record = proof.verified();
    let commit = Commit {
        height: u64::MAX,
        position: u32::MAX,
        ..proof.location()
    };
    let observation = observation_from_verified(&record, &proof.reveal, 0, u32::MAX, commit)
        .unwrap()
        .unwrap();
    assert_eq!((observation.height, observation.position), (0, u32::MAX));
    assert_eq!(observation.commit, commit);
    assert_eq!(observation.author, record.author());
    assert_eq!(observation.record_sha256, record.reference().record_hash);
    assert_eq!(observation.txid, record.txid());
}

#[test]
fn primitive_preserves_arbitrary_metadata_without_authenticating_it() {
    let raw = claim_bytes();
    let proof = Proof::signed(&raw);
    let verified = proof.verified();
    let other = Proof::signed_by(&raw, 5).verified();
    let txid = Txid::from_byte_array([0x91; 32]);
    let author = other.author();
    let commit = Commit {
        txid: Txid::from_byte_array([0x92; 32]),
        vout: u32::MAX,
        height: u64::MAX,
        position: u32::MAX,
    };
    assert_ne!(txid, verified.txid());
    assert_ne!(author, verified.author());
    assert_ne!(commit.txid, proof.commit.compute_txid());
    for height in [0, u64::MAX] {
        let parsed = observation_from_record(&raw, txid, author, height, u32::MAX, commit)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.txid, txid);
        assert_eq!(parsed.author, author);
        assert_eq!((parsed.height, parsed.position), (height, u32::MAX));
        assert_eq!(parsed.commit, commit);
        assert_eq!(
            parsed.payload,
            Payload::from_record(&PublicRecord::decode(&raw).unwrap()).unwrap()
        );
        assert_eq!(parsed.record_sha256, verified.reference().record_hash);
    }
    // This acceptance is only parsing: the authenticated wrapper still rejects
    // the exact same unrelated commit, without delegating/classifying first.
    let error =
        observation_from_verified(&verified, &proof.reveal, 0, u32::MAX, commit).unwrap_err();
    assert!(error.to_string().contains("commit outpoint"));
}

#[test]
fn primitive_digest_covers_exact_record_bytes_including_header() {
    let mut hashes = Vec::new();
    for name in ["claim.record", "renew.record"] {
        let raw = fs::read(vectors().join(name)).unwrap();
        let proof = Proof::signed(&raw);
        let record = proof.verified();
        let parsed = observation_from_record(
            &raw,
            record.txid(),
            record.author(),
            42,
            7,
            proof.location(),
        )
        .unwrap()
        .unwrap();
        let digest: [u8; 32] = Sha256::digest(&raw).into();
        let payload_digest: [u8; 32] = Sha256::digest(&raw[Urma::PREFIX_BYTES + 8..]).into();
        assert_eq!(parsed.record_sha256, digest);
        assert_eq!(parsed.record_sha256, record.reference().record_hash);
        assert_ne!(parsed.record_sha256, payload_digest);
        hashes.push(parsed.record_sha256);
    }
    assert_ne!(hashes[0], hashes[1]);
}

#[test]
fn primitive_rejects_invalid_record_headers_before_kind_filtering() {
    let proof = Proof::signed(&claim_bytes());
    let record = proof.verified();
    let mut marker = RecordKind::Post.prefix();
    marker[0] ^= 1;
    let mut version = RecordKind::Post.prefix();
    version[4] = 1;
    let mut flags = RecordKind::Post.prefix();
    flags[7] = 1;
    for raw in [
        &[][..],
        &marker[..],
        &version[..],
        &flags[..],
        b"URMA\0\xff\0\0".as_slice(),
    ] {
        assert!(matches!(
            observation_from_record(raw, record.txid(), record.author(), 42, 7, proof.location()),
            Err(NamesError::Protocol(_))
        ));
    }
}
