use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute,
    blockdata::constants::genesis_block,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind, Urma},
    multipart::{DataPart, MultipartRecord, VerifiedRecord},
    topics::Topics,
};
use urma_wire::{
    Error,
    cached::decode_cached,
    index::{self, entry_from_record, entry_from_verified},
    reader::Reader,
};

struct Proof {
    commit: Transaction,
    reveal: Transaction,
}

impl Proof {
    // Build and sign raw bytes without invoking the payload codec, so malformed
    // payload tests fail for semantic reasons after genuine proof verification.
    fn signed(bytes: &[u8]) -> Self {
        let secp = Secp256k1::new();
        let signer = Keypair::from_seckey_slice(&secp, &[4; 32]).unwrap();
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
            output: vec![TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
            }],
        };
        let mut reveal = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: commit.compute_txid(),
                    vout: 0,
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
                &Prevouts::All(&commit.output),
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
}

struct MemoryReader {
    block: Block,
    proofs: Vec<Proof>,
}

impl MemoryReader {
    const HEIGHT: u64 = 42;

    fn new(proofs: Vec<Proof>) -> Self {
        let mut block = genesis_block(Network::Regtest);
        block
            .txdata
            .extend(proofs.iter().map(|proof| proof.reveal.clone()));
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        Self { block, proofs }
    }

    fn scan(&self) -> index::Index {
        let directory = tempfile::tempdir().unwrap();
        index::sync(
            self,
            &directory.path().join("index.json"),
            Self::HEIGHT,
            1,
            |height, tip| assert_eq!((height, tip), (Self::HEIGHT, Self::HEIGHT)),
        )
        .unwrap()
        .1
    }
}

impl Reader for MemoryReader {
    type Error = std::io::Error;

    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Ok(genesis_block(Network::Regtest).block_hash())
    }
    fn tip_height(&self) -> Result<u64, Self::Error> {
        Ok(Self::HEIGHT)
    }
    fn block_hash(&self, height: u64) -> Result<BlockHash, Self::Error> {
        assert_eq!(height, Self::HEIGHT);
        Ok(self.block.block_hash())
    }
    fn block(&self, height: u64) -> Result<(Block, BlockHash), Self::Error> {
        assert_eq!(height, Self::HEIGHT);
        Ok((self.block.clone(), self.block.block_hash()))
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, Self::Error> {
        self.proofs
            .iter()
            .find(|proof| proof.commit.compute_txid() == txid)
            .map(|proof| proof.commit.clone())
            .ok_or_else(|| std::io::Error::other("unknown commit"))
    }
}

#[test]
fn standalone_projection_matches_scanner_and_existing_wire_verification_for_all_six_kinds() {
    let target = Txid::from_byte_array([0xAB; 32]);
    let topics = Topics {
        wire: "news".into(),
        hashtags: vec!["local".into(), "urma".into()],
    };
    let records = [
        PublicRecord::Post(" \0e\u{301}\r\n ".into()),
        PublicRecord::Reply {
            target,
            text: "reply ț".into(),
        },
        PublicRecord::Profile("ț".repeat(64)),
        PublicRecord::Avatar(Box::new([0xAB; 128])),
        PublicRecord::WirePost {
            topics: topics.clone(),
            text: "structured post".into(),
        },
        PublicRecord::WireReply {
            target,
            topics,
            text: "structured reply".into(),
        },
    ];
    let reader = MemoryReader::new(
        records
            .iter()
            .map(|record| Proof::signed(&record.encode().unwrap()))
            .collect(),
    );
    let scanned = reader.scan();
    assert_eq!(scanned.entries.len(), records.len());
    for (position, ((proof, expected), scanned)) in reader
        .proofs
        .iter()
        .zip(records)
        .zip(scanned.entries)
        .enumerate()
    {
        let verified = proof.verified();
        let returned = proof.reveal.output[0].script_pubkey.as_script();
        assert_eq!(
            scanned.return_script,
            Some(hex::encode(returned.as_bytes())),
            "the scanner keeps the reveal return script"
        );
        let direct = entry_from_verified(
            &verified,
            Some(returned),
            MemoryReader::HEIGHT,
            scanned.position,
        )
        .unwrap()
        .unwrap();
        let primitive = entry_from_record(
            verified.record_bytes(),
            verified.txid(),
            verified.author(),
            Some(returned),
            MemoryReader::HEIGHT,
            scanned.position,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_value(&primitive).unwrap(),
            serde_json::to_value(&direct).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            serde_json::to_value(&scanned).unwrap()
        );
        let old = urma_profiles::wire::verify(&proof.reveal, &proof.commit).unwrap();
        assert_eq!(old.record(), &expected);
        assert_eq!(direct.txid, proof.reveal.compute_txid().to_string());
        assert_eq!(direct.author, old.author().0.to_string());
        assert_eq!(hex::decode(&direct.record).unwrap(), old.raw_record());
        assert_eq!(scanned.height, MemoryReader::HEIGHT);
        assert_eq!(scanned.position, 1 + u32::try_from(position).unwrap());

        let metadata = entry_from_verified(&verified, None, u64::MAX, u32::MAX)
            .unwrap()
            .unwrap();
        assert_eq!((metadata.height, metadata.position), (u64::MAX, u32::MAX));
        assert_eq!(metadata.txid, direct.txid);
        assert_eq!(metadata.author, direct.author);
        assert_eq!(metadata.record, direct.record);
    }
}

#[test]
fn non_wire_kinds_are_omitted_including_kind_0c() {
    for kind in [
        RecordKind::Private,
        RecordKind::Container,
        RecordKind::DataPart,
        RecordKind::LeafManifest,
        RecordKind::RootManifest,
        RecordKind::ProfileRecord,
    ] {
        let proof = Proof::signed(&kind.prefix());
        let verified = proof.verified();
        assert!(
            entry_from_verified(&verified, None, 1, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            entry_from_record(
                verified.record_bytes(),
                verified.txid(),
                verified.author(),
                None,
                1,
                2
            )
            .unwrap()
            .is_none()
        );
    }
    let records = [
        MultipartRecord::Data(DataPart {
            index: 0,
            payload: b"data".to_vec(),
        })
        .encode()
        .unwrap(),
        PublicRecord::ProfileRecord {
            profile: *b"PROFILE1",
            payload: vec![0xFF; 129],
        }
        .encode()
        .unwrap(),
    ];
    let reader = MemoryReader::new(records.iter().map(|raw| Proof::signed(raw)).collect());
    for proof in &reader.proofs {
        let verified = proof.verified();
        assert!(
            entry_from_verified(&verified, None, 1, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            entry_from_record(
                verified.record_bytes(),
                verified.txid(),
                verified.author(),
                None,
                1,
                2
            )
            .unwrap()
            .is_none()
        );
    }
    assert!(reader.scan().entries.is_empty());
}

#[test]
fn authenticated_malformed_wire_payloads_are_errors_and_never_scanned() {
    let malformed = [
        (RecordKind::Post, vec![0xFF]),
        (RecordKind::Reply, vec![0; 31]),
        (RecordKind::Profile, vec![b'x'; 129]),
        (RecordKind::Profile, "ț".repeat(65).into_bytes()),
        (RecordKind::Avatar, vec![0; 127]),
        (RecordKind::Avatar, vec![0; 129]),
        (RecordKind::Avatar, vec![0; 512]),
        (RecordKind::WirePost, vec![1, b'A', 0, 0, 0]),
        (RecordKind::WireReply, vec![0; 31]),
    ];
    let mut proofs = Vec::new();
    for (kind, body) in malformed {
        let raw = [kind.prefix().to_vec(), body].concat();
        let proof = Proof::signed(&raw);
        let verified = proof.verified();
        assert_eq!(verified.record_bytes(), raw);
        assert!(PublicRecord::decode(&raw).is_err());
        assert!(matches!(
            entry_from_verified(&verified, None, 42, 1),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            entry_from_record(&raw, verified.txid(), verified.author(), None, 42, 1),
            Err(Error::Protocol(_))
        ));
        if kind == RecordKind::Profile || raw.len() == Urma::PREFIX_BYTES + 512 {
            assert!(decode_cached(&raw).is_ok());
        }
        proofs.push(proof);
    }
    assert!(MemoryReader::new(proofs).scan().entries.is_empty());
}

#[test]
fn record_projection_preserves_caller_metadata_without_authenticating_identity() {
    let raw = PublicRecord::Post("valid payload".into()).encode().unwrap();
    let proof = Proof::signed(&raw);
    let verified = proof.verified();
    let caller_txid = Txid::from_byte_array([0xCD; 32]);
    let caller_author = Keypair::from_seckey_slice(&Secp256k1::new(), &[9; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    assert_ne!(caller_txid, verified.txid());
    assert_ne!(caller_author, verified.author());

    let projected = entry_from_record(&raw, caller_txid, caller_author, None, u64::MAX, u32::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(projected.txid, caller_txid.to_string());
    assert_eq!(projected.author, caller_author.to_string());
    assert_eq!((projected.height, projected.position), (u64::MAX, u32::MAX));
    assert_eq!(hex::decode(&projected.record).unwrap(), raw);

    let authenticated = entry_from_verified(&verified, None, 42, 1)
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.txid, verified.txid().to_string());
    assert_eq!(authenticated.author, verified.author().to_string());
    assert_eq!(authenticated.record, projected.record);
    for malformed in [&[][..], b"junk".as_slice()] {
        assert!(matches!(
            entry_from_record(malformed, caller_txid, caller_author, None, 42, 1),
            Err(Error::Protocol(_))
        ));
    }
}

#[test]
fn scanner_requires_the_author_proof_before_projecting_a_valid_payload() {
    let raw = PublicRecord::Post("valid payload".into()).encode().unwrap();
    let mut proof = Proof::signed(&raw);
    let mut witness: Vec<Vec<u8>> = proof.reveal.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    witness[0][0] ^= 1;
    proof.reveal.input[0].witness = Witness::from_slice(&witness);
    assert!(envelope::extract_reveal(&proof.reveal).is_ok());
    assert!(
        VerifiedRecord::verify(proof.reveal.compute_txid(), &proof.reveal, &proof.commit).is_err()
    );
    assert!(MemoryReader::new(vec![proof]).scan().entries.is_empty());
}
