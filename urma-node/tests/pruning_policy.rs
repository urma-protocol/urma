//! Retention policy through public Engine APIs and exact durable transaction bytes.
//! Public vectors and locally signed valid records authenticate URMA bytes. The
//! witness-authenticated mock blocks make no PoW, UTXO or full-consensus claim.
//! Retaining a Names claim does not apply registry rules or establish its state.

#[allow(dead_code)]
mod common;

use bitcoin::{
    Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute,
    consensus::{deserialize, serialize},
    hashes::{Hash, sha256},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
};
use common::*;
use std::{collections::BTreeMap, sync::Arc};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind},
    multipart::VerifiedRecord,
    topics::Topics,
};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveStatus, RecordPackage, Retention},
};

// The signing steps follow urma-names/tests/projection.rs. Here the public
// codec and envelope builder validate the payload before signing; no fabricated
// VerifiedRecord, extra dependency, funding network or shared helper edit.
fn sign_public(record: PublicRecord) -> SignedPair {
    let bytes = record.encode().unwrap();
    assert_eq!(PublicRecord::decode(&bytes).unwrap(), record);
    let secp = Secp256k1::new();
    let signer = Keypair::from_seckey_slice(&secp, &[4; 32]).unwrap();
    let (script, info) = envelope::build(&bytes, &signer).unwrap();
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
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(verified.record_bytes(), bytes);
    envelope::verify_reveal(&reveal, &commit).unwrap();
    SignedPair {
        raw_commit: serialize(&commit),
        raw_reveal: serialize(&reveal),
        commit,
        reveal,
        verified,
    }
}

struct Corpus {
    retained: Vec<SignedPair>,
    children: [SignedPair; 2],
    container: SignedPair,
}

impl Corpus {
    fn load() -> Self {
        let mut retained: Vec<_> = [
            "proof-private",
            "proof-post-max",
            "proof-reply",
            "proof-profile-utf8-two-byte128",
            "proof-avatar-ega16-reference",
        ]
        .into_iter()
        .map(SignedPair::load)
        .collect();
        let topics = Topics {
            wire: "news".into(),
            hashtags: vec!["local".into(), "urma".into()],
        };
        retained.push(sign_public(PublicRecord::WirePost {
            topics: topics.clone(),
            text: "retained structured post".into(),
        }));
        retained.push(sign_public(PublicRecord::WireReply {
            target: retained[1].reveal.compute_txid(),
            topics,
            text: "retained structured reply".into(),
        }));

        // This is the unchanged valid Names V0 claim corpus, not the generic
        // proof-profile-record vector whose opaque payload is not a Names claim.
        let names = vector("names/claim.record");
        let manifest: serde_json::Value =
            serde_json::from_slice(&vector("names/manifest.json")).unwrap();
        let claim = manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "claim")
            .unwrap();
        assert_eq!(claim["outcome"], "valid");
        assert_eq!(
            claim["record"]["bytes"].as_u64(),
            Some(u64::try_from(names.len()).unwrap())
        );
        assert_eq!(
            claim["record"]["sha256"],
            sha256::Hash::hash(&names).to_string()
        );
        let record = PublicRecord::decode(&names).unwrap();
        let PublicRecord::ProfileRecord { profile, .. } = &record else {
            panic!("Names ProfileRecord fixture")
        };
        assert_eq!(profile, b"URMANAM1");
        let names_pair = sign_public(record);
        assert_eq!(names_pair.verified.record_bytes(), names);
        retained.push(names_pair);
        // Retain both roots, even though neither has been reconstructed/pinned.
        retained.push(SignedPair::load("multipart/one-root"));
        retained.push(SignedPair::load("multipart/empty-root"));

        let kinds: Vec<_> = retained
            .iter()
            .map(|pair| RecordKind::parse(pair.verified.record_bytes()).unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                RecordKind::Private,
                RecordKind::Post,
                RecordKind::Reply,
                RecordKind::Profile,
                RecordKind::Avatar,
                RecordKind::WirePost,
                RecordKind::WireReply,
                RecordKind::ProfileRecord,
                RecordKind::RootManifest,
                RecordKind::RootManifest,
            ]
        );
        assert_eq!(retained[0].verified.record_bytes().len(), 32_928);
        assert_eq!(retained[1].verified.record_bytes().len(), 32_768);
        for pair in &retained {
            envelope::verify_reveal(&pair.reveal, &pair.commit).unwrap();
        }
        let children = ["multipart/one-leaf", "multipart/one-part-0"].map(SignedPair::load);
        for (pair, kind) in children
            .iter()
            .zip([RecordKind::LeafManifest, RecordKind::DataPart])
        {
            assert_eq!(
                RecordKind::parse(pair.verified.record_bytes()).unwrap(),
                kind
            );
            assert!(pair.verified.record_bytes().len() < 128);
            envelope::verify_reveal(&pair.reveal, &pair.commit).unwrap();
        }

        // Authentication succeeds for this genuine signed negative vector.
        // VerifiedRecord alone authenticates bytes; V0 admission rejects the
        // offline Container wrapper before retention policy is applied.
        let container = SignedPair::load("proof-offline-container");
        assert_eq!(
            RecordKind::parse(container.verified.record_bytes()).unwrap(),
            RecordKind::Container
        );
        let error = envelope::verify_reveal(&container.reveal, &container.commit)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("offline container cannot be published")
        );
        Self {
            retained,
            children,
            container,
        }
    }

    fn publishable(&self) -> impl Iterator<Item = &SignedPair> {
        self.retained.iter().chain(&self.children)
    }

    fn block(&self, missing_commits: bool) -> Block {
        let transactions: Vec<_> = self
            .publishable()
            .chain(std::iter::once(&self.container))
            .flat_map(|pair| {
                if missing_commits {
                    vec![pair.reveal.clone()]
                } else {
                    pair.transactions().to_vec()
                }
            })
            .collect();
        witness_block(&transactions, None, 71)
    }
}

fn package(block: &Block, pair: &SignedPair) -> RecordPackage {
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
        .unwrap();
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(FIRST_HEIGHT, block),
        reveal: TransactionProof::from_block(
            block,
            u32::try_from(position).unwrap(),
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

fn assert_exact(engine: &Engine, block: &Block, pair: &SignedPair) {
    let archived = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
    let expected = package(block, pair);
    assert_eq!(archived.receipt.generation, 0);
    assert_eq!(archived.receipt.txid, pair.reveal.compute_txid());
    assert_eq!(archived.receipt.wtxid, pair.reveal.compute_wtxid());
    assert_eq!(archived.receipt.block, expected.block);
    assert_eq!(archived.receipt.position, expected.reveal.txid_path.index);
    assert_eq!(archived.package.commit, pair.raw_commit);
    assert_eq!(archived.package.reveal.transaction, pair.raw_reveal);
    assert_eq!(
        serde_json::to_value(&archived.package).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    let included = archived
        .package
        .reveal
        .verify(Chain::BitcoinRegtest, &block.header)
        .unwrap();
    assert_eq!(included.raw(), pair.raw_reveal);
    let commit: Transaction = deserialize(&archived.package.commit).unwrap();
    let verified = VerifiedRecord::verify(
        included.transaction().compute_txid(),
        included.transaction(),
        &commit,
    )
    .unwrap();
    assert_eq!(verified.record_bytes(), pair.verified.record_bytes());
    assert_eq!(verified.author(), pair.verified.author());
}

fn expected_bytes<'a>(
    pairs: impl IntoIterator<Item = &'a SignedPair>,
) -> BTreeMap<String, Vec<u8>> {
    let mut expected = BTreeMap::new();
    for pair in pairs {
        for (tx, raw) in [
            (&pair.commit, &pair.raw_commit),
            (&pair.reveal, &pair.raw_reveal),
        ] {
            assert!(
                expected
                    .insert(tx.compute_wtxid().to_string(), raw.clone())
                    .is_none()
            );
        }
    }
    expected
}

fn assert_coverage(status: &ArchiveStatus, block: &Block) {
    assert_eq!(status.generation, 0);
    assert_eq!(status.selected_tip, Some(point(FIRST_HEIGHT, block)));
    assert_eq!(status.indexed_through, Some(point(FIRST_HEIGHT, block)));
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.unresolved_dependencies, 0);
}

fn exercise_policy(retention: Retention, missing_commits: bool) {
    let corpus = Corpus::load();
    let block = corpus.block(missing_commits);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let config = config(&block, retention);
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();

    // A selective proof cannot bypass the same offline-only Container rule.
    match engine.admit_record(package(&block, &corpus.container)) {
        Err(Error::Invalid(message)) => {
            assert!(message.contains("offline container cannot be published"))
        }
        other => panic!("expected V0 Container rejection, got {other:?}"),
    }
    assert_eq!(engine.status().unwrap().stored_transactions, 0);
    let scanned = engine.scan_next().unwrap();
    if missing_commits {
        assert_eq!(
            scanned.unresolved_dependencies,
            corpus.publishable().count() as u64
        );
        assert_eq!(scanned.stored_transactions, 0);
        assert!(scanned.indexed_through.is_none());
        // Exercise the dependency-completion retention path without rescanning
        // or fabricating a commit placement: these parents are auxiliary bytes.
        for pair in corpus.publishable() {
            assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 1);
        }
        assert_eq!(
            engine.resolve_commit(&corpus.container.raw_commit).unwrap(),
            0
        );
    }
    assert_coverage(&engine.status().unwrap(), &block);
    let children_retained = retention == Retention::Unpruned;
    let retained_bytes = expected_bytes(&corpus.retained);
    assert_eq!(
        engine.status().unwrap().stored_transactions,
        if children_retained {
            expected_bytes(corpus.publishable()).len() as u64
        } else {
            retained_bytes.len() as u64
        }
    );
    for pair in &corpus.retained {
        assert_exact(&engine, &block, pair);
    }
    for child in &corpus.children {
        assert_eq!(
            engine
                .record(child.reveal.compute_txid())
                .unwrap()
                .is_some(),
            children_retained
        );
    }
    assert!(
        engine
            .record(corpus.container.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    for root in &corpus.retained[8..] {
        assert!(
            engine
                .object_status(root.reveal.compute_txid())
                .unwrap()
                .is_none()
        );
    }

    // Inspect exact raw transaction rows after the scan as well as after prune.
    // Close the Engine before using the shared READONLY inspection helper.
    let expected = if children_retained {
        expected_bytes(corpus.publishable())
    } else {
        retained_bytes
    };
    drop(engine);
    assert_eq!(stored_bytes(&readonly_archive(directory.path())), expected);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_eq!(engine.prune_cache().unwrap(), 0);

    // Each child is cached and pruned independently, with no reconstruction,
    // pin, size threshold or dependence on the other child's local presence.
    for child in &corpus.children {
        engine.admit_record(package(&block, child)).unwrap();
        assert_exact(&engine, &block, child);
        assert_eq!(
            engine.prune_cache().unwrap(),
            if children_retained { 0 } else { 1 }
        );
        for pair in &corpus.retained {
            assert_exact(&engine, &block, pair);
        }
        assert_eq!(
            engine
                .record(child.reveal.compute_txid())
                .unwrap()
                .is_some(),
            children_retained
        );
        assert_coverage(&engine.status().unwrap(), &block);
    }
    assert_eq!(engine.prune_cache().unwrap(), 0);
    let before_restart = engine.status().unwrap();
    assert_eq!(
        source.body_calls.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    drop(engine);
    assert_eq!(stored_bytes(&readonly_archive(directory.path())), expected);

    // Reopen offline. Exact commits/reveals, all roots and scan coverage survive;
    // pruned children remain absent rather than being fetched during the check.
    let engine = Engine::open(directory.path(), config, None).unwrap();
    assert_eq!(
        serde_json::to_value(engine.status().unwrap()).unwrap(),
        serde_json::to_value(before_restart).unwrap()
    );
    assert_eq!(engine.prune_cache().unwrap(), 0);
    for pair in &corpus.retained {
        assert_exact(&engine, &block, pair);
    }
    for child in &corpus.children {
        if children_retained {
            assert_exact(&engine, &block, child);
        } else {
            assert!(
                engine
                    .record(child.reveal.compute_txid())
                    .unwrap()
                    .is_none()
            );
        }
    }
    assert!(
        engine
            .record(corpus.container.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    drop(engine);
    assert_eq!(stored_bytes(&readonly_archive(directory.path())), expected);
}

#[test]
fn pruned_keeps_all_individual_kinds_and_roots_but_evicts_only_multipart_children() {
    // Both scan admission and later commit resolution preserve the same kinds.
    for missing_commits in [false, true] {
        exercise_policy(Retention::Pruned, missing_commits);
    }
}

#[test]
fn unpruned_keeps_children_and_prune_is_noop_across_restart() {
    exercise_policy(Retention::Unpruned, false);
}
