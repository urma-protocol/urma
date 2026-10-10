// SPDX-License-Identifier: 0BSD
// Independent signed corpus: untrusted witness bytes cannot establish a signed
// manifest contradiction until actual transaction authentication has succeeded.
use bitcoin::{Transaction, Witness, consensus::deserialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use urma_core::{
    envelope,
    multipart::{MultipartRecord, RecordRequest, VerifiedRecord},
};

const HASH_MISMATCH: &str = "record hash differs from the signed manifest reference";

struct Fixture {
    commit: Transaction,
    reveal: Transaction,
    record: Vec<u8>,
}

fn fixture(name: &str) -> Fixture {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/multipart");
    let manifest: Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    let case = manifest["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    assert_eq!(case["outcome"], "valid", "{name}");
    let artifact = |field: &str| {
        let descriptor = &case[field];
        let bytes = fs::read(directory.join(descriptor["file"].as_str().unwrap())).unwrap();
        assert_eq!(bytes.len() as u64, descriptor["bytes"].as_u64().unwrap());
        assert_eq!(hex::encode(Sha256::digest(&bytes)), descriptor["sha256"]);
        bytes
    };
    let reveal: Transaction = deserialize(&artifact("reveal")).unwrap();
    assert_eq!(reveal.compute_txid().to_string(), case["txid"]);
    Fixture {
        commit: deserialize(&artifact("commit")).unwrap(),
        reveal,
        record: artifact("record"),
    }
}

fn verified(fixture: &Fixture) -> VerifiedRecord {
    let result = VerifiedRecord::verify(
        fixture.reveal.compute_txid(),
        &fixture.reveal,
        &fixture.commit,
    )
    .unwrap();
    assert_eq!(result.record_bytes(), fixture.record);
    result
}

// The request comes from a genuinely authenticated parent, not an invented
// reference. For a data edge, authenticate the root -> leaf chain as well.
fn signed_edge(graph: &str, child_is_leaf: bool) -> (RecordRequest, Fixture) {
    let root = verified(&fixture(&format!("{graph}-root")));
    let MultipartRecord::Root(manifest) = root.decode().unwrap() else {
        panic!("expected signed root")
    };
    let leaf_request = RecordRequest {
        reference: manifest.entries[0],
    };
    let leaf_fixture = fixture(&format!("{graph}-leaf"));
    let leaf = verified(&leaf_fixture);
    leaf_request.check_txid(&leaf).unwrap();
    assert_eq!(leaf.author(), root.author());
    if child_is_leaf {
        return (leaf_request, leaf_fixture);
    }
    leaf_request.check_hash(&leaf).unwrap();
    let MultipartRecord::Leaf(manifest) = leaf.decode().unwrap() else {
        panic!("expected signed leaf")
    };
    let part_fixture = fixture(&format!("{graph}-part-0"));
    assert_eq!(verified(&part_fixture).author(), leaf.author());
    (
        RecordRequest {
            reference: manifest.entries[0],
        },
        part_fixture,
    )
}

fn altered_record_witness(fixture: &Fixture) -> (Transaction, Vec<u8>) {
    let author = verified(fixture).author();
    let mut altered_bytes = fixture.record.clone();
    *altered_bytes.last_mut().unwrap() ^= 1;
    // A payload byte or reference hash byte changes, retaining a valid codec and
    // canonical script. Keep the original signature/control/actual prevout.
    MultipartRecord::decode(&altered_bytes).unwrap();
    let (script, _) = envelope::build_for_author(&altered_bytes, author).unwrap();
    let mut witness: Vec<Vec<u8>> = fixture.reveal.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    witness[1] = script.into_bytes();
    let mut altered = fixture.reveal.clone();
    altered.input[0].witness = Witness::from_slice(&witness);
    assert_eq!(altered.compute_txid(), fixture.reveal.compute_txid());
    assert_ne!(altered.compute_wtxid(), fixture.reveal.compute_wtxid());
    assert_eq!(
        altered.input[0].previous_output,
        fixture.reveal.input[0].previous_output
    );
    assert_eq!(
        envelope::extract_reveal(&altered).unwrap().record,
        altered_bytes
    );
    (altered, altered_bytes)
}

#[test]
fn canonical_same_txid_witness_cannot_establish_a_manifest_hash_contradiction() {
    for child_is_leaf in [false, true] {
        let (request, authentic) = signed_edge("one", child_is_leaf);
        let (altered, record) = altered_record_witness(&authentic);
        assert_ne!(
            <[u8; 32]>::from(Sha256::digest(&record)),
            request.reference.record_hash
        );
        assert_eq!(altered.compute_txid(), request.reference.txid);
        // Shape, codec, TXID and spent outpoint pass. Failure is the actual
        // Taproot commitment, rather than an irrelevant early guard or hash.
        let cause = request.verify(&altered, &authentic.commit).unwrap_err();
        assert_eq!(cause.to_string(), "invalid Taproot commitment");
        assert!(!cause.to_string().contains(HASH_MISMATCH));
        // Same request accepts the genuine candidate afterward. The core API
        // carries no poisoned state; runtime owns origin selection and retries.
        let recovered = request
            .verify(&authentic.reveal, &authentic.commit)
            .unwrap();
        request.check_txid(&recovered).unwrap();
        request.check_hash(&recovered).unwrap();
        assert_eq!(recovered.record_bytes(), authentic.record);
    }
}

#[test]
fn genuine_signed_manifest_hash_mismatch_is_checked_after_candidate_proof() {
    for (graph, child_is_leaf) in [("wrong-child-hash", false), ("wrong-leaf-hash", true)] {
        let (request, authentic) = signed_edge(graph, child_is_leaf);
        let (altered, record) = altered_record_witness(&authentic);
        assert_ne!(
            <[u8; 32]>::from(Sha256::digest(&record)),
            request.reference.record_hash
        );
        let cause = request.verify(&altered, &authentic.commit).unwrap_err();
        assert_eq!(cause.to_string(), "invalid Taproot commitment");
        // An authenticated candidate with the same requested TXID succeeds at
        // proof validation despite this reference's deliberately wrong hash.
        let candidate = request
            .verify(&authentic.reveal, &authentic.commit)
            .unwrap();
        assert_eq!(candidate.record_bytes(), authentic.record);
        request.check_txid(&candidate).unwrap();
        assert_ne!(
            candidate.reference().record_hash,
            request.reference.record_hash
        );
        assert_eq!(
            request.check_hash(&candidate).unwrap_err().to_string(),
            HASH_MISMATCH
        );
        // Compare with the correct hash of those same authenticated bytes: only
        // the signed reference hash differs, not format, author, TXID or proof.
        RecordRequest {
            reference: candidate.reference(),
        }
        .check_hash(&candidate)
        .unwrap();
    }
}

#[test]
fn invalid_bip340_signature_precedes_a_real_signed_manifest_hash_mismatch() {
    for (graph, child_is_leaf) in [("wrong-child-hash", false), ("wrong-leaf-hash", true)] {
        let (request, authentic) = signed_edge(graph, child_is_leaf);
        let original: Vec<Vec<u8>> = authentic.reveal.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        let mut witness = original.clone();
        assert_eq!(witness[0].len(), 64);
        witness[0][63] ^= 1;
        bitcoin::secp256k1::schnorr::Signature::from_slice(&witness[0]).unwrap();
        assert_eq!(witness[1..], original[1..]);
        let mut altered = authentic.reveal.clone();
        altered.input[0].witness = Witness::from_slice(&witness);
        assert_eq!(altered.compute_txid(), authentic.reveal.compute_txid());
        assert_eq!(altered.compute_txid(), request.reference.txid);
        assert_ne!(altered.compute_wtxid(), authentic.reveal.compute_wtxid());
        assert_eq!(
            altered.input[0].previous_output,
            authentic.reveal.input[0].previous_output
        );
        assert_eq!(
            envelope::extract_reveal(&altered).unwrap().record,
            authentic.record
        );
        assert_ne!(
            <[u8; 32]>::from(Sha256::digest(&authentic.record)),
            request.reference.record_hash
        );
        // The complete proof of the unchanged script/commitment succeeds when
        // only the genuine signature is restored. The wrong signed hash remains.
        let candidate = request
            .verify(&authentic.reveal, &authentic.commit)
            .unwrap();
        assert_eq!(
            request.check_hash(&candidate).unwrap_err().to_string(),
            HASH_MISMATCH
        );
        let cause = request.verify(&altered, &authentic.commit).unwrap_err();
        match cause {
            urma_core::error::Error::Context { message, .. } => {
                assert_eq!(message, "invalid author signature");
            }
            other => panic!("signature-only alteration failed at an irrelevant guard: {other}"),
        }
    }
}
