// SPDX-License-Identifier: 0BSD
// UTF-8 byte oracles and signed Taproot fixtures produced independently of Rust.
use bitcoin::{Transaction, consensus::deserialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors")
}

fn artifact(value: &Value) -> Vec<u8> {
    let bytes = fs::read(vectors().join(value["file"].as_str().unwrap())).unwrap();
    assert_eq!(bytes.len() as u64, value["bytes"].as_u64().unwrap());
    assert_eq!(hex::encode(Sha256::digest(&bytes)), value["sha256"]);
    bytes
}

fn corpus() -> (Value, Value) {
    let manifest: Value =
        serde_json::from_slice(&fs::read(vectors().join("manifest.json")).unwrap()).unwrap();
    let reference = serde_json::from_slice(&artifact(&manifest["profile_reference"])).unwrap();
    (manifest, reference)
}

#[test]
fn independent_profile_utf8_byte_limits_and_exact_encoding() {
    let (_, reference) = corpus();
    assert_eq!(Urma::MAX_PROFILE_BYTES, 128);
    assert_eq!(reference["maximum_body_bytes"], 128);
    assert_eq!(reference["minimum_record_bytes"], 8);
    assert_eq!(reference["maximum_record_bytes"], 136);
    assert_eq!(reference["normalization"], "none");
    for case in reference["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let body = artifact(&case["body"]);
        let record = artifact(&case["record"]);
        assert_eq!(&record[..8], b"URMA\x00\x05\x00\x00", "{name}");
        assert_eq!(&record[8..], body, "{name}");
        let decoded = PublicRecord::decode(&record);
        if case["outcome"] == "valid" {
            let PublicRecord::Profile(text) = decoded.unwrap() else {
                panic!("{name}: wrong kind")
            };
            assert_eq!(text.as_bytes(), body, "{name}: decoder changed bytes");
            assert_eq!(text, case["text"].as_str().unwrap(), "{name}");
        } else {
            assert!(decoded.is_err(), "{name}: decoder accepted invalid profile");
        }
        if case["utf8_valid"] == true {
            // Encode the literal reference text, not a successful decoded value.
            let encoded = PublicRecord::Profile(case["text"].as_str().unwrap().to_owned()).encode();
            if case["outcome"] == "valid" {
                assert_eq!(encoded.unwrap(), record, "{name}: encoder changed bytes");
            } else {
                assert!(
                    encoded.is_err(),
                    "{name}: encoder normalized/truncated an overlong body"
                );
            }
        } else {
            assert!(
                std::str::from_utf8(&body).is_err(),
                "{name}: malformed UTF-8 fixture was valid"
            );
        }
    }
}

#[test]
fn literal_multibyte_and_normalization_oracles() {
    let (_, reference) = corpus();
    let cases = reference["cases"].as_array().unwrap();
    let body = |name: &str| artifact(&cases.iter().find(|c| c["name"] == name).unwrap()["body"]);
    // Independent literal encodings expose byte-vs-codepoint and normalization
    // mistakes even if encoder and decoder share the same wrong implementation.
    assert_eq!(body("profile-utf8-two-byte128"), [0xc8, 0x99].repeat(64));
    assert_eq!(
        body("profile-utf8-four-byte128"),
        [0xf0, 0x9f, 0x99, 0x82].repeat(32)
    );
    assert_eq!(
        body("profile-utf8-four-byte132"),
        [0xf0, 0x9f, 0x99, 0x82].repeat(33)
    );
    assert_eq!(
        body("profile-nfd128"),
        [vec![0x65, 0xcc, 0x81].repeat(42), b"ab".to_vec()].concat()
    );
    assert_eq!(
        body("profile-nfc86"),
        [vec![0xc3, 0xa9].repeat(42), b"ab".to_vec()].concat()
    );
    assert_ne!(body("profile-nfd128"), body("profile-nfc86"));
    assert_eq!(body("profile-nfd129"), [0x65, 0xcc, 0x81].repeat(43));
    assert_eq!(body("profile-nfc43"), [0xc3, 0xa9].repeat(43));
    assert_eq!(body("profile-preserve"), b" \0e\xcc\x81\r\n ");
    assert_eq!(
        std::str::from_utf8(&body("profile-utf8-two-byte128"))
            .unwrap()
            .chars()
            .count(),
        64
    );
    assert_eq!(
        std::str::from_utf8(&body("profile-utf8-four-byte128"))
            .unwrap()
            .chars()
            .count(),
        32
    );
}

#[test]
fn independent_signed_profile_proofs_obey_format_limits() {
    let (manifest, reference) = corpus();
    for case in reference["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let fixture = manifest["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == case["proof"])
            .unwrap();
        let commit: Transaction = deserialize(&artifact(&fixture["commit"])).unwrap();
        let reveal: Transaction = deserialize(&artifact(&fixture["reveal"])).unwrap();
        // Bind authentication to the actual supplied transactions and witnessed
        // bytes without invoking the PublicRecord codec. Negative format cases
        // must pass this proof check too, rather than fail for bad crypto.
        let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)
            .unwrap_or_else(|error| panic!("{name}: actual transaction proof failed: {error}"));
        assert_eq!(verified.record_bytes(), artifact(&case["record"]), "{name}");
        // Verify BIP340 independently of format acceptance, including negatives.
        let author = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &hex::decode(fixture["author"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(
            &hex::decode(fixture["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sighash: [u8; 32] = hex::decode(fixture["sighash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &bitcoin::secp256k1::Message::from_digest(sighash),
                &author,
            )
            .unwrap();
        let result = envelope::verify_reveal(&reveal, &commit);
        if case["outcome"] == "valid" {
            let parsed = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(parsed.record, artifact(&case["record"]), "{name}");
            assert_eq!(parsed.author, author, "{name}");
        } else {
            assert!(
                result.is_err(),
                "{name}: signature acceptance bypassed profile format validation"
            );
        }
    }
}
