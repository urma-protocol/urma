// SPDX-License-Identifier: 0BSD
// Known answers generated with Python stdlib HMAC and OpenSSL AES, never with
// the Rust encoder. Keep strict container acceptance distinct from recovery.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use urma_core::{
    container::{self, RecordMatch},
    error::Error,
};

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors")
}

fn corpus() -> Value {
    serde_json::from_slice(&fs::read(vectors().join("recovery/manifest.json")).unwrap()).unwrap()
}

fn artifact(value: &Value) -> Vec<u8> {
    let bytes = fs::read(vectors().join(value["file"].as_str().unwrap())).unwrap();
    assert_eq!(bytes.len() as u64, value["bytes"].as_u64().unwrap());
    assert_eq!(hex::encode(Sha256::digest(&bytes)), value["sha256"]);
    bytes
}

fn root(name: &str) -> [u8; 32] {
    fs::read(vectors().join(name)).unwrap().try_into().unwrap()
}

#[test]
fn independently_authenticated_record_oracles() {
    let corpus = corpus();
    let root = root(corpus["root"].as_str().unwrap());
    for (name, oracle) in corpus["records"].as_object().unwrap() {
        let record = artifact(&oracle["artifact"]);
        assert_eq!(record.len(), 32928, "{name}");
        // Independently check that semantic-invalid records really carry a
        // valid HMAC: otherwise successful skipping could hide MAC-only tests.
        let mut auth = [0; 32];
        Hkdf::<Sha256>::new(Some(&record[8..40]), &root)
            .expand(b"URMA/V0/private/authentication", &mut auth)
            .unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&auth).unwrap();
        mac.update(&record[..32896]);
        assert_eq!(
            mac.verify_slice(&record[32896..]).is_ok(),
            oracle["mac_valid_for_root"].as_bool().unwrap(),
            "{name}: independent HMAC oracle"
        );
        match (
            oracle["disposition"].as_str().unwrap(),
            container::open_record(&root, &record),
        ) {
            ("valid", Ok(RecordMatch::Authenticated(_)))
            | ("unrelated", Ok(RecordMatch::Unrelated))
            | ("invalid", Err(Error::Invalid(_) | Error::Unsupported(_))) => {}
            _ => panic!("{name}: record classification differs from the independent oracle"),
        }
    }
}

#[test]
fn independent_recovery_answers_and_strict_baseline() {
    let corpus = corpus();
    for case in corpus["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bytes = artifact(&case["container"]);
        let root = root(case["root"].as_str().unwrap());
        let expected = &case["expected"];
        if expected["status"] != "framing" {
            // Bind fixture descriptions and counters to the actual byte input.
            let mut packed = b"URMA\x00\x03\x00\x00".to_vec();
            let names = case["records"].as_array().unwrap();
            packed.extend_from_slice(&(names.len() as u32).to_le_bytes());
            let (mut valid, mut unrelated, mut invalid) = (0_u64, 0_u64, 0_u64);
            for name in names {
                let oracle = &corpus["records"][name.as_str().unwrap()];
                let record = artifact(&oracle["artifact"]);
                packed.extend_from_slice(&(record.len() as u32).to_le_bytes());
                packed.extend_from_slice(&record);
                match container::open_record(&root, &record) {
                    Ok(RecordMatch::Authenticated(_)) => valid += 1,
                    Ok(RecordMatch::Unrelated) => unrelated += 1,
                    Err(Error::Invalid(_) | Error::Unsupported(_)) => invalid += 1,
                    Err(error) => panic!("{name}: unexpected candidate error: {error}"),
                }
            }
            assert_eq!(
                packed, bytes,
                "{name}: manifest record sequence differs from fixture"
            );
            assert_eq!(valid, expected["valid_records"].as_u64().unwrap(), "{name}");
            assert_eq!(
                unrelated,
                expected["skipped_unrelated"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                invalid,
                expected["rejected_records"].as_u64().unwrap(),
                "{name}"
            );
        }
        let recovered = container::recover_container(&root, &bytes);
        if expected["status"] == "complete" {
            let result = recovered.unwrap_or_else(|error| panic!("{name}: {error}"));
            let object = &expected["object"];
            assert_eq!(
                result.bytes.as_slice(),
                artifact(&object["original"]),
                "{name}"
            );
            assert_eq!(hex::encode(result.id), object["id"], "{name}");
            assert_eq!(
                u64::from(result.count),
                object["count"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(result.total, object["total"].as_u64().unwrap(), "{name}");
            assert_eq!(hex::encode(result.digest), object["digest"], "{name}");
            assert_eq!(
                u64::from(result.content_type.code()),
                object["content_type"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                result.skipped_unrelated as u64,
                expected["skipped_unrelated"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                result.rejected_records as u64,
                expected["rejected_records"].as_u64().unwrap(),
                "{name}"
            );
        } else {
            let error = match recovered {
                Ok(_) => panic!("{name}: exported an object on a fatal condition"),
                Err(error) => error,
            };
            let required = match expected["status"].as_str().unwrap() {
                "no-object" => "no authenticated object",
                "mixed" => "multiple authenticated objects",
                "incomplete" => "incomplete object",
                "conflict" => "conflicting authenticated",
                "hash-mismatch" => "whole-file integrity",
                "framing" => "",
                status => panic!("{name}: unknown expected status {status}"),
            };
            let framing_overflow = expected["status"] == "framing"
                && matches!(&error, Error::Missing(message) if message == "container size overflow");
            assert!(
                matches!(&error, Error::Invalid(_) | Error::Unsupported(_)) || framing_overflow,
                "{name}: {error}"
            );
            assert!(
                error.to_string().contains(required),
                "{name}: wrong failure: {error}"
            );
        }
        // A recovered object does not make its source a canonical container.
        // In particular skipped candidates must still fail supplied-input open.
        let strict = container::unpack(&bytes).and_then(|records| container::open(&root, &records));
        if case["strict_status"] == "complete" {
            assert_eq!(
                strict.unwrap().as_slice(),
                artifact(&expected["object"]["original"]),
                "{name}"
            );
        } else {
            assert!(
                strict.is_err(),
                "{name}: strict open silently tolerated the source"
            );
        }
    }
}
