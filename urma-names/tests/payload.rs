use anyhow::{Context, Result};
use bitcoin::{Txid, hashes::Hash};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use urma_core::format::{PublicRecord, RecordKind};
use urma_names::{
    name::Name,
    payload::{Genesis, Mode, OwnerOp, Payload},
};

fn vectors() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/vectors/names")
}

fn manifest() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        vectors().join("manifest.json"),
    )?)?)
}

fn artifact(case: &Value) -> Result<Vec<u8>> {
    let record = &case["record"];
    let bytes = fs::read(vectors().join(record["file"].as_str().context("file")?))?;
    assert_eq!(
        bytes.len() as u64,
        record["bytes"].as_u64().context("bytes")?
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        record["sha256"].as_str().context("sha256")?
    );
    Ok(bytes)
}

fn decoded(case: &Value) -> Result<Payload> {
    Payload::from_record(&PublicRecord::decode(&artifact(case)?)?)
        .with_context(|| case["name"].to_string())
}

#[test]
fn independent_corpus_decodes_valid_records_and_re_encodes_them_exactly() -> Result<()> {
    let corpus = manifest()?;
    let mut valid = 0;
    let mut invalid = 0;
    for case in corpus["cases"].as_array().context("cases")? {
        let bytes = artifact(case)?;
        let public = PublicRecord::decode(&bytes)?;
        assert_eq!(public.kind(), RecordKind::ProfileRecord);
        let result = Payload::from_record(&public);
        match case["outcome"].as_str().context("outcome")? {
            "valid" => {
                let payload = result.with_context(|| case["name"].to_string())?;
                assert_eq!(payload.to_record()?.encode()?, bytes, "{}", case["name"]);
                valid += 1;
            }
            "invalid" | "foreign" => {
                assert!(result.is_err(), "accepted {}", case["name"]);
                invalid += 1;
            }
            other => panic!("unknown outcome {other}"),
        }
    }
    assert_eq!((valid, invalid), (14, 39));
    Ok(())
}

#[test]
fn layouts_place_every_field_and_keep_txid_wire_order() -> Result<()> {
    let corpus = manifest()?;
    for case in corpus["cases"].as_array().context("cases")? {
        let expect = &case["expect"];
        if expect.is_null() {
            continue;
        }
        match decoded(case)? {
            Payload::Genesis(genesis) => {
                let mode = match genesis.mode {
                    Mode::Open => "open",
                    Mode::Administered => "administered",
                };
                assert_eq!(mode, expect["mode"]);
                assert_eq!(u64::from(genesis.expiry_blocks), expect["expiry_blocks"]);
                assert_eq!(
                    u64::from(genesis.reveal_max_blocks),
                    expect["reveal_max_blocks"]
                );
                assert_eq!(u64::from(genesis.threshold), expect["threshold"]);
                let approvers: Vec<Value> = genesis
                    .approvers
                    .iter()
                    .map(|key| Value::from(hex::encode(key.serialize())))
                    .collect();
                assert_eq!(Value::from(approvers), expect["approvers"]);
            }
            Payload::Claim(op) => {
                assert_eq!(op.registry.to_string(), expect["registry"]);
                assert_eq!(hex::encode(op.salt), expect["salt"]);
                assert_eq!(op.name.as_str(), expect["name"]);
                assert_eq!(op.target.to_string(), expect["target"]);
            }
            Payload::Approve(approval) => {
                assert_eq!(approval.registry.to_string(), expect["registry"]);
                assert_eq!(approval.record_txid.to_string(), expect["record_txid"]);
                assert_eq!(hex::encode(approval.record_sha256), expect["record_sha256"]);
            }
            other => panic!("unexpected expectation for {other:?}"),
        }
    }
    let claim = decoded(
        corpus["cases"]
            .as_array()
            .context("cases")?
            .iter()
            .find(|case| case["name"] == "claim")
            .context("claim case")?,
    )?;
    let bytes = claim.encode()?;
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1..33], (0x40u8..0x60).collect::<Vec<u8>>()[..]);
    assert_eq!(bytes[50..57], *b"atelier");
    assert_eq!(bytes.len(), OwnerOp::FIXED_BYTES + 1 + 7);
    Ok(())
}

#[test]
fn name_grammar_normalization_and_genesis_bounds() -> Result<()> {
    for text in ["a", "0", "a-b", "a--b", "xn-a", "abc--d", &"x".repeat(63)] {
        assert_eq!(Name::parse(text)?.as_str(), text);
    }
    for text in [
        "",
        "-a",
        "a-",
        "ab--cd",
        "A",
        "a_b",
        "a.b",
        "a b",
        "ș",
        &"x".repeat(64),
    ] {
        assert!(Name::parse(text).is_err(), "{text:?}");
    }
    assert_eq!(Name::normalize("Atelier-X")?.as_str(), "atelier-x");
    assert!(Name::normalize("Ate lier").is_err());
    let open = Genesis {
        mode: Mode::Open,
        expiry_blocks: 145,
        reveal_max_blocks: 144,
        threshold: 0,
        approvers: Vec::new(),
    };
    open.validate()?;
    let mut bad = open.clone();
    bad.expiry_blocks = 144;
    assert!(bad.validate().is_err());
    assert!(Payload::Genesis(bad).encode().is_err());
    let mut bad = open.clone();
    bad.threshold = 1;
    assert!(bad.validate().is_err());
    assert!(Payload::decode(&[]).is_err());
    assert!(Payload::decode(&[7]).is_err());
    let post = PublicRecord::Post("x".into());
    assert!(Payload::from_record(&post).is_err());
    let op = OwnerOp {
        registry: Txid::from_byte_array([1; 32]),
        salt: [0; 16],
        name: Name::parse("shop")?,
        target: Txid::from_byte_array([0; 32]),
    };
    assert!(op.is_reserving());
    let record = Payload::Renew(op).to_record()?;
    let PublicRecord::ProfileRecord { profile, payload } = &record else {
        panic!("not a profile record")
    };
    assert_eq!(profile, b"URMANAM1");
    assert_eq!(payload.len(), OwnerOp::FIXED_BYTES + 1 + 4);
    assert_eq!(Payload::from_record(&record)?.op(), 3);
    Ok(())
}
