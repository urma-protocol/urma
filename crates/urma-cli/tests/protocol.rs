use anyhow::{Context, Result};
use bitcoin::{
    Amount, ScriptBuf, Transaction, Witness,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use urma::{
    backend,
    container::{self, RecordMatch},
    envelope,
    format::{ContentType, PublicRecord, RecordKind, Urma, chunk_count},
};

fn vectors() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).join("tests/vectors")
}
fn manifest() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        vectors().join("manifest.json"),
    )?)?)
}
fn artifact(value: &Value) -> Result<Vec<u8>> {
    let bytes = fs::read(vectors().join(value["file"].as_str().context("file")?))?;
    assert_eq!(
        bytes.len() as u64,
        value["bytes"].as_u64().context("bytes")?
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        value["sha256"].as_str().context("sha256")?
    );
    Ok(bytes)
}
fn key(name: &str) -> Result<[u8; 32]> {
    Ok(fs::read(vectors().join(name))?.as_slice().try_into()?)
}

#[test]
fn independent_private_known_answers_and_negative_corpus() -> Result<()> {
    let corpus = manifest()?;
    for case in corpus["private"].as_array().context("private cases")? {
        let bytes = artifact(&case["container"])?;
        let root = key(case["root"].as_str().context("root")?)?;
        let result = container::unpack(&bytes).and_then(|records| container::open(&root, &records));
        if case["outcome"] == "complete" {
            assert_eq!(
                result?.as_slice(),
                artifact(&case["original"])?,
                "{}",
                case["name"]
            );
        } else {
            assert!(result.is_err(), "accepted {}", case["name"]);
        }
    }
    let kdf = &corpus["kdf"];
    let root = hex::decode(kdf["root"].as_str().unwrap())?;
    let id = hex::decode(kdf["object_id"].as_str().unwrap())?;
    let derivation = Hkdf::<Sha256>::new(Some(&id), &root);
    for (field, label, size) in [
        ("encryption", Urma::CONTENT_DOMAIN, 32),
        ("authentication", Urma::AUTHENTICATION_DOMAIN, 32),
        ("discovery", Urma::DISCOVERY_DOMAIN, 16),
    ] {
        let mut output = vec![0; size];
        derivation.expand(label, &mut output).unwrap();
        assert_eq!(hex::encode(output), kdf[field].as_str().unwrap());
    }
    Ok(())
}

#[test]
fn independent_system_decoder_matches_entire_private_corpus() -> Result<()> {
    let corpus = manifest()?;
    let temp = tempfile::tempdir()?;
    for name in ["root.bin", "wrong-root.bin"] {
        urma::storage::write_new(&temp.path().join(name), &fs::read(vectors().join(name))?)?;
    }
    for case in corpus["private"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let output = temp.path().join(name);
        let result = Command::new("sh")
            .arg(
                Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
                    .join("scripts/open-bundle.sh"),
            )
            .arg(temp.path().join(case["root"].as_str().unwrap()))
            .arg(vectors().join(case["container"]["file"].as_str().unwrap()))
            .arg(&output)
            .output()?;
        if case["outcome"] == "complete" {
            assert!(
                result.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(fs::read(output)?, artifact(&case["original"])?);
        } else {
            assert!(!result.status.success(), "accepted {name}");
            assert!(!output.exists(), "exported {name}");
        }
    }
    Ok(())
}

#[test]
fn private_numeric_boundaries_do_not_allocate_the_claimed_object() -> Result<()> {
    for (length, count) in [
        (1, 1),
        (32768, 1),
        (32769, 2),
        (1_048_577, 33),
        (Urma::MAX_PRIVATE_BYTES, u32::MAX),
    ] {
        assert_eq!(chunk_count(length)?, count);
    }
    for length in [0, Urma::MAX_PRIVATE_BYTES + 1, u64::MAX] {
        assert!(chunk_count(length).is_err());
    }
    let record = artifact(&manifest()?["maximum_record"])?;
    let RecordMatch::Authenticated(chunk) = container::open_record(&key("root.bin")?, &record)?
    else {
        panic!("not authenticated")
    };
    assert_eq!(chunk.total, Urma::MAX_PRIVATE_BYTES);
    assert_eq!(chunk.index, u32::MAX - 1);
    assert_eq!(chunk.count, u32::MAX);
    let object = container::PrivateObject::new(chunk);
    assert!(!object.is_complete());
    assert!(object.finish().is_err());
    Ok(())
}

#[test]
fn random_writer_preserves_bytes_hints_and_fixed_record_size() -> Result<()> {
    let root = key("root.bin")?;
    for size in [1usize, 32767, 32768, 32769, 65536, 1_048_577] {
        let input: Vec<u8> = (0..size).map(|n| u8::try_from(n % 251).unwrap()).collect();
        for hint in [
            ContentType::Opaque,
            ContentType::Text,
            ContentType::Image,
            ContentType::Audio,
            ContentType::Video,
        ] {
            let records = container::seal(&root, &input, hint)?;
            assert_eq!(records.len(), size.div_ceil(32768));
            assert!(records.iter().all(|r| r.len() == 32928));
            assert_eq!(container::open(&root, &records)?.as_slice(), input);
            let RecordMatch::Authenticated(first) = container::open_record(&root, &records[0])?
            else {
                panic!("wrong root")
            };
            assert_eq!(first.content_type, hint);
        }
    }
    let first = container::seal(&root, b"same", ContentType::Text)?;
    let second = container::seal(&root, b"same", ContentType::Text)?;
    assert_ne!(first[0], second[0]);
    assert_ne!(
        container::inspect_header(&first[0])?.id,
        container::inspect_header(&second[0])?.id
    );
    assert!(container::seal(&root, b"", ContentType::Opaque).is_err());
    Ok(())
}

#[test]
fn all_private_truncations_and_each_authenticated_region_reject() -> Result<()> {
    let record = fs::read(vectors().join("private-text.urma"))?[16..].to_vec();
    for length in 0..record.len() {
        assert!(container::inspect_header(&record[..length]).is_err());
    }
    let root = key("root.bin")?;
    for index in [
        0, 4, 5, 6, 7, 8, 39, 40, 55, 56, 59, 60, 63, 64, 79, 80, 128, 32895, 32896, 32927,
    ] {
        let mut changed = record.clone();
        changed[index] ^= 0x80;
        assert!(
            container::open(&root, &[changed]).is_err(),
            "mutation {index}"
        );
    }
    Ok(())
}

#[test]
fn conflicts_and_incomplete_objects_do_not_block_unrelated_export() -> Result<()> {
    let root = key("root.bin")?;
    let mut objects = BTreeMap::new();
    for name in ["private-padding-conflict.urma", "private-incomplete.urma"] {
        for record in container::unpack(&fs::read(vectors().join(name))?)? {
            backend::accept_record(&root, &record, &mut objects)?;
        }
    }
    let records = container::seal(&root, b"independent", ContentType::Text)?;
    let id = container::inspect_header(&records[0])?.id;
    backend::accept_record(&root, &records[0], &mut objects)?;
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("export");
    let result = backend::export(
        backend::Recovery {
            objects,
            rejected_records: 0,
            observation: backend::Observation {
                backend: backend::Family::Directory,
                locator: backend::Locator::Directory {
                    path: temp.path().into(),
                },
                evidence: backend::Evidence::LocalBytes,
                scanned_bytes: 0,
            },
        },
        &output,
    )?;
    assert!(!result.complete);
    assert_eq!(result.report["status"], "partial");
    assert_eq!(
        fs::read(output.join(format!("{}.bin", hex::encode(id))))?,
        b"independent"
    );
    assert_eq!(fs::read_dir(&output)?.count(), 1);
    Ok(())
}

#[test]
fn fixed_public_layouts_preserve_utf8_txid_order_and_limits() -> Result<()> {
    for case in manifest()?["public"].as_array().unwrap() {
        let bytes = artifact(&case["record"])?;
        let decoded = PublicRecord::decode(&bytes);
        if case["outcome"] == "valid" {
            assert_eq!(decoded?.encode()?, bytes);
        } else {
            assert!(decoded.is_err(), "{}", case["name"]);
        }
    }
    let reply = PublicRecord::decode(&fs::read(vectors().join("reply.record"))?)?;
    let PublicRecord::Reply { target, text } = reply else {
        panic!("not reply")
    };
    assert_eq!(
        target.to_string(),
        hex::encode((0u8..32).rev().collect::<Vec<_>>())
    );
    assert_eq!(text, "reply");
    for length in 0..40 {
        assert!(
            PublicRecord::decode(&fs::read(vectors().join("reply.record"))?[..length]).is_err()
        );
    }
    assert!(PublicRecord::Post("x".repeat(32761)).encode().is_err());
    assert!(
        PublicRecord::Reply {
            target,
            text: "x".repeat(32729)
        }
        .encode()
        .is_err()
    );
    assert!(PublicRecord::Profile("x".repeat(32761)).encode().is_err());
    Ok(())
}

#[test]
fn independent_taproot_proofs_match_author_record_and_transaction() -> Result<()> {
    for case in manifest()?["proofs"].as_array().unwrap() {
        let commit: Transaction = deserialize(&artifact(&case["commit"])?)?;
        let reveal: Transaction = deserialize(&artifact(&case["reveal"])?)?;
        let result = envelope::verify_reveal(&reveal, &commit);
        if case["outcome"] == "valid" {
            let parsed = result.with_context(|| format!("{}", case["name"]))?;
            assert_eq!(
                hex::encode(&parsed.record),
                case["record_hex"].as_str().unwrap()
            );
            assert_eq!(parsed.author.to_string(), case["author"].as_str().unwrap());
            assert_eq!(
                reveal.compute_txid().to_string(),
                case["txid"].as_str().unwrap()
            );
        } else {
            assert!(result.is_err(), "{}", case["name"]);
        }
    }
    Ok(())
}

#[test]
fn signatures_require_exact_prevout_transaction_control_and_witness() -> Result<()> {
    let commit: Transaction = deserialize(&fs::read(vectors().join("proof-post.commit"))?)?;
    let original: Transaction = deserialize(&fs::read(vectors().join("proof-post.reveal"))?)?;
    let prevout = &commit.output[0];
    let mut bad_amount = prevout.clone();
    bad_amount.value += Amount::from_sat(1);
    assert!(envelope::verify_prevout(&original, &bad_amount).is_err());
    for field in 0..9 {
        let mut tx = original.clone();
        match field {
            0 => tx.version = bitcoin::transaction::Version::ONE,
            1 => tx.input[0].sequence = bitcoin::Sequence::MAX,
            2 => tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
            3 => tx.output[0].value += Amount::from_sat(1),
            4 => tx.output[0].script_pubkey = ScriptBuf::new(),
            5 => tx.input[0].previous_output.vout = 1,
            6 => tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0]),
            7 => tx.output.push(tx.output[0].clone()),
            8 => tx.input.push(tx.input[0].clone()),
            _ => unreachable!(),
        }
        assert!(
            envelope::verify_reveal(&tx, &commit).is_err(),
            "field {field}"
        );
    }
    let stack: Vec<Vec<u8>> = original.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    for mutation in 0..10 {
        let mut parts = stack.clone();
        match mutation {
            0 => parts[0][0] ^= 1,
            1 => parts[0].push(0),
            2 => parts[2][0] ^= 1,
            3 => parts[2][1] ^= 1,
            4 => parts[2].extend_from_slice(&[0; 32]),
            5 => parts.push(vec![0x50]),
            6 => parts[1][33] = 0x75,
            7 => parts[2][0] = 0xc2,
            8 => parts[1].push(0),
            9 => {
                parts.remove(0);
            }
            _ => unreachable!(),
        }
        let mut tx = original.clone();
        tx.input[0].witness = Witness::from_slice(&parts);
        assert_eq!(tx.compute_txid(), original.compute_txid());
        assert!(
            envelope::verify_reveal(&tx, &commit).is_err(),
            "witness {mutation}"
        );
    }
    Ok(())
}

#[test]
fn offline_public_preparation_and_cli_never_imply_broadcast_or_inclusion() -> Result<()> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use urma::{
        journal::Funding,
        publication::{self, Chain},
    };
    let secret = SecretKey::from_slice(&[3; 32])?;
    let author = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let mut funding: Transaction = deserialize(&fs::read(vectors().join("proof-post.commit"))?)?;
    funding.output[0].script_pubkey =
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20]));
    let source = Funding {
        raw_transaction: hex::encode(serialize(&funding)),
        vout: 0,
    };
    for chain in [
        Chain::BitcoinRegtest,
        Chain::BitcoinTestnet4,
        Chain::LitecoinTestnet,
    ] {
        let record = PublicRecord::Post("public text".into());
        let plan = publication::prepare(&record, &author, source.clone(), chain, 1)?;
        assert_eq!(plan.version, 0);
        let (found, proof) =
            publication::verify(&hex::decode(plan.commit)?, &hex::decode(plan.reveal)?)?;
        assert_eq!(record, found);
        assert_eq!(proof.author, author.x_only_public_key().0);
    }
    let temp = tempfile::tempdir()?;
    for name in ["proof-post.commit", "proof-post.reveal"] {
        fs::write(
            temp.path().join(name),
            hex::encode(fs::read(vectors().join(name))?),
        )?;
    }
    let response = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["wire", "expert", "verify", "--commit"])
        .arg(temp.path().join("proof-post.commit"))
        .arg("--reveal")
        .arg(temp.path().join("proof-post.reveal"))
        .output()?;
    assert!(
        response.status.success(),
        "{}",
        String::from_utf8_lossy(&response.stderr)
    );
    let report: Value = serde_json::from_slice(&response.stdout)?;
    assert_eq!(report["chain_inclusion_checked"], false);
    assert_eq!(
        RecordKind::parse(&fs::read(vectors().join("post.record"))?)?,
        RecordKind::Post
    );
    Ok(())
}

#[test]
fn unknown_allocations_and_client_capacity_are_distinct_errors() -> Result<()> {
    use urma_core::error::Error;
    for version in 1..=255u8 {
        let mut header = RecordKind::Post.prefix();
        header[4] = version;
        assert!(matches!(
            RecordKind::parse(&header),
            Err(Error::Unsupported(_))
        ));
    }
    for kind in 0..=255u8 {
        let mut header = RecordKind::Post.prefix();
        header[5] = kind;
        assert_eq!(RecordKind::parse(&header).is_ok(), (1..=9).contains(&kind));
    }
    for flags in 1..=u16::MAX {
        let mut header = RecordKind::Post.prefix();
        header[6..8].copy_from_slice(&flags.to_le_bytes());
        assert!(matches!(
            RecordKind::parse(&header),
            Err(Error::Unsupported(_))
        ));
    }
    let temp = tempfile::tempdir()?;
    let file = temp.path().join("input");
    fs::write(&file, b"123")?;
    assert!(matches!(
        urma::storage::read_bounded(&file, 2),
        Err(urma::error::Error::Capacity(_))
    ));
    Ok(())
}
