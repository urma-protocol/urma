use anyhow::{Context, Result};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
    transaction::Version,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use urma_chain::observation::Chain;
use urma_core::multipart::{ChildReference, DataPart, LeafManifest, MultipartRecord, RootManifest};
use urma_runtime::publication;
use urma_wallet::funding::Funding;
use urma_web::{
    package::{FileEntry, Package, PinnedEntry},
    store::{AcquisitionSource, Pointer, Served, Store, StoredPublication},
};

fn funding(seed: u8) -> Funding {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(300_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20])),
        }],
    };
    Funding {
        raw_transaction: hex::encode(serialize(&tx)),
        vout: 0,
    }
}

struct Published {
    reveal: Transaction,
    commit: Transaction,
    payload: Vec<u8>,
}

fn publish(package: &Package, author: &Keypair, seed: u8) -> Result<Published> {
    let payload = package.encode()?;
    let data = MultipartRecord::Data(DataPart {
        index: 0,
        payload: payload.clone(),
    })
    .encode()?;
    let leaf = MultipartRecord::Leaf(LeafManifest {
        index: 0,
        entries: vec![ChildReference::new(
            Txid::from_byte_array([0xd0; 32]),
            &data,
        )?],
    })
    .encode()?;
    let root = MultipartRecord::Root(RootManifest {
        length: u64::try_from(payload.len())?,
        payload_hash: Sha256::digest(&payload).into(),
        profile: Package::PROFILE,
        entries: vec![ChildReference::new(
            Txid::from_byte_array([0xe0; 32]),
            &leaf,
        )?],
    })
    .encode()?;
    let source = funding(seed);
    let back = source.prevout()?.1.script_pubkey;
    let plan =
        publication::prepare_bytes(&root, author, vec![source], &back, Chain::BitcoinRegtest, 1)?;
    Ok(Published {
        reveal: deserialize(&hex::decode(plan.reveal)?)?,
        commit: deserialize(&hex::decode(plan.commit)?)?,
        payload,
    })
}

fn pointer(network: &str, published: &Published) -> Pointer {
    Pointer {
        format: Store::FORMAT.into(),
        network: network.into(),
        root: published.reveal.compute_txid().to_string(),
        commit: published.commit.compute_txid().to_string(),
        tip_height: Some(7),
        tip_hash: Some("33".repeat(32)),
        source: None,
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    package: Package,
    published: Published,
    root: String,
    html: Vec<u8>,
    pinned_bytes: Vec<u8>,
    payload_sha256: String,
    pin_sha256: String,
}

fn fixture() -> Result<Fixture> {
    let temp = tempfile::tempdir()?;
    let store = Store::open(&temp.path().join("web-store"))?;
    let author = Keypair::from_seckey_slice(&Secp256k1::new(), &[5; 32])?;
    let html = b"<!doctype html><p>hi</p>".to_vec();
    let pinned_bytes = vec![7u8; 1000];
    let pin = PinnedEntry {
        path: "dl/app.bin".into(),
        mime: "application/octet-stream".into(),
        root_txid: Txid::from_byte_array([0x22; 32]),
        payload_sha256: Sha256::digest(&pinned_bytes).into(),
    };
    let package = Package::build(
        "demo",
        "index.html",
        vec![
            FileEntry::new("index.html", "text/html", html.clone()),
            FileEntry::new("sub/index.html", "text/html", html.clone()),
            FileEntry::new("style.css", "text/css", b"body{}".to_vec()),
        ],
        vec![pin],
    )?;
    let published = publish(&package, &author, 1)?;
    let root = published.reveal.compute_txid().to_string();
    store.put_transaction(&published.reveal)?;
    store.put_transaction(&published.commit)?;
    let payload_sha256 = store.put_object(&published.payload)?;
    let pin_sha256 = store.put_object(&pinned_bytes)?;
    store.put_pointer(&pointer("bitcoin-regtest", &published))?;
    Ok(Fixture {
        _temp: temp,
        store,
        package,
        published,
        root,
        html,
        pinned_bytes,
        payload_sha256,
        pin_sha256,
    })
}

fn refused(store: &Store, network: &str, root: &str) -> Result<String> {
    match store.publication(network, root, 1 << 20) {
        Ok(_) => anyhow::bail!("publication {network}/{root} accepted"),
        Err(error) => Ok(error.to_string()),
    }
}

#[test]
fn store_serves_only_what_the_authenticated_package_declares_and_rejects_tampering() -> Result<()> {
    let f = fixture()?;
    let author = Keypair::from_seckey_slice(&Secp256k1::new(), &[5; 32])?;
    let verified = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    assert_eq!(verified.author, author.x_only_public_key().0.to_string());
    assert_eq!(verified.payload_sha256, f.payload_sha256);
    let summary = f.store.summary(&verified)?;
    assert_eq!((summary.files.len(), summary.pinned.len()), (3, 1));
    assert_eq!(summary.pinned[0].sha256, f.pin_sha256);
    assert_eq!(summary.pinned[0].length, 1000);
    assert_eq!(summary.entry, "index.html");
    assert_eq!(
        summary.commit,
        f.published.commit.compute_txid().to_string()
    );
    let Served::Resource {
        mime,
        bytes,
        sha256,
    } = f.store.serve(&verified, "/")?
    else {
        panic!("entry")
    };
    assert_eq!(
        (mime.as_str(), bytes, sha256),
        (
            "text/html",
            f.html.clone(),
            hex::encode(Sha256::digest(&f.html))
        )
    );
    let Served::Resource { bytes, .. } = f.store.serve(&verified, "/sub/")? else {
        panic!("directory index")
    };
    assert_eq!(bytes, f.html);
    let Served::Resource { mime, bytes, .. } = f.store.serve(&verified, "/dl/app.bin")? else {
        panic!("pin")
    };
    assert_eq!(
        (mime.as_str(), bytes),
        ("application/octet-stream", f.pinned_bytes.clone())
    );
    for undeclared in ["/missing", "index.html", "/sub", "/Style.css", "/dl/"] {
        assert!(
            matches!(f.store.serve(&verified, undeclared)?, Served::Undeclared),
            "{undeclared}"
        );
    }
    assert!(refused(&f.store, "litecoin-mainnet", &f.root).is_ok());
    assert!(refused(&f.store, "bitcoin-regtest", &"44".repeat(32)).is_ok());
    let objects = f.store.root().join("objects");
    let original = fs::read(objects.join(&f.payload_sha256))?;
    let forged = Package::build(
        "forged",
        "index.html",
        vec![FileEntry::new(
            "index.html",
            "text/html",
            b"<p>forged</p>".to_vec(),
        )],
        Vec::new(),
    )?
    .encode()?;
    fs::write(objects.join(&f.payload_sha256), &forged)?;
    let message = refused(&f.store, "bitcoin-regtest", &f.root).context("forged package")?;
    assert!(message.contains("failed re-verification"), "{message}");
    fs::write(objects.join(&f.payload_sha256), &original)?;
    let mut wrong = pointer("bitcoin-regtest", &f.published);
    wrong.commit = "11".repeat(32);
    f.store.put_pointer(&wrong)?;
    assert!(
        refused(&f.store, "bitcoin-regtest", &f.root).is_ok(),
        "wrong commit accepted"
    );
    f.store
        .put_pointer(&pointer("bitcoin-regtest", &f.published))?;
    let forged_json = format!(
        "{{\"format\":\"{}\",\"network\":\"bitcoin-regtest\",\"root\":\"{}\",\"commit\":\"{}\",\"tip_height\":1,\"tip_hash\":\"x\",\"files\":[]}}",
        Store::FORMAT,
        f.root,
        f.published.commit.compute_txid()
    );
    let pointer_path = f
        .store
        .root()
        .join("publications")
        .join("bitcoin-regtest")
        .join(format!("{}.json", f.root));
    fs::write(&pointer_path, forged_json)?;
    assert!(
        refused(&f.store, "bitcoin-regtest", &f.root).is_ok(),
        "pointer with foreign fields accepted"
    );
    f.store
        .put_pointer(&pointer("bitcoin-regtest", &f.published))?;
    let reveal_path = f.store.root().join("tx").join(format!("{}.bin", f.root));
    fs::write(&reveal_path, serialize(&f.published.commit))?;
    assert!(
        refused(&f.store, "bitcoin-regtest", &f.root).is_ok(),
        "swapped reveal accepted"
    );
    let other_author = Keypair::from_seckey_slice(&Secp256k1::new(), &[6; 32])?;
    let other = publish(&f.package, &other_author, 2)?;
    fs::write(&reveal_path, serialize(&other.reveal))?;
    assert!(
        refused(&f.store, "bitcoin-regtest", &f.root).is_ok(),
        "another author's reveal accepted under the root"
    );
    fs::write(&reveal_path, serialize(&f.published.reveal))?;
    assert!(
        f.store
            .publication("bitcoin-regtest", &f.root, 1 << 20)
            .is_ok()
    );
    assert!(
        f.store.publication("bitcoin-regtest", &f.root, 16).is_err(),
        "payload above the caller's limit accepted"
    );
    Ok(())
}

#[test]
fn store_refuses_the_whole_publication_when_a_pinned_object_is_missing_corrupt_or_truncated()
-> Result<()> {
    let f = fixture()?;
    let objects = f.store.root().join("objects");
    fs::remove_file(objects.join(&f.pin_sha256))?;
    let message = refused(&f.store, "bitcoin-regtest", &f.root).context("missing pin")?;
    assert!(message.contains("declared set incomplete"), "{message}");
    fs::write(objects.join(&f.pin_sha256), vec![8u8; 1000])?;
    let message = refused(&f.store, "bitcoin-regtest", &f.root).context("corrupt pin")?;
    assert!(
        message.contains("declared set corrupt") && message.contains("dl/app.bin"),
        "{message}"
    );
    fs::write(objects.join(&f.pin_sha256), vec![7u8; 999])?;
    let message = refused(&f.store, "bitcoin-regtest", &f.root).context("truncated pin")?;
    assert!(message.contains("declared set corrupt"), "{message}");
    fs::write(objects.join(&f.pin_sha256), vec![7u8; 1001])?;
    let message = refused(&f.store, "bitcoin-regtest", &f.root).context("padded pin")?;
    assert!(message.contains("declared set corrupt"), "{message}");
    assert_eq!(f.store.put_object(&f.pinned_bytes)?, f.pin_sha256);
    let verified = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    assert_eq!(verified.pinned_lengths, vec![1000]);
    assert_eq!(f.store.summary(&verified)?.pinned[0].length, 1000);
    let Served::Resource { bytes, .. } = f.store.serve(&verified, "/dl/app.bin")? else {
        panic!("pin")
    };
    assert_eq!(bytes, f.pinned_bytes);
    fs::write(objects.join(&f.pin_sha256), vec![8u8; 1000])?;
    assert!(
        f.store.serve(&verified, "/dl/app.bin").is_err(),
        "pinned object corrupted after verification served"
    );
    assert_eq!(f.store.put_object(&f.pinned_bytes)?, f.pin_sha256);
    assert_eq!(fs::read(objects.join(&f.pin_sha256))?, f.pinned_bytes);
    Ok(())
}

#[test]
fn store_namespace_pointer_and_request_must_name_the_same_network_and_root() -> Result<()> {
    let f = fixture()?;
    let publications = f.store.root().join("publications");
    let original = fs::read(
        publications
            .join("bitcoin-regtest")
            .join(format!("{}.json", f.root)),
    )?;
    fs::create_dir_all(publications.join("litecoin-mainnet"))?;
    fs::write(
        publications
            .join("litecoin-mainnet")
            .join(format!("{}.json", f.root)),
        &original,
    )?;
    let message = refused(&f.store, "litecoin-mainnet", &f.root).context("moved pointer")?;
    assert!(message.contains("another network or root"), "{message}");
    let other = "44".repeat(32);
    fs::write(
        publications
            .join("bitcoin-regtest")
            .join(format!("{other}.json")),
        &original,
    )?;
    let message = refused(&f.store, "bitcoin-regtest", &other).context("renamed pointer")?;
    assert!(message.contains("another network or root"), "{message}");
    assert!(f.store.pointer("bitcoin-regtest", &f.root).is_ok());
    assert!(f.store.pointer("Bitcoin-Regtest", &f.root).is_err());
    assert!(f.store.pointer("../bitcoin-regtest", &f.root).is_err());
    Ok(())
}

// The commit and reveal bytes carry no chain identity: the same proof verifies under a
// pointer rewritten for another network. What binds a publication to a chain is the
// fetch (`web fetch` connects to a source whose genesis hash must equal the selected
// chain's before recovery) and the pointer that fetch writes; offline reads re-prove
// authorship and content, never inclusion or network. Documented limit, not a rule.
#[test]
fn store_network_is_fetch_time_metadata_not_re_proven_from_the_transactions() -> Result<()> {
    let f = fixture()?;
    f.store
        .put_pointer(&pointer("litecoin-mainnet", &f.published))?;
    let as_litecoin = f.store.publication("litecoin-mainnet", &f.root, 1 << 20)?;
    let as_regtest = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    assert_eq!(as_litecoin.pointer.network, "litecoin-mainnet");
    assert_eq!(as_litecoin.author, as_regtest.author);
    assert_eq!(as_litecoin.payload_sha256, as_regtest.payload_sha256);
    Ok(())
}

fn operator_pointer(published: &Published) -> Pointer {
    let mut pointer = pointer("bitcoin-regtest", published);
    pointer.format = Store::OPERATOR_FORMAT.into();
    pointer.tip_height = None;
    pointer.tip_hash = None;
    pointer.source = Some(AcquisitionSource::LocalNodeOperator);
    pointer
}

#[test]
fn store_acquisition_format_matrix_refuses_mixed_metadata_on_write_and_read() -> Result<()> {
    let f = fixture()?;
    let legacy = pointer("bitcoin-regtest", &f.published);
    let path = f
        .store
        .root()
        .join("publications/bitcoin-regtest")
        .join(format!("{}.json", f.root));
    for format in [Store::FORMAT, Store::OPERATOR_FORMAT, "URMA-WEB-STORE-4"] {
        for source in [false, true] {
            for height in [false, true] {
                for hash in [false, true] {
                    f.store.put_pointer(&legacy)?;
                    let before = fs::read(&path)?;
                    let candidate = Pointer {
                        format: format.into(),
                        network: legacy.network.clone(),
                        root: legacy.root.clone(),
                        commit: legacy.commit.clone(),
                        tip_height: height.then_some(7),
                        tip_hash: hash.then(|| "33".repeat(32)),
                        source: source.then_some(AcquisitionSource::LocalNodeOperator),
                    };
                    let allowed = (format == Store::FORMAT && !source && height && hash)
                        || (format == Store::OPERATOR_FORMAT && source && !height && !hash);
                    assert_eq!(
                        f.store.put_pointer(&candidate).is_ok(),
                        allowed,
                        "write: {candidate:?}"
                    );
                    if allowed {
                        assert_eq!(f.store.pointer("bitcoin-regtest", &f.root)?, candidate);
                    } else {
                        assert_eq!(fs::read(&path)?, before, "refused write changed pointer");
                    }
                    // Independent read boundary: malformed metadata is written
                    // only to the owned fixture path, never operator state.
                    let encoded = serde_json::to_vec(&candidate)?;
                    fs::write(&path, &encoded)?;
                    assert_eq!(
                        f.store.pointer("bitcoin-regtest", &f.root).is_ok(),
                        allowed,
                        "read: {candidate:?}"
                    );
                    assert_eq!(fs::read(&path)?, encoded, "read mutated pointer");
                }
            }
        }
    }
    f.store.put_pointer(&legacy)?;
    Ok(())
}

#[test]
fn acquisition_source_json_refuses_unknown_kinds_extra_fields_and_duplicates() -> Result<()> {
    let source = json!({"kind":"local-node-operator"});
    assert_eq!(
        serde_json::to_value(AcquisitionSource::LocalNodeOperator)?,
        source
    );
    assert_eq!(
        serde_json::from_value::<AcquisitionSource>(source)?,
        AcquisitionSource::LocalNodeOperator
    );
    let f = fixture()?;
    let operator = operator_pointer(&f.published);
    f.store.put_pointer(&operator)?;
    let verified = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    let summary = serde_json::to_value(f.store.summary(&verified)?)?;
    let pointer_json = serde_json::to_value(&operator)?;
    let path = f
        .store
        .root()
        .join("publications/bitcoin-regtest")
        .join(format!("{}.json", f.root));
    for bad in [
        json!({"kind":"autonomous"}),
        json!({"kind":"local-node-operator","extra":true}),
        json!({"kind":"local-node-operator","tip_height":7}),
        json!({"kind":"local-node-operator","extra":null}),
        json!({}),
        json!({"kind":7}),
        json!("local-node-operator"),
        json!([]),
    ] {
        assert!(
            serde_json::from_value::<AcquisitionSource>(bad.clone()).is_err(),
            "source accepted: {bad}"
        );
        let mut pointer = pointer_json.clone();
        pointer["source"] = bad.clone();
        assert!(
            serde_json::from_value::<Pointer>(pointer.clone()).is_err(),
            "pointer source accepted: {bad}"
        );
        let encoded = serde_json::to_vec(&pointer)?;
        fs::write(&path, &encoded)?;
        assert!(
            f.store.pointer("bitcoin-regtest", &f.root).is_err(),
            "stored source accepted: {bad}"
        );
        assert_eq!(fs::read(&path)?, encoded);
        let mut publication = summary.clone();
        publication["source"] = bad.clone();
        assert!(
            serde_json::from_value::<StoredPublication>(publication).is_err(),
            "summary source accepted: {bad}"
        );
    }
    assert!(
        serde_json::from_str::<AcquisitionSource>(
            r#"{"kind":"local-node-operator","kind":"local-node-operator"}"#
        )
        .is_err()
    );
    f.store.put_pointer(&operator)?;
    Ok(())
}

#[test]
fn summary_preserves_operator_metadata_and_refuses_invalid_public_verified() -> Result<()> {
    let f = fixture()?;
    let legacy = pointer("bitcoin-regtest", &f.published);
    let operator = operator_pointer(&f.published);
    let mut verified = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    let before = fs::read(
        f.store
            .root()
            .join("publications/bitcoin-regtest")
            .join(format!("{}.json", f.root)),
    )?;
    // Verified is public: validation cannot rely solely on Store::publication.
    verified.pointer = operator.clone();
    let summary = f.store.summary(&verified)?;
    assert_eq!(summary.format, Store::OPERATOR_FORMAT);
    assert_eq!(summary.source, Some(AcquisitionSource::LocalNodeOperator));
    assert!(summary.tip_height.is_none() && summary.tip_hash.is_none());
    let encoded = serde_json::to_value(&summary)?;
    assert_eq!(encoded["source"], json!({"kind":"local-node-operator"}));
    assert!(encoded.get("tip_height").is_none() && encoded.get("tip_hash").is_none());
    assert_eq!(
        serde_json::from_value::<StoredPublication>(encoded)?,
        summary
    );
    for format in [Store::FORMAT, Store::OPERATOR_FORMAT, "URMA-WEB-STORE-4"] {
        for source in [false, true] {
            for height in [false, true] {
                for hash in [false, true] {
                    verified.pointer = Pointer {
                        format: format.into(),
                        network: legacy.network.clone(),
                        root: legacy.root.clone(),
                        commit: legacy.commit.clone(),
                        tip_height: height.then_some(7),
                        tip_hash: hash.then(|| "33".repeat(32)),
                        source: source.then_some(AcquisitionSource::LocalNodeOperator),
                    };
                    let allowed = (format == Store::FORMAT && !source && height && hash)
                        || (format == Store::OPERATOR_FORMAT && source && !height && !hash);
                    assert_eq!(
                        f.store.summary(&verified).is_ok(),
                        allowed,
                        "public Verified: {:?}",
                        verified.pointer
                    );
                }
            }
        }
    }
    assert_eq!(
        fs::read(
            f.store
                .root()
                .join("publications/bitcoin-regtest")
                .join(format!("{}.json", f.root))
        )?,
        before
    );
    f.store.put_pointer(&operator)?;
    let authenticated = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    assert_eq!(f.store.summary(&authenticated)?, summary);
    Ok(())
}

#[test]
fn legacy_pointer_and_summary_keep_exact_json_values_and_omissions() -> Result<()> {
    let f = fixture()?;
    let legacy = pointer("bitcoin-regtest", &f.published);
    let expected = format!(
        r#"{{"format":"URMA-WEB-STORE-2","network":"bitcoin-regtest","root":"{}","commit":"{}","tip_height":7,"tip_hash":"{}"}}"#,
        f.root,
        f.published.commit.compute_txid(),
        "33".repeat(32)
    );
    assert_eq!(serde_json::to_string(&legacy)?, expected);
    assert_eq!(serde_json::from_str::<Pointer>(&expected)?, legacy);
    let verified = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    let summary = f.store.summary(&verified)?;
    assert_eq!(summary.source, None);
    let author = Keypair::from_seckey_slice(&Secp256k1::new(), &[5; 32])?
        .x_only_public_key()
        .0
        .to_string();
    let files: Vec<_> = f.package.files.iter().map(|file| json!({
        "path":file.path,"mime":file.mime,"sha256":hex::encode(file.sha256),"length":file.bytes.len()})).collect();
    let pins: Vec<_> = f
        .package
        .pinned
        .iter()
        .map(|pin| {
            json!({
        "path":pin.path,"mime":pin.mime,"root_txid":pin.root_txid.to_string(),
        "sha256":hex::encode(pin.payload_sha256),"length":f.pinned_bytes.len()})
        })
        .collect();
    let expected = json!({"format":"URMA-WEB-STORE-2","network":"bitcoin-regtest","root":f.root,
        "commit":f.published.commit.compute_txid().to_string(),"author":author,"label":"demo","entry":"index.html",
        "payload_sha256":f.payload_sha256,"payload_length":f.published.payload.len(),"files":files,"pinned":pins,
        "tip_height":7,"tip_hash":"33".repeat(32)});
    assert_eq!(serde_json::to_value(&summary)?, expected);
    // Exact legacy top-level field order and values; file/pin DTOs are unchanged
    // and their independent authenticated package values were compared above.
    let expected_bytes = format!(
        r#"{{"format":"URMA-WEB-STORE-2","network":"bitcoin-regtest","root":"{root}","commit":"{commit}","author":"{author}","label":"demo","entry":"index.html","payload_sha256":"{payload}","payload_length":{length},"files":{files},"pinned":{pins},"tip_height":7,"tip_hash":"{tip}"}}"#,
        root = f.root,
        commit = f.published.commit.compute_txid(),
        author = author,
        payload = f.payload_sha256,
        length = f.published.payload.len(),
        files = serde_json::to_string(&summary.files)?,
        pins = serde_json::to_string(&summary.pinned)?,
        tip = "33".repeat(32)
    );
    assert_eq!(serde_json::to_string(&summary)?, expected_bytes);
    assert_eq!(
        serde_json::from_value::<StoredPublication>(expected)?,
        summary
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn immutable_objects_bound_input_reuse_exact_regular_files_and_refuse_disagreement_or_symlinks()
-> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let temp = tempfile::tempdir()?;
    let store = Store::open(&temp.path().join("store"))?;
    let objects = store.root().join("objects");
    // Reject before hashing/I/O; no exact-limit large-object success claim.
    let oversized = vec![0; Store::MAX_OBJECT_BYTES + 1];
    assert!(store.put_object_immutable(&oversized).is_err());
    assert_eq!(fs::read_dir(&objects)?.count(), 0);
    drop(oversized);
    let bytes = b"immutable bytes";
    let sha = store.put_object_immutable(bytes)?;
    assert_eq!(sha, hex::encode(Sha256::digest(bytes)));
    let path = objects.join(&sha);
    let inode = fs::metadata(&path)?.ino();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    assert_eq!(store.put_object_immutable(bytes)?, sha);
    assert_eq!(
        fs::metadata(&path)?.ino(),
        inode,
        "exact reuse replaced file"
    );
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o400);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    for poisoned in [
        vec![b'x'; bytes.len()],
        b"short".to_vec(),
        [bytes.as_slice(), b"extra"].concat(),
    ] {
        fs::write(&path, &poisoned)?;
        assert!(store.put_object_immutable(bytes).is_err());
        assert_eq!(
            fs::read(&path)?,
            poisoned,
            "immutable refusal rewrote disagreement"
        );
    }
    // Preserve the autonomous repair contract: existing put_object still repairs.
    assert_eq!(store.put_object(bytes)?, sha);
    assert_eq!(fs::read(&path)?, bytes);
    fs::remove_file(&path)?;
    let target = temp.path().join("matching-target");
    fs::write(&target, bytes)?;
    symlink(&target, &path)?;
    assert!(
        store.put_object_immutable(bytes).is_err(),
        "matching symlink accepted"
    );
    assert_eq!(fs::read_link(&path)?, target);
    assert_eq!(fs::read(&target)?, bytes);
    fs::remove_file(&path)?;
    let missing = temp.path().join("missing-target");
    symlink(&missing, &path)?;
    assert!(
        store.put_object_immutable(bytes).is_err(),
        "dangling symlink accepted"
    );
    assert_eq!(fs::read_link(&path)?, missing);
    assert!(!missing.exists());
    fs::remove_file(&path)?;
    fs::create_dir(&path)?;
    assert!(
        store.put_object_immutable(bytes).is_err(),
        "directory accepted"
    );
    assert!(path.is_dir());
    Ok(())
}
