use anyhow::{Context, Result};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
    transaction::Version,
};
use sha2::{Digest, Sha256};
use std::fs;
use urma_chain::observation::Chain;
use urma_core::multipart::{ChildReference, DataPart, LeafManifest, MultipartRecord, RootManifest};
use urma_runtime::publication;
use urma_wallet::funding::Funding;
use urma_web::{
    package::{FileEntry, Package, PinnedEntry},
    store::{Pointer, Served, Store},
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
    let plan = publication::prepare_bytes(&root, author, funding(seed), Chain::BitcoinRegtest, 1)?;
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
        tip_height: 7,
        tip_hash: "33".repeat(32),
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
    assert_eq!(summary.commit, f.published.commit.compute_txid().to_string());
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
    assert!(refused(&f.store, "bitcoin-regtest", &f.root).is_ok(), "wrong commit accepted");
    f.store.put_pointer(&pointer("bitcoin-regtest", &f.published))?;
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
    f.store.put_pointer(&pointer("bitcoin-regtest", &f.published))?;
    let reveal_path = f.store.root().join("tx").join(format!("{}.bin", f.root));
    fs::write(&reveal_path, serialize(&f.published.commit))?;
    assert!(refused(&f.store, "bitcoin-regtest", &f.root).is_ok(), "swapped reveal accepted");
    let other_author = Keypair::from_seckey_slice(&Secp256k1::new(), &[6; 32])?;
    let other = publish(&f.package, &other_author, 2)?;
    fs::write(&reveal_path, serialize(&other.reveal))?;
    assert!(
        refused(&f.store, "bitcoin-regtest", &f.root).is_ok(),
        "another author's reveal accepted under the root"
    );
    fs::write(&reveal_path, serialize(&f.published.reveal))?;
    assert!(f.store.publication("bitcoin-regtest", &f.root, 1 << 20).is_ok());
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
    f.store.put_pointer(&pointer("litecoin-mainnet", &f.published))?;
    let as_litecoin = f.store.publication("litecoin-mainnet", &f.root, 1 << 20)?;
    let as_regtest = f.store.publication("bitcoin-regtest", &f.root, 1 << 20)?;
    assert_eq!(as_litecoin.pointer.network, "litecoin-mainnet");
    assert_eq!(as_litecoin.author, as_regtest.author);
    assert_eq!(as_litecoin.payload_sha256, as_regtest.payload_sha256);
    Ok(())
}
