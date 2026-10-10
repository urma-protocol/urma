//! Mock providers exercise the production Node/source/prefetch/retention path.
//! Confirmation and chain-tip replies are provider claims, not a chain proof.

use bitcoin::{
    Transaction, Txid, Witness,
    consensus::{deserialize, serialize},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use urma_chain::observation::Chain;
use urma_core::envelope;
use urma_runtime::{
    error::Error,
    multipart::{MultipartRecord, RecordRequest, RecoveryLimits, VerifiedRecord},
    node::Node,
    recovery,
    transport::{BlockEncoding, Evidence, Provider},
};

type Queries = Arc<Mutex<Vec<(&'static str, Txid)>>>;

struct Graph {
    transactions: BTreeMap<Txid, Transaction>,
    root: Txid,
    leaf: Txid,
    data: Txid,
}

fn vectors() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/vectors/multipart")
}

fn artifact(descriptor: &Value) -> Vec<u8> {
    let bytes = fs::read(vectors().join(descriptor["file"].as_str().unwrap())).unwrap();
    assert_eq!(bytes.len() as u64, descriptor["bytes"].as_u64().unwrap());
    assert_eq!(hex::encode(Sha256::digest(&bytes)), descriptor["sha256"]);
    bytes
}

impl Graph {
    fn load(name: &str) -> Self {
        let manifest: Value =
            serde_json::from_slice(&fs::read(vectors().join("manifest.json")).unwrap()).unwrap();
        let mut transactions = BTreeMap::new();
        let mut ids = BTreeMap::new();
        for suffix in ["root", "leaf", "part-0"] {
            let label = format!("{name}-{suffix}");
            let proof = manifest["proofs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|proof| proof["name"] == label)
                .unwrap();
            let commit: Transaction = deserialize(&artifact(&proof["commit"])).unwrap();
            let reveal: Transaction = deserialize(&artifact(&proof["reveal"])).unwrap();
            let txid: Txid = proof["txid"].as_str().unwrap().parse().unwrap();
            let verified = VerifiedRecord::verify(txid, &reveal, &commit).unwrap();
            assert_eq!(verified.record_bytes(), artifact(&proof["record"]));
            transactions.insert(commit.compute_txid(), commit);
            transactions.insert(txid, reveal);
            ids.insert(suffix, txid);
        }
        Self {
            transactions,
            root: ids["root"],
            leaf: ids["leaf"],
            data: ids["part-0"],
        }
    }

    fn request(&self, child: Txid) -> RecordRequest {
        let parent = if child == self.leaf {
            self.root
        } else {
            self.leaf
        };
        let reveal = &self.transactions[&parent];
        let commit = &self.transactions[&reveal.input[0].previous_output.txid];
        let reference = match VerifiedRecord::verify(parent, reveal, commit)
            .unwrap()
            .decode()
            .unwrap()
        {
            MultipartRecord::Root(root) => root.entries[0],
            MultipartRecord::Leaf(leaf) => leaf.entries[0],
            MultipartRecord::Data(_) => panic!("data cannot reference a child"),
        };
        assert_eq!(reference.txid, child);
        RecordRequest { reference }
    }
}

fn poisoned(graph: &Graph, txid: Txid) -> Transaction {
    let reveal = &graph.transactions[&txid];
    let parsed = envelope::extract_reveal(reveal).unwrap();
    let mut record = parsed.record.clone();
    *record.last_mut().unwrap() ^= 1;
    // Rebuild a canonical script, but preserve the original signature/control.
    // This changes the record SHA and wTXID without changing the TXID.
    let (script, _) = envelope::build_for_author(&record, parsed.author).unwrap();
    let mut items = reveal.input[0].witness.to_vec();
    items[1] = script.into_bytes();
    let mut altered = reveal.clone();
    altered.input[0].witness = Witness::from_slice(&items);
    assert_eq!(altered.compute_txid(), txid);
    assert_ne!(altered.compute_wtxid(), reveal.compute_wtxid());
    assert_eq!(envelope::extract_reveal(&altered).unwrap().record, record);
    assert_ne!(Sha256::digest(&record), Sha256::digest(&parsed.record));
    let commit = &graph.transactions[&reveal.input[0].previous_output.txid];
    let failure = VerifiedRecord::verify(txid, &altered, commit).unwrap_err();
    assert_eq!(failure.to_string(), "invalid Taproot commitment");
    altered
}

struct MockProvider {
    label: &'static str,
    transactions: BTreeMap<Txid, Transaction>,
    queries: Queries,
}

impl Provider for MockProvider {
    fn label(&self) -> String {
        self.label.into()
    }
    fn evidence(&self) -> Evidence {
        Evidence::PublicProviderObservation
    }
    fn block_encoding(&self) -> BlockEncoding {
        BlockEncoding::Core
    }
    fn supports(&self, method: &str) -> bool {
        [
            "getblockhash",
            "getblockheader",
            "getblockchaininfo",
            "getrawtransaction",
        ]
        .contains(&method)
    }
    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        let tip = "11".repeat(32);
        match method {
            "getblockhash" if args[0] == 0 => Ok(json!(chain.genesis()?.0.to_string())),
            "getblockhash" => Ok(json!(tip)),
            "getblockheader" => Ok(json!({"height": 1})),
            "getblockchaininfo" => Ok(json!({
                "blocks": 1, "bestblockhash": tip, "initialblockdownload": false
            })),
            "getrawtransaction" => {
                let txid = args[0].as_str().unwrap().parse().unwrap();
                let transaction = self.transactions.get(&txid).unwrap();
                if args[1] == true {
                    Ok(json!({"confirmations": 1, "blockhash": tip}))
                } else {
                    self.queries.lock().unwrap().push((self.label, txid));
                    Ok(json!(hex::encode(serialize(transaction))))
                }
            }
            _ => panic!("unexpected mock method {method}; no network or broadcast is implemented"),
        }
    }
}

fn node(graph: &Graph, first: Transaction, second: Transaction) -> (Node, Queries) {
    let queries = Arc::new(Mutex::new(Vec::new()));
    let providers = [("primary", first), ("backup", second)]
        .into_iter()
        .map(|(label, tx)| {
            let mut transactions = graph.transactions.clone();
            transactions.insert(tx.compute_txid(), tx);
            Box::new(MockProvider {
                label,
                transactions,
                queries: queries.clone(),
            }) as Box<dyn Provider>
        })
        .collect();
    (
        Node::with_providers(Chain::BitcoinRegtest, providers).unwrap(),
        queries,
    )
}

fn origins(queries: &Queries, txid: Txid) -> Vec<&'static str> {
    queries
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(label, requested)| (*requested == txid).then_some(*label))
        .collect()
}

fn retained_path(directory: &Path, txid: Txid) -> PathBuf {
    directory.join("tx").join(format!("{txid}.bin"))
}

fn fallback(child: fn(&Graph) -> Txid) {
    let graph = Graph::load("one");
    let child = child(&graph);
    let altered = poisoned(&graph, child);
    let extracted = envelope::extract_reveal(&altered).unwrap();
    assert_ne!(
        <[u8; 32]>::from(Sha256::digest(&extracted.record)),
        graph.request(child).reference.record_hash
    );
    let (node, queries) = node(&graph, altered, graph.transactions[&child].clone());
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let mut object = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    object.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"x");
    assert_eq!(origins(&queries, child), ["primary", "backup"]);
    assert_eq!(
        fs::read_dir(proofs.path().join("tx")).unwrap().count(),
        graph.transactions.len()
    );
    for (txid, transaction) in &graph.transactions {
        assert_eq!(
            fs::read(retained_path(proofs.path(), *txid)).unwrap(),
            serialize(transaction)
        );
    }
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn altered_leaf_same_txid_retries_another_origin_and_retains_only_authentic_bytes() {
    fallback(|graph| graph.leaf);
}

#[test]
fn altered_data_same_txid_retries_another_origin_and_retains_only_authentic_bytes() {
    fallback(|graph| graph.data);
}

fn wrong_hash(name: &str, child: fn(&Graph) -> Txid) {
    let graph = Graph::load(name);
    let child = child(&graph);
    let reveal = &graph.transactions[&child];
    let commit = &graph.transactions[&reveal.input[0].previous_output.txid];
    let request = graph.request(child);
    let verified = request.verify(reveal, commit).unwrap();
    assert!(
        request
            .check_hash(&verified)
            .unwrap_err()
            .to_string()
            .contains("signed manifest reference")
    );
    let (node, queries) = node(&graph, reveal.clone(), reveal.clone());
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let failure = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .err()
    .unwrap();
    assert!(matches!(failure, Error::Protocol(_)));
    assert!(
        failure
            .to_string()
            .contains("record hash differs from the signed manifest reference")
    );
    assert_eq!(origins(&queries, child), ["primary"]);
    // Retention certifies the proof, not membership in a successfully recovered object.
    assert_eq!(
        fs::read(retained_path(proofs.path(), child)).unwrap(),
        serialize(reveal)
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn authenticated_leaf_hash_mismatch_is_terminal_without_provider_retry() {
    wrong_hash("wrong-leaf-hash", |graph| graph.leaf);
}

#[test]
fn authenticated_data_hash_mismatch_is_terminal_without_provider_retry() {
    wrong_hash("wrong-child-hash", |graph| graph.data);
}

#[test]
fn exhausted_invalid_proofs_are_not_reported_as_manifest_hash_mismatch_or_retained() {
    let graph = Graph::load("one");
    let altered = poisoned(&graph, graph.leaf);
    let (node, queries) = node(&graph, altered.clone(), altered);
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let failure = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .err()
    .unwrap();
    // recover() erases the InvalidCandidate/InvalidObject enum distinction into Protocol.
    assert!(matches!(failure, Error::Protocol(_)));
    assert_eq!(failure.to_string(), "invalid Taproot commitment");
    assert_eq!(origins(&queries, graph.leaf), ["primary", "backup"]);
    assert!(!retained_path(proofs.path(), graph.leaf).exists());
    assert!(!retained_path(proofs.path(), graph.data).exists());
    assert_eq!(fs::read_dir(proofs.path().join("tx")).unwrap().count(), 2);
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn altered_root_same_txid_retries_another_origin_and_recovers_exact_bytes() {
    let graph = Graph::load("one");
    let (node, queries) = node(
        &graph,
        poisoned(&graph, graph.root),
        graph.transactions[&graph.root].clone(),
    );
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let mut object = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .unwrap_or_else(|cause| {
        panic!(
            "root recovery failed: {cause}; origins: {:?}",
            origins(&queries, graph.root)
        )
    });
    let mut bytes = Vec::new();
    object.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"x");
    assert_eq!(origins(&queries, graph.root), ["primary", "backup"]);
    for (txid, transaction) in &graph.transactions {
        assert_eq!(
            fs::read(retained_path(proofs.path(), *txid)).unwrap(),
            serialize(transaction)
        );
    }
}

#[test]
fn existing_proof_directory_and_same_txid_bytes_are_not_overwritten() {
    let graph = Graph::load("one");
    let reveal = graph.transactions[&graph.root].clone();
    let (node, queries) = node(&graph, reveal.clone(), reveal);
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    urma_io::create_private_directory(&proofs.path().join("tx")).unwrap();
    let path = retained_path(proofs.path(), graph.root);
    let existing = serialize(&poisoned(&graph, graph.root));
    fs::write(&path, &existing).unwrap();
    let failure = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .err()
    .unwrap();
    match failure {
        Error::Io(cause) => assert_eq!(cause.kind(), std::io::ErrorKind::AlreadyExists),
        other => panic!("expected existing directory refusal, got {other}"),
    }
    assert_eq!(fs::read(path).unwrap(), existing);
    assert!(queries.lock().unwrap().is_empty());
    assert_eq!(fs::read_dir(proofs.path().join("tx")).unwrap().count(), 1);
}

#[test]
fn authenticated_malformed_root_is_terminal_without_alternate_source_or_children() {
    let graph = Graph::load("root-count-mismatch");
    let reveal = graph.transactions[&graph.root].clone();
    let commit = &graph.transactions[&reveal.input[0].previous_output.txid];
    let verified = VerifiedRecord::verify(graph.root, &reveal, commit).unwrap();
    let structural_error = verified.decode().unwrap_err().to_string();
    let (node, queries) = node(&graph, reveal.clone(), reveal.clone());
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let failure = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .err()
    .unwrap();
    assert!(matches!(failure, Error::Protocol(_)));
    assert_eq!(failure.to_string(), structural_error);
    assert_eq!(origins(&queries, graph.root), ["primary"]);
    assert!(origins(&queries, graph.leaf).is_empty());
    assert!(origins(&queries, graph.data).is_empty());
    assert_eq!(fs::read_dir(proofs.path().join("tx")).unwrap().count(), 2);
    assert_eq!(
        fs::read(retained_path(proofs.path(), graph.root)).unwrap(),
        serialize(&reveal)
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn exhausted_invalid_root_proofs_exclude_each_origin_and_retain_nothing() {
    let graph = Graph::load("one");
    let altered = poisoned(&graph, graph.root);
    let (node, queries) = node(&graph, altered.clone(), altered);
    let scratch = tempfile::tempdir().unwrap();
    let proofs = tempfile::tempdir().unwrap();
    let failure = recovery::recover_retained(
        &node,
        graph.root,
        RecoveryLimits::new(1024, 3),
        scratch.path(),
        proofs.path(),
    )
    .err()
    .unwrap();
    assert!(matches!(failure, Error::Protocol(_)));
    assert_eq!(failure.to_string(), "invalid Taproot commitment");
    assert_eq!(origins(&queries, graph.root), ["primary", "backup"]);
    assert_eq!(fs::read_dir(proofs.path().join("tx")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn root_retrieval_obeys_existing_attempt_floor_and_deadline_before_fetch() {
    let graph = Graph::load("one");
    for attempts in [0, 1] {
        let (node, queries) = node(
            &graph,
            poisoned(&graph, graph.root),
            graph.transactions[&graph.root].clone(),
        );
        let scratch = tempfile::tempdir().unwrap();
        let mut limits = RecoveryLimits::new(1024, 3);
        limits.attempts = attempts;
        let failure = recovery::recover(&node, graph.root, limits, scratch.path())
            .err()
            .unwrap();
        assert_eq!(failure.to_string(), "invalid Taproot commitment");
        assert_eq!(origins(&queries, graph.root), ["primary"]);
    }
    let reveal = graph.transactions[&graph.root].clone();
    let (node, queries) = node(&graph, reveal.clone(), reveal);
    let scratch = tempfile::tempdir().unwrap();
    let mut limits = RecoveryLimits::new(1024, 3);
    limits.timeout = std::time::Duration::ZERO;
    let failure = recovery::recover(&node, graph.root, limits, scratch.path())
        .err()
        .unwrap();
    match failure {
        Error::Io(cause) => assert_eq!(cause.kind(), std::io::ErrorKind::TimedOut),
        other => panic!("expected deadline error, got {other}"),
    }
    assert!(queries.lock().unwrap().is_empty());
}
