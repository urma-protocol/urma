// Other suites use additional shared helpers. This module stays read-only.
#[allow(dead_code)]
mod common;

use bitcoin::{
    Block, BlockHash, Transaction, Txid, Witness,
    block::Header,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, readonly_archive, stored_bytes,
    witness_block,
};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::multipart::{MultipartRecord, RecordRequest, VerifiedRecord};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveStatus, ChainPoint, RecordPackage, Retention},
    retrieval::{FetchLimits, RecordSource, fetch_record, recover},
    source::ChainSource,
};
use urma_runtime::multipart::{RecoveredObject, RecoveryError, RecoveryLimits};

struct Graph {
    pairs: Vec<SignedPair>, // Root, leaf, then data parts in payload order.
}

impl Graph {
    fn load(name: &str, parts: usize) -> Self {
        let names = ["root".to_owned(), "leaf".to_owned()]
            .into_iter()
            .chain((0..parts).map(|i| format!("part-{i}")));
        Self {
            pairs: names
                .map(|suffix| SignedPair::load(&format!("multipart/{name}-{suffix}")))
                .collect(),
        }
    }

    fn id(&self, index: usize) -> Txid {
        self.pairs[index].reveal.compute_txid()
    }

    fn block(&self, previous: Option<&Block>, nonce: u32) -> Block {
        let transactions: Vec<_> = self
            .pairs
            .iter()
            .flat_map(SignedPair::transactions)
            .collect();
        witness_block(&transactions, previous, nonce)
    }

    fn packages(&self, block: &Block, height: u64) -> BTreeMap<Txid, RecordPackage> {
        self.pairs
            .iter()
            .map(|pair| (pair.reveal.compute_txid(), package(block, height, pair)))
            .collect()
    }

    fn payload(&self) -> Vec<u8> {
        self.pairs[2..]
            .iter()
            .flat_map(|pair| {
                let MultipartRecord::Data(part) = pair.verified.decode().unwrap() else {
                    panic!("data fixture")
                };
                part.payload
            })
            .collect()
    }

    fn limits(&self) -> RecoveryLimits {
        RecoveryLimits {
            timeout: Duration::from_secs(5),
            ..RecoveryLimits::new(self.payload().len() as u64, self.pairs.len() as u32)
        }
    }
}

fn package(block: &Block, height: u64, pair: &SignedPair) -> RecordPackage {
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
        .unwrap();
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(height, block),
        reveal: TransactionProof::from_block(
            block,
            position as u32,
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

// No sockets or elapsed-time simulation: each callback completes synchronously.
// Transport implementations own per-call timeouts; these tests cover only
// callback boundaries and explicit caller budgets, never hard interruption.
struct Peer<'a> {
    calls: Mutex<Vec<Txid>>,
    callback: Box<dyn Fn(Txid) -> Result<Option<RecordPackage>, Error> + 'a>,
}

impl<'a> Peer<'a> {
    fn new(callback: impl Fn(Txid) -> Result<Option<RecordPackage>, Error> + 'a) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            callback: Box::new(callback),
        }
    }
    fn calls(&self) -> Vec<Txid> {
        self.calls.lock().unwrap().clone()
    }
}

impl RecordSource for Peer<'_> {
    fn fetch(&self, id: Txid) -> Result<Option<RecordPackage>, Error> {
        self.calls.lock().unwrap().push(id);
        (self.callback)(id)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LocatedCall {
    Block(u64),
    Header(u64),
}

struct SlowLocatedSource {
    inner: MemorySource,
    delay_reveal: AtomicBool,
    calls: Mutex<Vec<LocatedCall>>,
}

impl ChainSource for SlowLocatedSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.inner.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.inner.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.lock().unwrap().push(LocatedCall::Header(height));
        self.inner.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.lock().unwrap().push(LocatedCall::Block(height));
        let bytes = self.inner.block(height)?;
        if height == FIRST_HEIGHT + 1 && self.delay_reveal.load(Ordering::Acquire) {
            // Explicitly bounded over-budget callback. It returns normally;
            // only subsequent callback/write boundaries are under test.
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(bytes)
    }
}

fn assert_coverage(actual: &ArchiveStatus, before: &ArchiveStatus) {
    assert_eq!(actual.generation, before.generation);
    assert_eq!(actual.selected_tip, before.selected_tip);
    assert_eq!(actual.indexed_through, before.indexed_through);
    assert_eq!(actual.scanned_blocks, before.scanned_blocks);
    assert_eq!(
        actual.unresolved_dependencies,
        before.unresolved_dependencies
    );
    assert_eq!(actual.scan_rules_version, before.scan_rules_version);
}

fn assert_status(engine: &Engine, before: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(engine.status().unwrap()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

fn assert_cached(engine: &Engine, graph: &Graph) {
    for pair in &graph.pairs {
        let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
        assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
        assert_eq!(record.package.commit, pair.raw_commit);
        assert_eq!(record.receipt.wtxid, pair.reveal.compute_wtxid());
    }
}

fn assert_payload(mut object: RecoveredObject, graph: &Graph) {
    assert_eq!(object.root(), graph.id(0));
    assert_eq!(object.author(), graph.pairs[0].verified.author());
    let mut bytes = Vec::new();
    object.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, graph.payload());
    assert_eq!(object.manifest().length, bytes.len() as u64);
}

fn assert_no_output(scratch: &std::path::Path) {
    assert_eq!(std::fs::read_dir(scratch).unwrap().count(), 0);
}

#[test]
fn pruned_scanned_roots_recover_from_located_full_blocks_without_peers_or_new_coverage() {
    let graph = Graph::load("one", 1);
    let blocks: Vec<_> =
        graph
            .pairs
            .iter()
            .enumerate()
            .fold(Vec::new(), |mut blocks, (i, pair)| {
                blocks.push(witness_block(
                    &pair.transactions(),
                    blocks.last(),
                    i as u32 + 1,
                ));
                blocks
            });
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(&blocks));
    let engine = Engine::open(
        directory.path(),
        config(&blocks[0], Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    for _ in &blocks {
        engine.scan_next().unwrap();
    }
    let before = engine.status().unwrap();
    assert_eq!(before.stored_transactions, 2);
    assert_eq!(before.scanned_blocks, 3);
    assert_eq!(
        before.indexed_through,
        Some(point(FIRST_HEIGHT + 2, &blocks[2]))
    );
    assert!(engine.record(graph.id(0)).unwrap().is_some());
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    assert!(engine.record(graph.id(2)).unwrap().is_none());
    let calls = source.body_calls.load(Ordering::Relaxed);

    assert_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), calls + 2);
    let after = engine.status().unwrap();
    assert_coverage(&after, &before);
    assert_eq!(after.stored_transactions, 6);
    assert_cached(&engine, &graph);
    assert_no_output(scratch.path());
    // Once cached, a second recovery needs neither peer nor full-block calls.
    assert_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), calls + 2);
    drop(engine);
    let db = readonly_archive(directory.path());
    let bytes = stored_bytes(&db);
    assert_eq!(bytes.len(), 6);
    for pair in &graph.pairs {
        assert_eq!(
            bytes.get(&pair.reveal.compute_wtxid().to_string()),
            Some(&pair.raw_reveal)
        );
        assert_eq!(
            bytes.get(&pair.commit.compute_wtxid().to_string()),
            Some(&pair.raw_commit)
        );
    }
    let scans: i64 = db
        .query_row("SELECT count(*) FROM scans", [], |row| row.get(0))
        .unwrap();
    assert_eq!(scans, 3);
}

#[test]
fn headers_only_engine_recovers_from_signed_peer_packages_without_full_block_calls() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let packages = graph.packages(&block, FIRST_HEIGHT);
    let peer = Peer::new(|id| Ok(packages.get(&id).cloned()));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    assert_eq!(before.scanned_blocks, 0);
    assert_eq!(before.indexed_through, None);
    assert_eq!(before.stored_transactions, 0);

    assert_payload(
        recover(
            &engine,
            graph.id(0),
            &[&peer],
            graph.limits(),
            scratch.path(),
        )
        .unwrap(),
        &graph,
    );
    assert_eq!(peer.calls(), [graph.id(0), graph.id(1), graph.id(2)]);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_cached(&engine, &graph);
    fetch_record(&engine, graph.id(1), &[&peer], FetchLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(peer.calls().len(), 3);
    drop(engine);
    let db = readonly_archive(directory.path());
    for table in ["scans", "locators"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[test]
fn stale_primary_package_does_not_block_good_backup() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let good = package(&block, FIRST_HEIGHT, &graph.pairs[0]);
    let mut stale = good.clone();
    stale.block.hash = witness_block(&[], None, 99).block_hash();
    assert_ne!(stale.block.hash, good.block.hash);
    // Identical signed transactions and inclusion proof: only the claimed
    // selected block differs. An untrusted peer cannot declare a local reorg.
    assert_eq!(stale.reveal, good.reveal);
    let reveal: Transaction = deserialize(&stale.reveal.transaction).unwrap();
    VerifiedRecord::verify(graph.id(0), &reveal, &graph.pairs[0].commit).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let primary = Peer::new(|_| Ok(Some(stale.clone())));
    let backup = Peer::new(|_| {
        assert_status(&engine, &before);
        Ok(Some(good.clone()))
    });

    let result = fetch_record(
        &engine,
        graph.id(0),
        &[&primary, &backup],
        FetchLimits::default(),
    );
    assert!(
        result.is_ok(),
        "stale peer package blocked good backup: {result:?}; backup calls: {:?}",
        backup.calls()
    );
    let verified = result.unwrap().unwrap();
    assert_eq!(
        verified.record_bytes(),
        graph.pairs[0].verified.record_bytes()
    );
    assert_eq!(primary.calls(), [graph.id(0)]);
    assert_eq!(backup.calls(), [graph.id(0)]);
    assert_eq!(
        engine.record(graph.id(0)).unwrap().unwrap().package.block,
        good.block
    );
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_primary_proofs_are_rejected_before_good_backup_admission() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let good = package(&block, FIRST_HEIGHT, &graph.pairs[0]);
    let mut bad_inclusion = good.clone();
    bad_inclusion.reveal.witness_path.siblings[0][0] ^= 1;
    assert!(
        bad_inclusion
            .reveal
            .verify(Chain::BitcoinRegtest, &block.header)
            .is_err()
    );
    let mut bad_signature = good.clone();
    let mut reveal: Transaction = deserialize(&good.reveal.transaction).unwrap();
    let mut items = reveal.input[0].witness.to_vec();
    items[0][0] ^= 1;
    reveal.input[0].witness = Witness::from_slice(&items);
    assert_eq!(reveal.compute_txid(), graph.id(0));
    assert!(VerifiedRecord::verify(graph.id(0), &reveal, &graph.pairs[0].commit).is_err());
    bad_signature.reveal.transaction = serialize(&reveal);

    for bad in [bad_inclusion, bad_signature] {
        let directory = tempfile::tempdir().unwrap();
        let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
        let engine = Engine::open(
            directory.path(),
            config(&block, Retention::Pruned),
            Some(source.clone()),
        )
        .unwrap();
        let before = engine.synchronize_headers().unwrap();
        let primary = Peer::new(|_| Ok(Some(bad.clone())));
        assert!(fetch_record(&engine, graph.id(0), &[&primary], FetchLimits::default()).is_err());
        assert_status(&engine, &before);
        assert!(engine.record(graph.id(0)).unwrap().is_none());
        let backup = Peer::new(|_| {
            assert_status(&engine, &before); // Invalid primary never populated cache.
            Ok(Some(good.clone()))
        });
        let verified = fetch_record(
            &engine,
            graph.id(0),
            &[&primary, &backup],
            FetchLimits::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            verified.record_bytes(),
            graph.pairs[0].verified.record_bytes()
        );
        assert_eq!(primary.calls(), [graph.id(0), graph.id(0)]);
        assert_eq!(backup.calls(), [graph.id(0)]);
        assert_coverage(&engine.status().unwrap(), &before);
        assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn valid_package_for_wrong_requested_txid_is_never_admitted() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let wrong = package(&block, FIRST_HEIGHT, &graph.pairs[1]);
    wrong
        .reveal
        .verify(Chain::BitcoinRegtest, &block.header)
        .unwrap();
    let peer = Peer::new(|_| Ok(Some(wrong.clone())));
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();

    let error = fetch_record(&engine, graph.id(0), &[&peer], FetchLimits::default()).unwrap_err();
    assert!(
        error.to_string().contains("candidate TXID mismatch"),
        "{error}"
    );
    assert_eq!(peer.calls(), [graph.id(0)]);
    assert!(engine.record(graph.id(0)).unwrap().is_none());
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    assert_status(&engine, &before);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn missing_locator_never_fabricates_a_full_block_lookup() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let headers = source.header_calls.load(Ordering::Relaxed);

    // The transaction actually exists in the source block, but headers alone
    // do not establish its location. An unknown TXID also cannot invent a query.
    for id in [graph.id(2), Txid::from_byte_array([0x42; 32])] {
        assert!(engine.retrieve_located_record(id).unwrap().is_none());
        assert!(
            fetch_record(&engine, id, &[], FetchLimits::default())
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    assert_eq!(source.header_calls.load(Ordering::Relaxed), headers);
    assert_status(&engine, &before);
}

#[test]
fn missing_later_part_returns_error_without_exporting_partial_payload() {
    let graph = Graph::load("two", 2);
    let block = graph.block(None, 1);
    let mut packages = graph.packages(&block, FIRST_HEIGHT);
    packages.remove(&graph.id(3));
    let peer = Peer::new(|id| Ok(packages.get(&id).cloned()));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();

    let error = recover(
        &engine,
        graph.id(0),
        &[&peer],
        graph.limits(),
        scratch.path(),
    )
    .unwrap_err();
    let Error::Source(cause) = error else {
        panic!("expected incomplete reconstruction: {error}")
    };
    assert!(
        matches!(cause.downcast_ref::<RecoveryError>(), Some(RecoveryError::Incomplete { txid }) if *txid == graph.id(3)),
        "{cause}"
    );
    assert_eq!(
        peer.calls(),
        [graph.id(0), graph.id(1), graph.id(2), graph.id(3)]
    );
    assert!(engine.record(graph.id(2)).unwrap().is_some());
    assert!(engine.record(graph.id(3)).unwrap().is_none());
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_no_output(scratch.path());
}

#[test]
fn authenticated_wrong_reference_hash_is_terminal_without_backup_retry() {
    for (name, child) in [("wrong-leaf-hash", 1), ("wrong-child-hash", 2)] {
        let graph = Graph::load(name, 1);
        let parent = &graph.pairs[child - 1];
        let reference = match parent.verified.decode().unwrap() {
            MultipartRecord::Root(root) => root.entries[0],
            MultipartRecord::Leaf(leaf) => leaf.entries[0],
            _ => panic!("manifest fixture"),
        };
        let request = RecordRequest { reference };
        let verified = request
            .verify(&graph.pairs[child].reveal, &graph.pairs[child].commit)
            .unwrap();
        assert!(request.check_hash(&verified).is_err()); // Genuine authentication, wrong signed reference.
        let block = graph.block(None, 1);
        let packages = graph.packages(&block, FIRST_HEIGHT);
        let primary = Peer::new(|id| Ok(packages.get(&id).cloned()));
        let backup = Peer::new(|id| Ok(packages.get(&id).cloned()));
        let directory = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
        let engine = Engine::open(
            directory.path(),
            config(&block, Retention::Pruned),
            Some(source.clone()),
        )
        .unwrap();
        let before = engine.synchronize_headers().unwrap();

        let error = recover(
            &engine,
            graph.id(0),
            &[&primary, &backup],
            graph.limits(),
            scratch.path(),
        )
        .unwrap_err();
        let Error::Source(cause) = error else {
            panic!("expected invalid reconstructed object: {error}")
        };
        assert!(
            matches!(
                cause.downcast_ref::<RecoveryError>(),
                Some(RecoveryError::InvalidObject(_))
            ),
            "{cause}"
        );
        assert!(
            cause
                .to_string()
                .contains("record hash differs from the signed manifest reference")
        );
        assert_eq!(
            primary.calls(),
            (0..=child).map(|i| graph.id(i)).collect::<Vec<_>>()
        );
        assert!(backup.calls().is_empty());
        assert!(engine.record(graph.id(child)).unwrap().is_some());
        assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
        assert_coverage(&engine.status().unwrap(), &before);
        assert_no_output(scratch.path());
    }
}

#[test]
fn reorg_during_peer_callback_rejects_an_old_selected_package() {
    let graph = Graph::load("one", 1);
    let first = witness_block(&[], None, 1);
    let old = graph.block(Some(&first), 2);
    let replacement = witness_block(&[], Some(&first), 3);
    let old_package = package(&old, FIRST_HEIGHT + 1, &graph.pairs[0]);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(&[first.clone(), old]));
    let engine = Engine::open(
        directory.path(),
        config(&first, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let peer = Peer::new(|_| {
        source.replace_branch(&[first.clone(), replacement.clone()]);
        engine.synchronize_headers().unwrap();
        Ok(Some(old_package.clone()))
    });

    assert!(matches!(
        fetch_record(&engine, graph.id(0), &[&peer], FetchLimits::default()),
        Err(Error::Stale)
    ));
    assert_eq!(peer.calls(), [graph.id(0)]);
    assert!(engine.record(graph.id(0)).unwrap().is_none());
    let after = engine.status().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(
        after.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(after.indexed_through, None);
    assert_eq!(after.scanned_blocks, 0);
    assert_eq!(after.stored_transactions, 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn reorg_during_last_peer_callback_prevents_a_complete_but_stale_object_result() {
    let graph = Graph::load("one", 1);
    let first = witness_block(&[], None, 1);
    let old = graph.block(Some(&first), 2);
    let replacement = witness_block(&graph.pairs[2].transactions(), Some(&first), 3);
    let current_data = package(&replacement, FIRST_HEIGHT + 1, &graph.pairs[2]);
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(&[first.clone(), old.clone()]));
    let engine = Engine::open(
        directory.path(),
        config(&first, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    for pair in &graph.pairs[..2] {
        engine
            .admit_record(package(&old, FIRST_HEIGHT + 1, pair))
            .unwrap();
    }
    let peer = Peer::new(|id| {
        assert_eq!(id, graph.id(2));
        source.replace_branch(&[first.clone(), replacement.clone()]);
        engine.synchronize_headers().unwrap();
        Ok(Some(current_data.clone()))
    });

    // Root/leaf were authenticated before the callback; data is valid under the
    // new selected header and can reconstruct all bytes. Only the final epoch
    // check prevents those mixed-generation bytes being returned as current.
    assert!(matches!(
        recover(
            &engine,
            graph.id(0),
            &[&peer],
            graph.limits(),
            scratch.path()
        ),
        Err(Error::Stale)
    ));
    assert_eq!(peer.calls(), [graph.id(2)]);
    assert!(engine.record(graph.id(0)).unwrap().is_none());
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    assert!(engine.record(graph.id(2)).unwrap().is_some());
    let after = engine.status().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(
        after.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(after.scanned_blocks, 0);
    assert_eq!(after.indexed_through, None);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    assert_no_output(scratch.path());
}

#[test]
fn fetch_source_count_and_zero_deadline_bound_callbacks_without_sleep() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let good = package(&block, FIRST_HEIGHT, &graph.pairs[0]);
    let primary = Peer::new(|_| Ok(None));
    let backup = Peer::new(|_| Ok(Some(good.clone())));
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();

    assert!(
        fetch_record(
            &engine,
            graph.id(0),
            &[&primary, &backup],
            FetchLimits {
                sources: 1,
                ..FetchLimits::default()
            }
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(primary.calls(), [graph.id(0)]);
    assert!(backup.calls().is_empty());
    assert!(matches!(
        fetch_record(
            &engine,
            graph.id(0),
            &[&backup],
            FetchLimits {
                sources: 1,
                timeout: Duration::ZERO
            }
        ),
        Err(Error::Busy(_))
    ));
    assert!(backup.calls().is_empty());
    assert_status(&engine, &before);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);

    // A callback's own timeout is a completed transport error, not a caller
    // forcibly interrupting I/O. A bounded good backup may still satisfy it.
    let timed_out = Peer::new(|_| {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "source-owned timeout",
        )))
    });
    assert!(
        fetch_record(
            &engine,
            graph.id(0),
            &[&timed_out, &backup],
            FetchLimits::default()
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(timed_out.calls(), [graph.id(0)]);
    assert_eq!(backup.calls(), [graph.id(0)]);
    assert_coverage(&engine.status().unwrap(), &before);
}

#[test]
fn located_fetch_expiry_after_reveal_skips_parent_header_and_all_writes() {
    let graph = Graph::load("one", 1);
    let leaf = &graph.pairs[1];
    let parent = witness_block(std::slice::from_ref(&leaf.commit), None, 1);
    let reveal = witness_block(std::slice::from_ref(&leaf.reveal), Some(&parent), 2);
    let source = Arc::new(SlowLocatedSource {
        inner: MemorySource::new(&[parent.clone(), reveal.clone()]),
        delay_reveal: AtomicBool::new(false),
        calls: Mutex::new(Vec::new()),
    });
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&parent, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.scanned_blocks, 2);
    assert_eq!(
        before.indexed_through,
        Some(point(FIRST_HEIGHT + 1, &reveal))
    );
    assert_eq!(before.unresolved_dependencies, 0);
    assert_eq!(before.stored_transactions, 0);
    assert!(engine.record(graph.id(1)).unwrap().is_none());

    // Both locators are known, while leaf/commit bytes were pruned. This
    // fallback needs reveal block -> separate parent block -> header.
    source.calls.lock().unwrap().clear();
    source.delay_reveal.store(true, Ordering::Release);
    let result = fetch_record(
        &engine,
        graph.id(1),
        &[],
        FetchLimits {
            sources: 0,
            timeout: Duration::from_millis(50),
        },
    );
    assert!(matches!(result, Err(Error::Busy(_))), "{result:?}");
    assert_eq!(
        *source.calls.lock().unwrap(),
        [LocatedCall::Block(FIRST_HEIGHT + 1)],
        "an expired reveal callback must not start parent/header callbacks"
    );
    assert_status(&engine, &before);
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    assert!(stored_bytes(&db).is_empty());
    for (table, expected) in [
        ("records", 0),
        ("dependencies", 0),
        ("scans", 2),
        ("locators", 4),
        ("events", 3),
    ] {
        let actual: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(actual, expected, "{table}");
    }
}

#[test]
fn zero_global_recovery_budget_stops_before_root_or_child_peer_callbacks() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let packages = graph.packages(&block, FIRST_HEIGHT);
    let peer = Peer::new(|id| Ok(packages.get(&id).cloned()));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let limits = RecoveryLimits {
        timeout: Duration::ZERO,
        ..graph.limits()
    };
    let before = engine.status().unwrap();
    assert!(matches!(
        recover(&engine, graph.id(0), &[&peer], limits, scratch.path()),
        Err(Error::Busy(_))
    ));
    assert!(peer.calls().is_empty());
    assert_status(&engine, &before);

    engine.admit_record(packages[&graph.id(0)].clone()).unwrap();
    let cached = engine.status().unwrap();
    let error = recover(&engine, graph.id(0), &[&peer], limits, scratch.path()).unwrap_err();
    // The global budget is already exhausted even when the root is cached;
    // expiry must precede any further acquisition, without relying on which
    // layer notices it or on the exact deadline message.
    assert!(matches!(error, Error::Busy(_)), "{error}");
    assert!(peer.calls().is_empty());
    assert_status(&engine, &cached);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    assert_no_output(scratch.path());
}
