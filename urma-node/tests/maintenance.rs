#[allow(dead_code)]
mod common;

use bitcoin::{Block, Txid, consensus::serialize};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, readonly_archive, witness_block,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveStatus, ObjectStatus, RecordPackage, Retention},
    retrieval::RecordSource,
};
use urma_runtime::multipart::RecoveryLimits;

// Unchanged signed public fixtures in witness-authenticated mock blocks.
// No consensus, hard I/O interruption or elapsed deadline claim is made here.
struct Graph {
    pairs: [SignedPair; 3],
    payload_bytes: u64,
}

impl Graph {
    fn load(name: &str) -> Self {
        Self {
            pairs: ["root", "leaf", "part-0"]
                .map(|suffix| SignedPair::load(&format!("multipart/{name}-{suffix}"))),
            payload_bytes: if name == "empty" { 0 } else { 1 },
        }
    }
    fn id(&self, i: usize) -> Txid {
        self.pairs[i].reveal.compute_txid()
    }
    fn block(&self) -> Block {
        let transactions: Vec<_> = self
            .pairs
            .iter()
            .flat_map(SignedPair::transactions)
            .collect();
        witness_block(&transactions, None, 1)
    }
    fn packages(&self, block: &Block) -> BTreeMap<Txid, RecordPackage> {
        self.pairs
            .iter()
            .map(|pair| (pair.reveal.compute_txid(), package(block, pair)))
            .collect()
    }
}

fn limits() -> RecoveryLimits {
    RecoveryLimits {
        timeout: Duration::from_secs(5),
        ..RecoveryLimits::new(1, 3)
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
            position as u32,
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

struct Peer<F> {
    callback: F,
    calls: Mutex<Vec<Txid>>,
}
impl<F: Fn(Txid) -> Result<Option<RecordPackage>, Error>> Peer<F> {
    fn new(callback: F) -> Self {
        Self {
            callback,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<Txid> {
        self.calls.lock().unwrap().clone()
    }
}
impl<F: Fn(Txid) -> Result<Option<RecordPackage>, Error>> RecordSource for Peer<F> {
    fn fetch(&self, id: Txid) -> Result<Option<RecordPackage>, Error> {
        self.calls.lock().unwrap().push(id);
        (self.callback)(id)
    }
}

fn two_roots() -> (Graph, Graph, Block) {
    let first = Graph::load("empty");
    let second = Graph::load("one");
    // The archive cursor orders the displayed TXID strings. Do not depend on
    // block position or internal consensus-byte ordering to choose the first.
    assert!(first.id(0).to_string() < second.id(0).to_string());
    let transactions: Vec<_> = first
        .pairs
        .iter()
        .chain(&second.pairs)
        .flat_map(SignedPair::transactions)
        .collect();
    (first, second, witness_block(&transactions, None, 1))
}

fn source_calls(source: &MemorySource) -> (usize, usize) {
    (
        source.header_calls.load(Ordering::Relaxed),
        source.body_calls.load(Ordering::Relaxed),
    )
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

fn assert_complete(status: &ObjectStatus, graph: &Graph, generation: u64) {
    assert_eq!(status.root, graph.id(0));
    assert_eq!(status.verified_generation, generation);
    assert_eq!(status.payload_bytes, graph.payload_bytes);
    assert_eq!(status.members_total, 3);
    assert_eq!(status.members_local, 3);
    assert_eq!(status.members_selected, 3);
    assert!(status.locally_complete());
    assert!(status.selected_complete());
    assert!(!status.pinned);
}

fn assert_no_publication(directory: &std::path::Path) {
    // Engine has been dropped. Inspect READONLY; never alter archive state.
    let db = readonly_archive(directory);
    for table in ["objects", "object_members", "pins"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind IN ('object','pin')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn pruned_maintenance_is_noop_even_with_selected_unretained_roots() {
    let graph = Graph::load("one");
    let block = graph.block();
    let packages = graph.packages(&block);
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
    let before = engine.scan_next().unwrap();
    assert_eq!(before.stored_transactions, 2);
    let calls = source_calls(&source);

    assert!(
        engine
            .retain_next_object(&[&peer], limits(), scratch.path(), &AtomicBool::new(false))
            .unwrap()
            .is_none()
    );
    assert!(peer.calls().is_empty());
    assert_eq!(source_calls(&source), calls);
    assert!(engine.object_status(graph.id(0)).unwrap().is_none());
    assert_status(&engine, &before);
    drop(engine);
    assert_no_publication(directory.path());
}

#[test]
fn cached_unpruned_roots_complete_one_per_call_then_skip_without_acquisition() {
    let (first, second, block) = two_roots();
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.stored_transactions, 12);
    assert!(engine.object_status(first.id(0)).unwrap().is_none());
    assert!(engine.object_status(second.id(0)).unwrap().is_none());
    let calls = source_calls(&source);
    let peer = Peer::new(|_| panic!("complete cached records must not fetch from a peer"));
    let cancelled = AtomicBool::new(false);

    let result = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap()
        .unwrap();
    assert_complete(&result, &first, before.generation);
    assert!(engine.object_status(second.id(0)).unwrap().is_none()); // Only one attempt.
    let result = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap()
        .unwrap();
    assert_complete(&result, &second, before.generation);
    for _ in 0..3 {
        assert!(
            engine
                .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
                .unwrap()
                .is_none()
        );
    }
    assert!(peer.calls().is_empty());
    assert_eq!(source_calls(&source), calls);
    assert_status(&engine, &before);
    for graph in [&first, &second] {
        assert_complete(
            &engine.object_status(graph.id(0)).unwrap().unwrap(),
            graph,
            before.generation,
        );
        for pair in &graph.pairs {
            let cached = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
            assert_eq!(cached.package.reveal.transaction, pair.raw_reveal);
            assert_eq!(cached.package.commit, pair.raw_commit);
        }
    }
    drop(engine);
    let db = readonly_archive(directory.path());
    let completions: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind='object'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(completions, 2); // Complete roots skipped across repeated cursor wraps.
}

#[test]
fn failed_first_root_advances_cursor_instead_of_starving_the_second() {
    let (first, second, block) = two_roots();
    let available = second.packages(&block);
    let peer = Peer::new(|id| Ok(available.get(&id).cloned()));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    // Roots are authenticated and selected, but neither children nor locators
    // were acquired. Full-block fallback cannot bypass the missing first leaf.
    for graph in [&first, &second] {
        engine
            .admit_record(package(&block, &graph.pairs[0]))
            .unwrap();
    }
    let before = engine.status().unwrap();
    let calls = source_calls(&source);
    let cancelled = AtomicBool::new(false);

    let error = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap_err();
    assert!(error.to_string().contains("incomplete object"), "{error}");
    assert_eq!(peer.calls(), [first.id(1)]);
    assert!(engine.object_status(first.id(0)).unwrap().is_none());
    assert!(engine.object_status(second.id(0)).unwrap().is_none());
    assert_status(&engine, &before);
    let result = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap()
        .unwrap();
    assert_complete(&result, &second, before.generation);
    assert_eq!(peer.calls(), [first.id(1), second.id(1), second.id(2)]);
    assert!(engine.object_status(first.id(0)).unwrap().is_none());
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(source_calls(&source), calls);
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn precancelled_maintenance_does_no_work_or_cursor_advancement() {
    let (first, second, block) = two_roots();
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    let calls = source_calls(&source);
    let peer = Peer::new(|_| panic!("pre-cancelled or fully cached work must not fetch"));
    let cancelled = AtomicBool::new(true);

    assert!(matches!(
        engine.retain_next_object(&[&peer], limits(), scratch.path(), &cancelled),
        Err(Error::Busy(_))
    ));
    assert!(peer.calls().is_empty());
    assert_eq!(source_calls(&source), calls);
    assert!(engine.object_status(first.id(0)).unwrap().is_none());
    assert!(engine.object_status(second.id(0)).unwrap().is_none());
    assert_status(&engine, &before);
    cancelled.store(false, Ordering::Release);
    let result = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap()
        .unwrap();
    assert_complete(&result, &first, before.generation); // Pre-cancel did not consume first root.
    assert!(engine.object_status(second.id(0)).unwrap().is_none());
    assert_eq!(source_calls(&source), calls);
    assert_status(&engine, &before);
}

#[test]
fn callback_cancellation_skips_further_children_or_finalization_without_publication() {
    let graph = Graph::load("one");
    let block = graph.block();
    let packages = graph.packages(&block);
    for cancel_at in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
        let engine = Engine::open(
            directory.path(),
            config(&block, Retention::Unpruned),
            Some(source.clone()),
        )
        .unwrap();
        engine.synchronize_headers().unwrap();
        engine
            .admit_record(package(&block, &graph.pairs[0]))
            .unwrap();
        let before = engine.status().unwrap();
        let calls = source_calls(&source);
        let cancelled = AtomicBool::new(false);
        let peer = Peer::new(|id| {
            if id == graph.id(cancel_at) {
                cancelled.store(true, Ordering::Release);
            }
            // The in-flight callback still returns normally. Independently
            // verified cache admission may survive the cancelled recovery.
            Ok(packages.get(&id).cloned())
        });

        let error = engine
            .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
            .unwrap_err();
        assert!(
            error.to_string().contains("object retention cancelled"),
            "{error}"
        );
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(
            peer.calls(),
            (1..=cancel_at).map(|i| graph.id(i)).collect::<Vec<_>>()
        );
        assert!(engine.object_status(graph.id(0)).unwrap().is_none());
        assert_coverage(&engine.status().unwrap(), &before);
        assert_eq!(source_calls(&source), calls);
        for pair in &graph.pairs {
            if let Some(record) = engine.record(pair.reveal.compute_txid()).unwrap() {
                assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
                assert_eq!(record.package.commit, pair.raw_commit);
            }
        }
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
        drop(engine);
        assert_no_publication(directory.path());
    }
}

#[test]
fn peer_callback_can_read_status_while_reentrant_maintenance_returns_busy() {
    let graph = Graph::load("one");
    let block = graph.block();
    let packages = graph.packages(&block);
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    engine
        .admit_record(package(&block, &graph.pairs[0]))
        .unwrap();
    let before = engine.status().unwrap();
    let calls = source_calls(&source);
    let cancelled = AtomicBool::new(false);
    let peer = Peer::new(|id| {
        // Direct reentrant calls, no threads/sleeps. Status would deadlock if
        // the archive mutex remained held over this peer callback.
        let callback_status = engine.status().unwrap();
        assert_coverage(&callback_status, &before);
        assert!(matches!(
            engine.retain_next_object(&[], limits(), scratch.path(), &AtomicBool::new(false)),
            Err(Error::Busy(_))
        ));
        assert_status(&engine, &callback_status);
        assert!(engine.object_status(graph.id(0)).unwrap().is_none());
        Ok(packages.get(&id).cloned())
    });

    let result = engine
        .retain_next_object(&[&peer], limits(), scratch.path(), &cancelled)
        .unwrap()
        .unwrap();
    assert_complete(&result, &graph, before.generation);
    assert_eq!(peer.calls(), [graph.id(1), graph.id(2)]);
    assert_eq!(source_calls(&source), calls);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}
