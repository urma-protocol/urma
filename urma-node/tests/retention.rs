#[allow(dead_code)]
mod common;

use bitcoin::{
    Block, Transaction, Txid, Witness,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive, stored_bytes,
    witness_block,
};
use rusqlite::Connection;
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::multipart::{MultipartRecord, VerifiedRecord};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveStatus, ObjectStatus, RecordPackage, Retention},
    retrieval::{RecordSource, recover, recover_and_pin},
};
use urma_runtime::multipart::{RecoveredObject, RecoveryLimits};

// Public, genuinely signed fixtures in witness-authenticated mock blocks.
// This exercises archive/recovery evidence, without a consensus claim.
struct Graph {
    pairs: Vec<SignedPair>,
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
    fn id(&self, i: usize) -> Txid {
        self.pairs[i].reveal.compute_txid()
    }
    fn transactions(&self) -> Vec<Transaction> {
        self.pairs
            .iter()
            .flat_map(SignedPair::transactions)
            .collect()
    }
    fn block(&self, previous: Option<&Block>, nonce: u32) -> Block {
        witness_block(&self.transactions(), previous, nonce)
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
    fn packages(&self, block: &Block, height: u64) -> BTreeMap<Txid, RecordPackage> {
        self.pairs
            .iter()
            .map(|pair| (pair.reveal.compute_txid(), package(block, height, pair)))
            .collect()
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

struct Peer<F>(F);
impl<F: Fn(Txid) -> Result<Option<RecordPackage>, Error>> RecordSource for Peer<F> {
    fn fetch(&self, id: Txid) -> Result<Option<RecordPackage>, Error> {
        (self.0)(id)
    }
}

fn read_payload(mut object: RecoveredObject, graph: &Graph) {
    assert_eq!(object.root(), graph.id(0));
    assert_eq!(object.author(), graph.pairs[0].verified.author());
    let mut payload = Vec::new();
    object.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, graph.payload());
}

fn recover_mode(
    engine: &Engine,
    graph: &Graph,
    peers: &[&dyn RecordSource],
    scratch: &Path,
    pin: bool,
) -> Result<RecoveredObject, Error> {
    if pin {
        recover_and_pin(engine, graph.id(0), peers, graph.limits(), scratch)
    } else {
        recover(engine, graph.id(0), peers, graph.limits(), scratch)
    }
}

fn assert_object(
    engine: &Engine,
    graph: &Graph,
    generation: u64,
    local: u64,
    selected: u64,
    pinned: bool,
) -> ObjectStatus {
    let status = engine.object_status(graph.id(0)).unwrap().unwrap();
    assert_eq!(status.root, graph.id(0));
    assert_eq!(status.verified_generation, generation);
    assert_eq!(status.payload_bytes, graph.payload().len() as u64);
    assert_eq!(status.members_total, graph.pairs.len() as u64); // Includes root.
    assert_eq!(status.members_local, local);
    assert_eq!(status.members_selected, selected); // Independent of local bytes.
    assert_eq!(status.pinned, pinned);
    assert_eq!(status.locally_complete(), local == status.members_total);
    assert_eq!(
        status.selected_complete(),
        local == status.members_total && selected == status.members_total
    );
    status
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

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn assert_no_completion(engine: &Engine, root: Txid) {
    assert!(engine.object_status(root).unwrap().is_none());
    assert!(matches!(engine.set_pin(root, true), Err(Error::Invalid(_))));
    engine.set_pin(root, false).unwrap();
    engine.set_pin(root, false).unwrap();
}

// All SQL inspection uses a separate READONLY handle after dropping Engine.
fn assert_no_completion_rows(directory: &Path) {
    let db = readonly_archive(directory);
    for table in ["objects", "object_members", "pins"] {
        assert_eq!(count(&db, table), 0, "{table}");
    }
    let events: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind IN ('object','pin')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 0);
}

fn assert_raw(db: &Connection, pairs: &[SignedPair]) {
    let bytes = stored_bytes(db);
    for pair in pairs {
        assert_eq!(
            bytes.get(&pair.reveal.compute_wtxid().to_string()),
            Some(&pair.raw_reveal)
        );
        assert_eq!(
            bytes.get(&pair.commit.compute_wtxid().to_string()),
            Some(&pair.raw_commit)
        );
    }
}

type MemberRow = (String, String, u32, String, Vec<u8>);

fn member_rows(db: &Connection, root: Txid) -> Vec<MemberRow> {
    db.prepare("SELECT txid,block_hash,position,wtxid,record_hash FROM object_members WHERE root_txid=?1 ORDER BY txid")
        .unwrap()
        .query_map([root.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn pruned_recovery_eviction_pin_and_unpin_preserve_evidence_and_coverage() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.stored_transactions, 2); // Root and its exact commit only.
    assert_eq!(before.indexed_through, Some(point(FIRST_HEIGHT, &block)));
    assert!(engine.object_status(graph.id(0)).unwrap().is_none());

    read_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, before.generation, 3, 3, false);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(engine.status().unwrap().stored_transactions, 6);
    assert_eq!(engine.prune_cache().unwrap(), 2); // Records, not four raw transactions.
    assert_object(&engine, &graph, before.generation, 1, 3, false);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(engine.status().unwrap().stored_transactions, 2);
    assert!(engine.record(graph.id(0)).unwrap().is_some());
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    assert!(engine.record(graph.id(2)).unwrap().is_none());
    assert!(matches!(
        engine.set_pin(graph.id(0), true),
        Err(Error::Invalid(_))
    ));
    assert_eq!(engine.prune_cache().unwrap(), 0);

    read_payload(
        recover_and_pin(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, before.generation, 3, 3, true);
    let pinned = engine.status().unwrap();
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_status(&engine, &pinned);
    engine.set_pin(graph.id(0), false).unwrap();
    engine.set_pin(graph.id(0), false).unwrap();
    assert_object(&engine, &graph, before.generation, 3, 3, false);
    assert_eq!(engine.prune_cache().unwrap(), 2);
    assert_object(&engine, &graph, before.generation, 1, 3, false);
    assert_coverage(&engine.status().unwrap(), &before);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_raw(&db, &graph.pairs[..1]);
    assert_eq!(stored_bytes(&db).len(), 2);
    for (table, expected) in [
        ("objects", 1),
        ("object_members", 3),
        ("pins", 0),
        ("records", 1),
        ("locators", 7),
        ("scans", 1),
        ("dependencies", 0),
    ] {
        assert_eq!(count(&db, table), expected, "{table}");
    }
}

#[test]
fn pin_requires_successful_reconstruction_and_complete_local_storage() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
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
    assert_no_completion(&engine, Txid::from_byte_array([0x42; 32]));
    assert_status(&engine, &before);
    for pair in &graph.pairs {
        engine
            .admit_record(package(&block, FIRST_HEIGHT, pair))
            .unwrap();
    }
    // Having individually authenticated every record is not completion evidence.
    assert_no_completion(&engine, graph.id(0));
    read_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, before.generation, 3, 3, false);
    engine.set_pin(graph.id(0), true).unwrap();
    engine.set_pin(graph.id(0), true).unwrap();
    assert_object(&engine, &graph, before.generation, 3, 3, true);
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_coverage(&engine.status().unwrap(), &before);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn unpruned_cache_maintenance_is_a_noop_for_unpinned_objects() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    assert!(engine.object_status(graph.id(0)).unwrap().is_none());
    read_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    let before = engine.status().unwrap();
    assert_object(&engine, &graph, before.generation, 3, 3, false);
    for _ in 0..2 {
        assert_eq!(engine.prune_cache().unwrap(), 0);
    }
    assert_status(&engine, &before);
    assert_object(&engine, &graph, before.generation, 3, 3, false);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_raw(&db, &graph.pairs);
    assert_eq!(stored_bytes(&db).len(), 6);
    let prune_events: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE kind='prune'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(prune_events, 0);
}

#[test]
fn incomplete_or_invalid_children_never_publish_completion_or_pin() {
    for scenario in [
        "missing",
        "invalid-proof",
        "wrong-child-hash",
        "wrong-digest",
    ] {
        let graph = Graph::load(
            match scenario {
                "missing" => "two",
                "invalid-proof" => "one",
                name => name,
            },
            if scenario == "missing" { 2 } else { 1 },
        );
        let block = graph.block(None, 1);
        let mut packages = graph.packages(&block, FIRST_HEIGHT);
        if scenario == "missing" {
            packages.remove(&graph.id(3));
        }
        if scenario == "invalid-proof" {
            let bad = packages.get_mut(&graph.id(1)).unwrap();
            let mut reveal: Transaction = deserialize(&bad.reveal.transaction).unwrap();
            let mut witness = reveal.input[0].witness.to_vec();
            witness[0][0] ^= 1;
            reveal.input[0].witness = Witness::from_slice(&witness);
            assert_eq!(reveal.compute_txid(), graph.id(1));
            assert!(VerifiedRecord::verify(graph.id(1), &reveal, &graph.pairs[1].commit).is_err());
            bad.reveal.transaction = serialize(&reveal);
        }
        for pin in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let scratch = tempfile::tempdir().unwrap();
            let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
            let engine = Engine::open(
                directory.path(),
                config(&block, Retention::Pruned),
                Some(source.clone()),
            )
            .unwrap();
            let before = engine.synchronize_headers().unwrap(); // No locators to bypass a missing peer child.
            let peer = Peer(|id| Ok(packages.get(&id).cloned()));
            let error = recover_mode(&engine, &graph, &[&peer], scratch.path(), pin).unwrap_err();
            match scenario {
                "missing" => assert!(error.to_string().contains("incomplete object"), "{error}"),
                "wrong-child-hash" => assert!(
                    error.to_string().contains("signed manifest reference"),
                    "{error}"
                ),
                "wrong-digest" => assert!(
                    error
                        .to_string()
                        .contains("complete payload length or digest mismatch"),
                    "{error}"
                ),
                _ => assert!(
                    !error.to_string().contains("signed manifest reference"),
                    "{error}"
                ),
            }
            assert!(engine.record(graph.id(0)).unwrap().is_some());
            assert_no_completion(&engine, graph.id(0));
            assert_coverage(&engine.status().unwrap(), &before);
            assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
            assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
            drop(engine);
            assert_no_completion_rows(directory.path());
        }
    }
}

#[test]
fn pinned_orphan_members_survive_restart_and_prune_but_lose_selected_status() {
    let graph = Graph::load("one", 1);
    let mut blocks = Vec::new();
    for (i, pair) in graph.pairs.iter().enumerate() {
        blocks.push(witness_block(
            &pair.transactions(),
            blocks.last(),
            i as u32 + 1,
        ));
    }
    let source = Arc::new(MemorySource::new(&blocks));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let cfg = config(&blocks[0], Retention::Pruned);
    let engine = Engine::open(directory.path(), cfg.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    for _ in &blocks {
        engine.scan_next().unwrap();
    }
    let generation = engine.status().unwrap().generation;
    read_payload(
        recover_and_pin(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, generation, 3, 3, true);
    drop(engine);
    {
        let db = readonly_archive(directory.path());
        assert_raw(&db, &graph.pairs);
    }

    let engine = Engine::open(directory.path(), cfg.clone(), Some(source.clone())).unwrap();
    assert_object(&engine, &graph, generation, 3, 3, true);
    let replacement_leaf = witness_block(&[], Some(&blocks[0]), 11);
    let replacement_data = witness_block(&[], Some(&replacement_leaf), 12);
    source.replace_branch(&[
        blocks[0].clone(),
        replacement_leaf,
        replacement_data.clone(),
    ]);
    let reorg = engine.synchronize_headers().unwrap();
    assert_eq!(reorg.generation, generation + 1);
    assert_eq!(
        reorg.selected_tip,
        Some(point(FIRST_HEIGHT + 2, &replacement_data))
    );
    assert_eq!(reorg.indexed_through, Some(point(FIRST_HEIGHT, &blocks[0])));
    assert_object(&engine, &graph, generation, 3, 1, true);
    assert!(engine.record(graph.id(1)).unwrap().is_none());
    assert!(engine.record(graph.id(2)).unwrap().is_none());
    assert_eq!(engine.prune_cache().unwrap(), 0); // Protect pinned historical placements.
    assert_status(&engine, &reorg);
    engine.set_pin(graph.id(0), false).unwrap();
    engine.set_pin(graph.id(0), true).unwrap(); // Local completeness suffices after reorg.
    assert_object(&engine, &graph, generation, 3, 1, true);
    drop(engine);
    {
        let db = readonly_archive(directory.path());
        assert_raw(&db, &graph.pairs);
        assert_eq!(count(&db, "pins"), 1);
    }
    let offline = Engine::open(directory.path(), cfg, None).unwrap();
    assert_object(&offline, &graph, generation, 3, 1, true);
    assert_eq!(offline.prune_cache().unwrap(), 0);
    assert_status(&offline, &reorg);
    offline.set_pin(graph.id(0), false).unwrap();
    assert_eq!(offline.prune_cache().unwrap(), 2);
    assert_object(&offline, &graph, generation, 1, 1, false);
    assert_coverage(&offline.status().unwrap(), &reorg);
    drop(offline);
    let db = readonly_archive(directory.path());
    assert_raw(&db, &graph.pairs[..1]);
    assert_eq!(stored_bytes(&db).len(), 2);
    assert_eq!(count(&db, "objects"), 1);
    assert_eq!(count(&db, "object_members"), 3);
}

#[test]
fn pinned_members_refuse_new_placement_until_explicit_unpin_then_rebind() {
    let graph = Graph::load("one", 1);
    let root_block = witness_block(&graph.pairs[0].transactions(), None, 1);
    let children: Vec<_> = graph.pairs[1..]
        .iter()
        .flat_map(SignedPair::transactions)
        .collect();
    let old = witness_block(&children, Some(&root_block), 2);
    let replacement = witness_block(&children, Some(&root_block), 12);
    assert_ne!(old.block_hash(), replacement.block_hash());
    let source = Arc::new(MemorySource::new(&[root_block.clone(), old]));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let cfg = config(&root_block, Retention::Pruned);
    let engine = Engine::open(directory.path(), cfg.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let original_generation = engine.scan_next().unwrap().generation;
    read_payload(
        recover_and_pin(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, original_generation, 3, 3, true);
    drop(engine);
    let original_members = {
        let db = readonly_archive(directory.path());
        member_rows(&db, graph.id(0))
    };
    for pair in &graph.pairs {
        let row = original_members
            .iter()
            .find(|row| row.0 == pair.reveal.compute_txid().to_string())
            .unwrap();
        assert_eq!(row.3, pair.reveal.compute_wtxid().to_string());
        assert_eq!(row.4, pair.verified.reference().record_hash);
    }

    let engine = Engine::open(directory.path(), cfg.clone(), Some(source.clone())).unwrap();
    source.replace_branch(&[root_block.clone(), replacement.clone()]);
    engine.synchronize_headers().unwrap();
    let current = engine.scan_next().unwrap(); // Establish current full-block locators.
    assert_eq!(current.generation, original_generation + 1);
    assert_object(&engine, &graph, original_generation, 3, 1, true);
    for pin in [false, true] {
        let error = recover_mode(&engine, &graph, &[], scratch.path(), pin).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)), "{error}");
        assert!(error.to_string().contains("explicitly unpin"), "{error}");
        assert_object(&engine, &graph, original_generation, 3, 1, true);
        assert_coverage(&engine.status().unwrap(), &current);
    }
    // The attempted recoveries cached children at their new placement, but
    // could not redirect protection away from the pinned historical members.
    assert_eq!(engine.prune_cache().unwrap(), 2);
    assert_object(&engine, &graph, original_generation, 3, 1, true);
    assert_eq!(engine.status().unwrap().stored_transactions, 6);
    drop(engine);
    {
        let db = readonly_archive(directory.path());
        assert_eq!(member_rows(&db, graph.id(0)), original_members);
        assert_raw(&db, &graph.pairs);
        assert_eq!(count(&db, "pins"), 1);
        let completions: i64 = db
            .query_row(
                "SELECT count(*) FROM events WHERE kind='object'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(completions, 1); // Neither rejected recovery published completion.
    }

    let engine = Engine::open(directory.path(), cfg, Some(source)).unwrap();
    engine.set_pin(graph.id(0), false).unwrap();
    read_payload(
        recover_and_pin(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_object(&engine, &graph, current.generation, 3, 3, true);
    assert_eq!(engine.prune_cache().unwrap(), 2); // Old orphan placements now unprotected.
    assert_object(&engine, &graph, current.generation, 3, 3, true);
    assert_coverage(&engine.status().unwrap(), &current);
    drop(engine);
    let db = readonly_archive(directory.path());
    let rebound = member_rows(&db, graph.id(0));
    assert_ne!(rebound, original_members);
    for row in rebound {
        assert_eq!(
            row.1,
            if row.0 == graph.id(0).to_string() {
                root_block.block_hash()
            } else {
                replacement.block_hash()
            }
            .to_string()
        );
    }
    // Raw WTXID bytes shared by old/new placements survive GC while any
    // surviving pinned record still references them.
    assert_raw(&db, &graph.pairs);
    assert_eq!(stored_bytes(&db).len(), 6);
    assert_eq!(count(&db, "records"), 3);
    assert_eq!(count(&db, "object_members"), 3);
    assert_eq!(count(&db, "pins"), 1);
}

#[test]
fn one_pinned_object_does_not_protect_unrelated_unpinned_children() {
    let pinned = Graph::load("one", 1);
    let cached = Graph::load("opaque-manifest", 1);
    let transactions = [pinned.transactions(), cached.transactions()].concat();
    let block = witness_block(&transactions, None, 1);
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    read_payload(
        recover_and_pin(&engine, pinned.id(0), &[], pinned.limits(), scratch.path()).unwrap(),
        &pinned,
    );
    read_payload(
        recover(&engine, cached.id(0), &[], cached.limits(), scratch.path()).unwrap(),
        &cached,
    );
    assert_eq!(engine.prune_cache().unwrap(), 2);
    assert_object(&engine, &pinned, before.generation, 3, 3, true);
    assert_object(&engine, &cached, before.generation, 1, 3, false);
    assert_coverage(&engine.status().unwrap(), &before);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_raw(&db, &pinned.pairs);
    assert_raw(&db, &cached.pairs[..1]);
    assert_eq!(stored_bytes(&db).len(), 8);
    assert_eq!(count(&db, "objects"), 2);
    assert_eq!(count(&db, "object_members"), 6);
    assert_eq!(count(&db, "pins"), 1);
}

#[test]
fn reorg_during_recovery_never_publishes_completion_or_pin() {
    let graph = Graph::load("one", 1);
    let first = witness_block(&[], None, 1);
    let old = graph.block(Some(&first), 2);
    let replacement = witness_block(&graph.pairs[2].transactions(), Some(&first), 3);
    let current = package(&replacement, FIRST_HEIGHT + 1, &graph.pairs[2]);
    for pin in [false, true] {
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
        let peer = Peer(|id| {
            assert_eq!(id, graph.id(2));
            source.replace_branch(&[first.clone(), replacement.clone()]);
            engine.synchronize_headers().unwrap();
            Ok(Some(current.clone()))
        });
        assert!(matches!(
            recover_mode(&engine, &graph, &[&peer], scratch.path(), pin),
            Err(Error::Stale)
        ));
        assert_eq!(engine.status().unwrap().generation, before.generation + 1);
        assert!(engine.record(graph.id(2)).unwrap().is_some());
        assert_no_completion(&engine, graph.id(0));
        assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
        drop(engine);
        assert_no_completion_rows(directory.path());
    }
}

#[test]
fn eviction_between_child_callbacks_refuses_completion_and_atomic_pin() {
    let graph = Graph::load("one", 1);
    let block = graph.block(None, 1);
    let packages = graph.packages(&block, FIRST_HEIGHT);
    for pin in [false, true] {
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
        let peer = Peer(|id| {
            if id == graph.id(2) {
                assert!(engine.record(graph.id(1)).unwrap().is_some());
                assert_eq!(engine.prune_cache().unwrap(), 1);
            }
            Ok(packages.get(&id).cloned())
        });
        // Reconstruction consumed the leaf before eviction and can assemble
        // all bytes. Finalization must recheck local identities atomically.
        let error = recover_mode(&engine, &graph, &[&peer], scratch.path(), pin).unwrap_err();
        assert!(matches!(error, Error::Busy(_)), "{error}");
        assert!(engine.record(graph.id(1)).unwrap().is_none());
        assert!(engine.record(graph.id(2)).unwrap().is_some());
        assert_no_completion(&engine, graph.id(0));
        assert_coverage(&engine.status().unwrap(), &before);
        assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
        drop(engine);
        assert_no_completion_rows(directory.path());
    }
}

#[test]
fn pruning_children_preserves_application_records_pending_dependencies_and_locators() {
    let graph = Graph::load("one", 1);
    let application = profile();
    let pending = SignedPair::load("proof-post");
    let mut transactions = graph.transactions();
    transactions.extend(application.transactions());
    transactions.push(pending.reveal.clone()); // Commit unavailable: genuine unresolved dependency.
    let block = witness_block(&transactions, None, 1);
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.unresolved_dependencies, 1);
    assert_eq!(before.indexed_through, None);
    read_payload(
        recover(&engine, graph.id(0), &[], graph.limits(), scratch.path()).unwrap(),
        &graph,
    );
    assert_eq!(engine.prune_cache().unwrap(), 2);
    assert_coverage(&engine.status().unwrap(), &before);
    let kept = engine
        .record(application.reveal.compute_txid())
        .unwrap()
        .unwrap();
    assert_eq!(kept.package.reveal.transaction, application.raw_reveal);
    assert_eq!(kept.package.commit, application.raw_commit);
    assert_object(&engine, &graph, before.generation, 1, 3, false);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_raw(&db, &graph.pairs[..1]);
    assert_raw(&db, std::slice::from_ref(&application));
    assert_eq!(stored_bytes(&db).len(), 4);
    for (table, expected) in [
        ("records", 2),
        ("locators", 10),
        ("scans", 1),
        ("dependencies", 1),
    ] {
        assert_eq!(count(&db, table), expected, "{table}");
    }
    let proof: Vec<u8> = db
        .query_row("SELECT proof FROM dependencies", [], |row| row.get(0))
        .unwrap();
    let proof: TransactionProof = serde_json::from_slice(&proof).unwrap();
    assert_eq!(proof.transaction, pending.raw_reveal);
    proof.verify(Chain::BitcoinRegtest, &block.header).unwrap();
}
