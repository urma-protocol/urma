//! Logical cache accounting in owned Linux TEMP archives. Signed public records
//! have real proofs in witness-authenticated mock-selected blocks; duplicate
//! placements make no UTXO, PoW, script validity or consensus claim. Closed-DB
//! raw-only/trigger fixtures are explicitly trusted storage fixtures, not
//! admissions, source observations or fabricated scan coverage.
#[allow(dead_code)]
mod common;

use bitcoin::{Block, Transaction, Txid, Witness, absolute::LockTime, consensus::serialize};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive, stored_bytes,
    witness_block,
};
use rusqlite::{Connection, params, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    cache::{MAX_CACHE_RECORDS, MAX_CACHE_TRANSACTIONS},
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, ArchiveStatus, RecordPackage, Retention},
    retrieval::recover_and_pin,
};
use urma_runtime::multipart::RecoveryLimits;

type Placement = (String, u32);
type Evidence = BTreeMap<Placement, (Vec<u8>, Vec<u8>)>;
type Snapshot = BTreeMap<String, Vec<Vec<Value>>>;

struct Graph(Vec<SignedPair>);
impl Graph {
    fn load() -> Self {
        Self(
            ["root", "leaf", "part-0"]
                .map(|part| SignedPair::load(&format!("multipart/one-{part}")))
                .into(),
        )
    }
    fn id(&self, index: usize) -> Txid {
        self.0[index].reveal.compute_txid()
    }
    fn transactions(&self) -> Vec<Transaction> {
        self.0.iter().flat_map(SignedPair::transactions).collect()
    }
    fn pin(&self, engine: &Engine, scratch: &Path) {
        let MultipartRecord::Data(data) = self.0[2].verified.decode().unwrap() else {
            panic!("public data fixture")
        };
        let limits = RecoveryLimits {
            timeout: Duration::from_secs(5),
            ..RecoveryLimits::new(data.payload.len() as u64, 3)
        };
        let mut object = recover_and_pin(engine, self.id(0), &[], limits, scratch).unwrap();
        let mut bytes = Vec::new();
        object.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, data.payload);
    }
}

fn package(block: &Block, height: u64, pair: &SignedPair) -> RecordPackage {
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_wtxid() == pair.reveal.compute_wtxid())
        .unwrap() as u32;
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(height, block),
        reveal: TransactionProof::from_block(
            block,
            position,
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

fn admit(engine: &Engine, block: &Block, height: u64, pair: &SignedPair, evidence: &mut Evidence) {
    let package = package(block, height, pair);
    let proof = serde_json::to_vec(&package.reveal).unwrap();
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_wtxid() == pair.reveal.compute_wtxid())
        .unwrap() as u32;
    engine.admit_record(package).unwrap();
    assert!(
        evidence
            .insert(
                (block.block_hash().to_string(), position),
                (pair.verified.record_bytes().to_vec(), proof)
            )
            .is_none()
    );
}

fn open(directory: &Path, cfg: &ArchiveConfig, source: &Arc<MemorySource>) -> Engine {
    Engine::open(directory, cfg.clone(), Some(source.clone())).unwrap()
}
fn calls(source: &MemorySource) -> (usize, usize) {
    (
        source.body_calls.load(Ordering::Relaxed),
        source.header_calls.load(Ordering::Relaxed),
    )
}
fn coverage(engine: &Engine, before: &ArchiveStatus) {
    let after = engine.status().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.selected_tip, before.selected_tip);
    assert_eq!(after.indexed_through, before.indexed_through);
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(
        after.unresolved_dependencies,
        before.unresolved_dependencies
    );
    assert_eq!(after.scan_rules_version, before.scan_rules_version);
}
fn count(db: &Connection, table: &str) -> u64 {
    let value = db
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    u64::try_from(value).unwrap()
}
fn cache_events(db: &Connection) -> u64 {
    let value = db
        .query_row("SELECT count(*) FROM events WHERE kind='cache'", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    u64::try_from(value).unwrap()
}
fn object_status(engine: &Engine, root: Txid) -> serde_json::Value {
    serde_json::to_value(engine.object_status(root).unwrap().unwrap()).unwrap()
}

// Read committed table values independently; also usable with Engine alive for
// rollback checks. The handle is READONLY and never changes the coordinator.
fn snapshot(directory: &Path) -> Snapshot {
    let db = readonly_archive(directory);
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            assert!(table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            let mut stmt = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

// The eligible placements come from the explicit genuine admissions above,
// not the production SQL kind predicate. Load all rows and raw blobs, compare
// exact evidence, then form physical WTXID/reference sets in ordinary Rust.
fn usage(directory: &Path, eligible: &Evidence) -> u64 {
    let db = readonly_archive(directory);
    let mut seen = BTreeSet::new();
    let mut protected_raw = BTreeSet::new();
    let mut bytes = 0u64;
    let mut stmt = db
        .prepare("SELECT block_hash,position,wtxid,commit_wtxid,record,proof FROM records")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (block, pos, reveal, commit, record, proof) = row.unwrap();
        let key = (block, pos);
        if let Some((expected_record, expected_proof)) = eligible.get(&key) {
            assert_eq!(&record, expected_record);
            assert_eq!(&proof, expected_proof);
            bytes += (record.len() + proof.len()) as u64;
            seen.insert(key);
        } else {
            protected_raw.insert(reveal);
            protected_raw.insert(commit);
        }
    }
    assert_eq!(seen, eligible.keys().cloned().collect());
    let dependencies: BTreeSet<String> = db
        .prepare("SELECT commit_txid FROM dependencies")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (wtxid, raw) in stored_bytes(&db) {
        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(tx.compute_wtxid().to_string(), wtxid);
        if !protected_raw.contains(&wtxid) && !dependencies.contains(&tx.compute_txid().to_string())
        {
            bytes += raw.len() as u64;
        }
    }
    bytes
}

// Only call with Engine dropped. These are correct serializations and identity
// columns in a closed owned TEMP DB, deliberately without record admission.
fn insert_trusted_raw(directory: &Path, transactions: &[Transaction]) {
    let mut db = Connection::open(directory.join("archive.sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    for transaction in transactions {
        tx.execute(
            "INSERT INTO transactions(wtxid,txid,raw) VALUES(?1,?2,?3)",
            params![
                transaction.compute_wtxid().to_string(),
                transaction.compute_txid().to_string(),
                serialize(transaction)
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn exact_metric_target_boundaries_dependency_protection_and_event_cursor() {
    let graph = Graph::load();
    let wire = profile();
    let pending = SignedPair::load("proof-post");
    let mut transactions = graph.transactions();
    transactions.extend(wire.transactions());
    transactions.push(pending.reveal.clone());
    let first = witness_block(&transactions, None, 1);
    let second = witness_block(&wire.transactions(), Some(&first), 2);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(&[first.clone(), second.clone()]));
    let cfg = config(&first, Retention::Pruned);
    let engine = open(directory.path(), &cfg, &source);
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    engine.scan_next().unwrap();
    let mut eligible = Evidence::new();
    for child in &graph.0[1..] {
        admit(&engine, &first, FIRST_HEIGHT, child, &mut eligible);
    }
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    drop(engine);
    // The genuine unresolved reveal already names this parent. Both physical
    // witness variants must be excluded from reclamation by that TXID; neither
    // insertion resolves the dependency or manufactures a record/scan mark.
    let mut variant = pending.commit.clone();
    variant.input[0].witness = Witness::from_slice(&[b"trusted cached witness variant"]);
    assert_eq!(variant.compute_txid(), pending.commit.compute_txid());
    assert_ne!(variant.compute_wtxid(), pending.commit.compute_wtxid());
    insert_trusted_raw(directory.path(), &[pending.commit.clone(), variant.clone()]);
    let expected = usage(directory.path(), &eligible);
    assert!(expected > 0);
    assert_eq!(
        expected,
        eligible
            .values()
            .map(|(record, proof)| (record.len() + proof.len()) as u64)
            .sum::<u64>()
            + graph.0[1..]
                .iter()
                .map(|pair| (pair.raw_reveal.len() + pair.raw_commit.len()) as u64)
                .sum::<u64>(),
        "only the two child pairs are reclaimable; root/Wire/dependency raw is excluded"
    );
    let initial = snapshot(directory.path());
    let engine = open(directory.path(), &cfg, &source);
    let before = engine.status().unwrap();
    let source_calls = calls(&source);
    let page = engine.wire_page(None, 1).unwrap();
    let cursor = page.next.expect("two real Wire placements");
    for limit in [expected + 1, expected] {
        let receipt = engine
            .maintain_cache(limit, &AtomicBool::new(false))
            .unwrap();
        assert!(receipt.enabled);
        assert_eq!(receipt.limit_bytes, limit);
        assert_eq!(receipt.before_bytes, expected);
        assert_eq!(receipt.remaining_bytes, expected);
        assert_eq!(
            (receipt.removed_records, receipt.removed_transactions),
            (0, 0)
        );
        assert!(!receipt.over_budget);
        assert!(engine.wire_page(Some(&cursor), 1).is_ok());
        assert_eq!(snapshot(directory.path()), initial);
    }
    let receipt = engine
        .maintain_cache(expected - 1, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(receipt.remaining_bytes, 0);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (2, 4)
    );
    assert!(!receipt.over_budget);
    assert!(matches!(
        engine.wire_page(Some(&cursor), 1),
        Err(Error::Busy(_))
    ));
    assert!(engine.record(graph.id(0)).unwrap().is_some());
    assert!(engine.record(wire.reveal.compute_txid()).unwrap().is_some());
    for i in 1..3 {
        assert!(engine.record(graph.id(i)).unwrap().is_none());
    }
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    drop(engine);
    let after = snapshot(directory.path());
    for table in [
        "selected",
        "headers",
        "scans",
        "locators",
        "dependencies",
        "objects",
        "object_members",
        "pins",
        "state",
    ] {
        assert_eq!(after[table], initial[table], "{table}");
    }
    let db = readonly_archive(directory.path());
    assert_eq!(cache_events(&db), 1);
    let raw = stored_bytes(&db);
    for transaction in [pending.commit, variant] {
        assert_eq!(
            raw.get(&transaction.compute_wtxid().to_string()),
            Some(&serialize(&transaction))
        );
    }
    assert_eq!(usage(directory.path(), &Evidence::new()), 0);
}

#[test]
fn exact_pinned_orphan_members_and_shared_raw_survive_restart_unpruned_is_disabled() {
    let graph = Graph::load();
    let wire = profile();
    let first = witness_block(&wire.transactions(), None, 10);
    let old = witness_block(&graph.transactions(), Some(&first), 11);
    let source = Arc::new(MemorySource::new(&[first.clone(), old.clone()]));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let cfg = config(&first, Retention::Pruned);
    let engine = open(directory.path(), &cfg, &source);
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    engine.scan_next().unwrap();
    let mut old_evidence = Evidence::new();
    for child in &graph.0[1..] {
        admit(&engine, &old, FIRST_HEIGHT + 1, child, &mut old_evidence);
    }
    graph.pin(&engine, scratch.path());
    let child_transactions: Vec<_> = graph.0[1..]
        .iter()
        .flat_map(SignedPair::transactions)
        .collect();
    let replacement = witness_block(&child_transactions, Some(&first), 12);
    source.replace_branch(&[first.clone(), replacement.clone()]);
    engine.synchronize_headers().unwrap();
    let mut eligible = Evidence::new();
    for child in &graph.0[1..] {
        admit(
            &engine,
            &replacement,
            FIRST_HEIGHT + 1,
            child,
            &mut eligible,
        );
    }
    let status = engine.object_status(graph.id(0)).unwrap().unwrap();
    assert!(status.pinned && status.locally_complete());
    assert_eq!(status.members_selected, 0);
    assert!(!status.selected_complete());
    let expected_status = serde_json::to_value(&status).unwrap();
    drop(engine);
    let initial = snapshot(directory.path());
    let raw_before = stored_bytes(&readonly_archive(directory.path()));
    let expected = usage(directory.path(), &eligible);
    assert_eq!(
        expected,
        eligible
            .values()
            .map(|(record, proof)| (record.len() + proof.len()) as u64)
            .sum::<u64>(),
        "old pinned members protect shared raw"
    );
    let engine = open(directory.path(), &cfg, &source);
    let before = engine.status().unwrap();
    let source_calls = calls(&source);
    assert_eq!(object_status(&engine, graph.id(0)), expected_status);
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(receipt.remaining_bytes, 0);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (2, 0)
    );
    assert_eq!(object_status(&engine, graph.id(0)), expected_status);
    assert!(engine.record(wire.reveal.compute_txid()).unwrap().is_some());
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    drop(engine);
    let after = snapshot(directory.path());
    for table in [
        "objects",
        "object_members",
        "pins",
        "locators",
        "scans",
        "dependencies",
        "selected",
        "state",
    ] {
        assert_eq!(after[table], initial[table], "{table}");
    }
    assert_eq!(
        stored_bytes(&readonly_archive(directory.path())),
        raw_before
    );
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "records"), 4);
    let retained: BTreeSet<Placement> = db
        .prepare("SELECT block_hash,position FROM records")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(old_evidence.keys().all(|key| retained.contains(key)));
    assert!(eligible.keys().all(|key| !retained.contains(key)));
    drop(db);
    let engine = open(directory.path(), &cfg, &source);
    assert_eq!(object_status(&engine, graph.id(0)), expected_status);
    assert_eq!(
        engine
            .maintain_cache(0, &AtomicBool::new(false))
            .unwrap()
            .removed_records,
        0
    );
    drop(engine);

    let unpruned_directory = tempfile::tempdir().unwrap();
    let block = witness_block(&graph.transactions(), None, 13);
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let cfg = config(&block, Retention::Unpruned);
    let engine = open(unpruned_directory.path(), &cfg, &source);
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    drop(engine);
    let initial = snapshot(unpruned_directory.path());
    let engine = open(unpruned_directory.path(), &cfg, &source);
    let source_calls = calls(&source);
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert!(!receipt.enabled);
    assert_eq!(
        (
            receipt.before_bytes,
            receipt.remaining_bytes,
            receipt.removed_records,
            receipt.removed_transactions
        ),
        (0, 0, 0, 0)
    );
    assert!(!receipt.over_budget);
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    assert_eq!(snapshot(unpruned_directory.path()), initial);
    drop(engine);
    let engine = open(unpruned_directory.path(), &cfg, &source);
    assert_eq!(
        engine.maintain_cache(0, &AtomicBool::new(false)).unwrap(),
        receipt
    );
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    assert_eq!(snapshot(unpruned_directory.path()), initial);
    drop(engine);
}

#[test]
fn actual_child_and_raw_batch_bounds_and_raw_only_backlog_progress() {
    assert_eq!(MAX_CACHE_RECORDS, 128);
    assert_eq!(MAX_CACHE_TRANSACTIONS, 512);
    let child = SignedPair::load("multipart/one-part-0");
    let mut blocks = Vec::new();
    for nonce in 0..129 {
        let block = witness_block(&child.transactions(), blocks.last(), 1000 + nonce);
        blocks.push(block);
    }
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(&blocks));
    let cfg = config(&blocks[0], Retention::Pruned);
    let engine = open(directory.path(), &cfg, &source);
    engine.synchronize_headers().unwrap();
    let mut eligible = Evidence::new();
    for (index, block) in blocks.iter().enumerate() {
        admit(
            &engine,
            block,
            FIRST_HEIGHT + index as u64,
            &child,
            &mut eligible,
        );
    }
    assert_eq!(engine.status().unwrap().scanned_blocks, 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    drop(engine);
    // Closed TEMP raw-only backlog: serializable distinct transactions, with
    // real identity columns but NO claimed signed record, inclusion or scan.
    let backlog: Vec<_> = (0..1025)
        .map(|index| {
            let mut tx = child.commit.clone();
            tx.lock_time = LockTime::from_consensus(9000 + index);
            tx
        })
        .collect();
    insert_trusted_raw(directory.path(), &backlog);
    let raw_before = stored_bytes(&readonly_archive(directory.path()));
    assert_eq!(raw_before.len(), 1027);
    let mut expected = usage(directory.path(), &eligible);
    assert_eq!(
        expected,
        eligible
            .values()
            .map(|(record, proof)| (record.len() + proof.len()) as u64)
            .sum::<u64>()
            + raw_before.values().map(|raw| raw.len() as u64).sum::<u64>(),
        "129 child placements, but one physical reveal/commit pair plus the raw-only backlog"
    );
    let engine = open(directory.path(), &cfg, &source);
    let before = engine.status().unwrap();
    let source_calls = calls(&source);
    let revision = engine.wire_page(None, 1).unwrap().snapshot.revision;
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (128, 512)
    );
    assert!(receipt.over_budget);
    coverage(&engine, &before);
    assert_eq!(
        engine.wire_page(None, 1).unwrap().snapshot.revision,
        revision + 1
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "records"), 1);
    assert_eq!(count(&db, "transactions"), 515);
    let remaining: Placement = db
        .query_row("SELECT block_hash,position FROM records", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    eligible.retain(|key, _| *key == remaining);
    let raw = stored_bytes(&db);
    assert_eq!(
        raw.get(&child.reveal.compute_wtxid().to_string()),
        Some(&child.raw_reveal)
    );
    assert_eq!(
        raw.get(&child.commit.compute_wtxid().to_string()),
        Some(&child.raw_commit)
    );
    drop(db);
    expected = usage(directory.path(), &eligible);
    assert_eq!(receipt.remaining_bytes, expected);
    let engine = open(directory.path(), &cfg, &source);
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (1, 512)
    );
    assert!(receipt.over_budget);
    coverage(&engine, &before);
    drop(engine);
    assert_eq!(
        count(&readonly_archive(directory.path()), "transactions"),
        3
    );
    expected = usage(directory.path(), &Evidence::new());
    assert_eq!(receipt.remaining_bytes, expected);
    let engine = open(directory.path(), &cfg, &source);
    let revision = engine.wire_page(None, 1).unwrap().snapshot.revision;
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (0, 3)
    );
    assert_eq!(receipt.remaining_bytes, 0);
    assert!(!receipt.over_budget);
    assert_eq!(
        engine.wire_page(None, 1).unwrap().snapshot.revision,
        revision + 1
    );
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, 0);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (0, 0)
    );
    assert_eq!(
        engine.wire_page(None, 1).unwrap().snapshot.revision,
        revision + 1
    );
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(cache_events(&db), 3);
    assert_eq!(count(&db, "transactions"), 0);
    assert_eq!(count(&db, "records"), 0);
    assert_eq!(count(&db, "scans"), 0);
}

#[test]
fn pre_cancel_invalid_limit_and_event_abort_are_atomic_with_same_instance_and_reopen_retry() {
    let child = SignedPair::load("multipart/one-part-0");
    let block = witness_block(&child.transactions(), None, 2000);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let cfg = config(&block, Retention::Pruned);
    let engine = open(directory.path(), &cfg, &source);
    engine.synchronize_headers().unwrap();
    let mut eligible = Evidence::new();
    admit(&engine, &block, FIRST_HEIGHT, &child, &mut eligible);
    drop(engine);
    let expected = usage(directory.path(), &eligible);
    let initial = snapshot(directory.path());
    let engine = open(directory.path(), &cfg, &source);
    let before = engine.status().unwrap();
    let source_calls = calls(&source);
    assert!(matches!(
        engine.maintain_cache(0, &AtomicBool::new(true)),
        Err(Error::Busy(_))
    ));
    assert!(matches!(
        engine.maintain_cache(i64::MAX as u64 + 1, &AtomicBool::new(false)),
        Err(Error::Invalid(_))
    ));
    assert_eq!(snapshot(directory.path()), initial);
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    drop(engine);
    // Fault injection only in the closed, owned DB. ABORT occurs after child
    // and raw deletes, at the cache event in their same production transaction.
    Connection::open(directory.path().join("archive.sqlite3")).unwrap().execute_batch("CREATE TRIGGER reject_cache_event BEFORE INSERT ON events WHEN NEW.kind='cache' BEGIN SELECT RAISE(ABORT,'owned cache event failure'); END;").unwrap();
    let engine = open(directory.path(), &cfg, &source);
    for _ in 0..2 {
        let error = engine
            .maintain_cache(0, &AtomicBool::new(false))
            .unwrap_err();
        assert!(
            error.to_string().contains("owned cache event failure"),
            "{error}"
        );
        assert_eq!(
            snapshot(directory.path()),
            initial,
            "full data/event/sequence rollback"
        );
        coverage(&engine, &before);
    }
    // Same instance remains usable after both failed mutations; equality retry
    // succeeds with no event. Successful eviction retry follows closed-DB
    // removal of the fault, never a write through a live Engine's coordinator.
    let receipt = engine
        .maintain_cache(expected, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (0, 0)
    );
    assert_eq!(snapshot(directory.path()), initial);
    drop(engine);
    Connection::open(directory.path().join("archive.sqlite3"))
        .unwrap()
        .execute_batch("DROP TRIGGER reject_cache_event;")
        .unwrap();
    let engine = open(directory.path(), &cfg, &source);
    let receipt = engine.maintain_cache(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(receipt.before_bytes, expected);
    assert_eq!(
        (receipt.removed_records, receipt.removed_transactions),
        (1, 2)
    );
    assert_eq!(receipt.remaining_bytes, 0);
    coverage(&engine, &before);
    assert_eq!(calls(&source), source_calls);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(cache_events(&db), 1);
    assert_eq!(count(&db, "records"), 0);
    assert_eq!(count(&db, "transactions"), 0);
}
