//! Schema migration and object-storage transaction failures in owned TEMP state.
//! SQLite DDL errors and trigger ABORT are not crash/power-loss simulations.
//! Signed public vectors authenticate records/reconstruction; mock headers make
//! no PoW, UTXO, full-consensus or auxiliary parent-placement claim.

#[allow(dead_code)]
mod common;

use bitcoin::{
    Block, BlockHash, Txid,
    consensus::serialize,
    hashes::{Hash, sha256},
};
use common::*;
use rusqlite::{Connection, params_from_iter, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
    sync::Arc,
    time::Duration,
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, ArchiveStatus, ObjectStatus, RecordPackage, Retention},
    retrieval::{recover, recover_and_pin},
};
use urma_runtime::multipart::{RecoveredObject, RecoveryLimits};

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<Value>>>,
}

fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn snapshot(db: &Connection) -> Snapshot {
    let schema: Vec<(String, String, String, Option<String>)> = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables = schema
        .iter()
        .filter(|entry| entry.0 == "table")
        .map(|entry| {
            let name = &entry.1;
            let statement = db
                .prepare(&format!("SELECT * FROM {}", identifier(name)))
                .unwrap();
            let columns = statement.column_count();
            let order = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = db
                .prepare(&format!(
                    "SELECT * FROM {} ORDER BY {order}",
                    identifier(name)
                ))
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name.clone(), rows)
        })
        .collect();
    Snapshot {
        version: db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap(),
        schema,
        tables,
    }
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(
        &format!("SELECT count(*) FROM {}", identifier(table)),
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn event_count(db: &Connection, kind: &str) -> i64 {
    db.query_row("SELECT count(*) FROM events WHERE kind=?1", [kind], |row| {
        row.get(0)
    })
    .unwrap()
}

fn assert_status_eq(actual: &ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn assert_object_eq(actual: &ObjectStatus, expected: &ObjectStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn assert_coverage(actual: &ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(actual.generation, expected.generation);
    assert_eq!(actual.selected_tip, expected.selected_tip);
    assert_eq!(actual.indexed_through, expected.indexed_through);
    assert_eq!(actual.scanned_blocks, expected.scanned_blocks);
    assert_eq!(
        actual.unresolved_dependencies,
        expected.unresolved_dependencies
    );
    assert_eq!(actual.scan_rules_version, expected.scan_rules_version);
}

// This connection is only for constructing old-schema fixtures and injecting
// faults after dropping Engine. Production coordination is never bypassed.
fn temp_writer(directory: &Path) -> Connection {
    Connection::open(directory.join("archive.sqlite3")).unwrap()
}

fn populated_schema1(directory: &Path) -> (ArchiveConfig, ArchiveStatus) {
    // Obtain all row evidence from public verification/scan APIs in a separate
    // TEMP archive. Do not invent scan marks, record proofs or dependency state.
    let seed = tempfile::tempdir().unwrap();
    let pair = profile();
    let unresolved = SignedPair::load("proof-post");
    let block = witness_block(
        &[pair.commit.clone(), pair.reveal.clone(), unresolved.reveal],
        None,
        1,
    );
    let config = config(&block, Retention::Unpruned);
    let engine = Engine::open(
        seed.path(),
        config.clone(),
        Some(Arc::new(MemorySource::new(&[block]))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let status = engine.scan_next().unwrap();
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.unresolved_dependencies, 1);
    assert_eq!(status.stored_transactions, 2);
    assert_eq!(status.indexed_through, None);
    drop(engine);
    let seed_db = readonly_archive(seed.path());
    let evidence = snapshot(&seed_db);
    let mut db = temp_writer(directory);
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch(include_str!("../src/schema.sql")).unwrap();
    // This is the exact schema1 declaration, with its original config encoding.
    // Copy in FK order; events restore sqlite_sequence naturally.
    for table in [
        "config",
        "state",
        "headers",
        "selected",
        "scans",
        "locators",
        "transactions",
        "records",
        "dependencies",
        "pins",
        "events",
    ] {
        tx.execute(&format!("DELETE FROM {}", identifier(table)), [])
            .unwrap();
        for row in &evidence.tables[table] {
            let placeholders = (1..=row.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",");
            tx.execute(
                &format!("INSERT INTO {} VALUES({placeholders})", identifier(table)),
                params_from_iter(row.iter()),
            )
            .unwrap();
        }
    }
    tx.commit().unwrap();
    let old = snapshot(&db);
    assert_eq!(old.version, 1);
    assert_eq!(old.tables.len() + 9, evidence.tables.len());
    for (name, rows) in &old.tables {
        assert_eq!(rows, &evidence.tables[name], "schema1 seed {name}");
    }
    assert_eq!(
        old.tables["config"][0][1],
        Value::Text(serde_json::to_string(&config).unwrap())
    );
    (config, status)
}

#[test]
fn schema1_configuration_mismatch_cannot_migrate_or_reset_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let (config, _) = populated_schema1(directory.path());
    let db = readonly_archive(directory.path());
    let original = snapshot(&db);
    drop(db);
    let mut mismatches = Vec::new();
    let mut other = config.clone();
    other.retention = Retention::Pruned;
    mismatches.push(other);
    let mut other = config.clone();
    other.application_start.height += 1;
    mismatches.push(other);
    let mut other = config.clone();
    other.application_start.hash = BlockHash::from_byte_array([42; 32]);
    mismatches.push(other);
    let mut other = config;
    other.chain = Chain::BitcoinTestnet4;
    mismatches.push(other);
    for other in mismatches {
        match Engine::open(directory.path(), other, None) {
            Err(Error::Invalid(message)) => assert_eq!(
                message,
                "archive configuration differs; explicit migration required"
            ),
            Err(error) => panic!("wrong mismatch rejection: {error}"),
            Ok(_) => panic!("mismatched schema1 config was accepted"),
        }
        let db = readonly_archive(directory.path());
        assert_eq!(snapshot(&db), original);
        assert!(!original.tables.contains_key("objects"));
        assert!(!original.tables.contains_key("object_members"));
    }
}

fn assert_migration_only(old: &Snapshot, migrated: &Snapshot) {
    assert_eq!(old.version, 1);
    assert_eq!(migrated.version, 5);
    for (name, rows) in &old.tables {
        assert_eq!(&migrated.tables[name], rows, "migration changed {name}");
    }
    assert_eq!(migrated.tables.len(), old.tables.len() + 9);
    assert!(migrated.tables["objects"].is_empty());
    assert!(migrated.tables["object_members"].is_empty());
    for entry in &old.schema {
        assert!(
            migrated.schema.contains(entry),
            "changed old DDL: {entry:?}"
        );
    }
    let added: BTreeSet<_> = migrated
        .schema
        .iter()
        .filter(|entry| !old.schema.contains(entry))
        .map(|entry| entry.1.as_str())
        .collect();
    assert_eq!(
        added,
        BTreeSet::from([
            "objects",
            "object_members",
            "object_member_record",
            "sqlite_autoindex_objects_1",
            "sqlite_autoindex_object_members_1",
            "names_registries",
            "names_states",
            "names_pending",
            "names_blocks",
            "names_outcomes",
            "sqlite_autoindex_names_registries_1",
            "sqlite_autoindex_names_states_1",
            "sqlite_autoindex_names_pending_1",
            "sqlite_autoindex_names_blocks_1",
            "sqlite_autoindex_names_outcomes_1",
            "peer_coverage",
            "peer_omissions",
            "sqlite_autoindex_peer_coverage_1",
            "sqlite_autoindex_peer_omissions_1"
        ])
    );
}

#[test]
fn exact_config_migrates_schema1_to4_without_fabricating_data_or_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let (config, before) = populated_schema1(directory.path());
    let db = readonly_archive(directory.path());
    let old = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(
        engine
            .object_status(profile().reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    let migrated = snapshot(&db);
    assert_migration_only(&old, &migrated);
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), migrated);
}

#[test]
fn second_migration_ddl_collision_rolls_back_first_ddl_and_version() {
    let directory = tempfile::tempdir().unwrap();
    let (config, before) = populated_schema1(directory.path());
    let db = temp_writer(directory.path());
    // An ordinary preexisting table is a legitimate SQLite name collision, not
    // corruption. CREATE objects precedes the failing CREATE object_members.
    db.execute_batch(
        "CREATE TABLE object_members(id INTEGER PRIMARY KEY, note TEXT NOT NULL);
        INSERT INTO object_members VALUES(1,'preexisting table with colliding name');",
    )
    .unwrap();
    let original = snapshot(&db);
    drop(db);
    match Engine::open(directory.path(), config.clone(), None) {
        Err(Error::Database(error)) => {
            // Modern SQLite can report this prepare failure as SqlInputError
            // with the SQL offset, rather than SqliteFailure. Require the exact
            // intended collision before testing rollback of the earlier DDL.
            assert!(
                error
                    .to_string()
                    .contains("table object_members already exists"),
                "{error}"
            );
        }
        Err(error) => panic!("wrong migration failure: {error}"),
        Ok(_) => panic!("colliding schema migration succeeded"),
    }
    let db = temp_writer(directory.path());
    assert_eq!(snapshot(&db), original);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name IN ('objects','object_member_record')",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    db.execute_batch("DROP TABLE object_members;").unwrap();
    let repaired_fixture = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&engine.status().unwrap(), &before);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_migration_only(&repaired_fixture, &snapshot(&db));
}

struct Graph {
    pairs: Vec<SignedPair>,
}

impl Graph {
    fn load(name: &str, parts: usize) -> Self {
        let suffixes = ["root".to_owned(), "leaf".to_owned()]
            .into_iter()
            .chain((0..parts).map(|i| format!("part-{i}")));
        Self {
            pairs: suffixes
                .map(|suffix| SignedPair::load(&format!("multipart/{name}-{suffix}")))
                .collect(),
        }
    }
    fn root(&self) -> Txid {
        self.pairs[0].reveal.compute_txid()
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

fn expected_bytes<'a>(pairs: impl Iterator<Item = &'a SignedPair>) -> BTreeMap<String, Vec<u8>> {
    let mut bytes = BTreeMap::new();
    for pair in pairs {
        bytes.insert(
            pair.commit.compute_wtxid().to_string(),
            pair.raw_commit.clone(),
        );
        bytes.insert(
            pair.reveal.compute_wtxid().to_string(),
            pair.raw_reveal.clone(),
        );
    }
    bytes
}

fn cached_graphs(directory: &Path, graphs: &[&Graph]) -> (ArchiveConfig, Block, ArchiveStatus) {
    let transactions: Vec<_> = graphs
        .iter()
        .flat_map(|graph| graph.pairs.iter())
        .flat_map(SignedPair::transactions)
        .collect();
    let block = witness_block(&transactions, None, 1);
    let config = config(&block, Retention::Pruned);
    let engine = Engine::open(
        directory,
        config.clone(),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    for pair in graphs.iter().flat_map(|graph| graph.pairs.iter()) {
        let position = block
            .txdata
            .iter()
            .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
            .unwrap();
        engine
            .admit_record(RecordPackage {
                version: API_VERSION,
                chain_genesis: config.chain.genesis().unwrap().0,
                block: config.application_start,
                reveal: TransactionProof::from_block(
                    &block,
                    position as u32,
                    pair.raw_reveal.clone(),
                    serialize(&block.txdata[0]),
                )
                .unwrap(),
                commit: pair.raw_commit.clone(),
            })
            .unwrap();
    }
    let status = engine.status().unwrap();
    assert_eq!(status.scanned_blocks, 0);
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.unresolved_dependencies, 0);
    assert_eq!(
        status.stored_transactions as usize,
        expected_bytes(graphs.iter().flat_map(|graph| graph.pairs.iter())).len()
    );
    drop(engine);
    (config, block, status)
}

fn assert_cached(engine: &Engine, graph: &Graph) {
    for pair in &graph.pairs {
        let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
        assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
        assert_eq!(record.package.commit, pair.raw_commit);
        assert_eq!(record.receipt.wtxid, pair.reveal.compute_wtxid());
    }
}

fn assert_payload(mut recovered: RecoveredObject, graph: &Graph) {
    assert_eq!(recovered.root(), graph.root());
    assert_eq!(recovered.author(), graph.pairs[0].verified.author());
    let mut payload = Vec::new();
    recovered.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, graph.payload());
    assert_eq!(recovered.manifest().length, payload.len() as u64);
    assert_eq!(
        recovered.manifest().payload_hash,
        sha256::Hash::hash(&payload).to_byte_array()
    );
}

fn assert_complete(status: &ObjectStatus, graph: &Graph, pinned: bool) {
    assert_eq!(status.root, graph.root());
    assert_eq!(status.verified_generation, 0);
    assert_eq!(status.payload_bytes, graph.payload().len() as u64);
    assert_eq!(status.members_total as usize, graph.pairs.len());
    assert_eq!(status.members_local, status.members_total);
    assert_eq!(status.members_selected, status.members_total);
    assert_eq!(status.pinned, pinned);
    assert!(status.locally_complete());
    assert!(status.selected_complete());
}

fn assert_abort(error: Error, message: &str) {
    match error {
        Error::Database(rusqlite::Error::SqliteFailure(code, detail)) => {
            assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
            assert_eq!(detail.as_deref(), Some(message));
        }
        error => panic!("expected injected SQLite abort, got {error}"),
    }
}

fn completion_abort(pin: bool) {
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let graph = Graph::load("one", 1);
    let (config, block, before) = cached_graphs(directory.path(), &[&graph]);
    let db = temp_writer(directory.path());
    assert_eq!(stored_bytes(&db), expected_bytes(graph.pairs.iter()));
    assert_eq!(count(&db, "objects"), 0);
    assert_eq!(count(&db, "object_members"), 0);
    assert_eq!(count(&db, "pins"), 0);
    // Abort after completion, every member, the optional pin AND object event
    // have been staged. The message proves the transaction reached that point.
    db.execute_batch(&format!(
        "CREATE TRIGGER u4_object_abort AFTER INSERT ON events WHEN NEW.kind='object' BEGIN
        SELECT CASE WHEN (SELECT count(*) FROM objects)=1 AND
            (SELECT count(*) FROM object_members)=3 AND (SELECT count(*) FROM pins)={} AND
            (SELECT count(*) FROM events WHERE kind='object')=1
        THEN RAISE(ABORT, 'u4 object completion abort after staged members')
        ELSE RAISE(ABORT, 'u4 fixture did not stage object completion') END;
        END;",
        i64::from(pin)
    ))
    .unwrap();
    let original = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    let failure = if pin {
        recover_and_pin(&engine, graph.root(), &[], graph.limits(), scratch.path())
    } else {
        recover(&engine, graph.root(), &[], graph.limits(), scratch.path())
    };
    assert_abort(
        failure.unwrap_err(),
        "u4 object completion abort after staged members",
    );
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(engine.object_status(graph.root()).unwrap().is_none());
    assert_cached(&engine, &graph);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), original);
    drop(db);
    let restarted = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    assert!(restarted.object_status(graph.root()).unwrap().is_none());
    assert_cached(&restarted, &graph);
    drop(restarted);
    let db = temp_writer(directory.path());
    db.execute_batch("DROP TRIGGER u4_object_abort;").unwrap();
    drop(db);
    let engine = Engine::open(directory.path(), config, None).unwrap();
    let recovered = if pin {
        recover_and_pin(&engine, graph.root(), &[], graph.limits(), scratch.path())
    } else {
        recover(&engine, graph.root(), &[], graph.limits(), scratch.path())
    }
    .unwrap();
    assert_payload(recovered, &graph);
    assert_status_eq(&engine.status().unwrap(), &before);
    let completed = engine.object_status(graph.root()).unwrap().unwrap();
    assert_complete(&completed, &graph, pin);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "objects"), 1);
    assert_eq!(count(&db, "object_members"), 3);
    assert_eq!(count(&db, "pins"), i64::from(pin));
    assert_eq!(event_count(&db, "object"), 1);
    assert_eq!(stored_bytes(&db), expected_bytes(graph.pairs.iter()));
    let (length, digest): (i64, Vec<u8>) = db
        .query_row(
            "SELECT payload_bytes,payload_hash FROM objects",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(length as usize, graph.payload().len());
    assert_eq!(digest, sha256::Hash::hash(&graph.payload()).to_byte_array());
    let members: BTreeSet<(String, String, u32, String, Vec<u8>)> = db
        .prepare("SELECT txid,block_hash,position,wtxid,record_hash FROM object_members")
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let expected: BTreeSet<_> = graph
        .pairs
        .iter()
        .map(|pair| {
            (
                pair.reveal.compute_txid().to_string(),
                block.block_hash().to_string(),
                block
                    .txdata
                    .iter()
                    .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
                    .unwrap() as u32,
                pair.reveal.compute_wtxid().to_string(),
                pair.verified.reference().record_hash.to_vec(),
            )
        })
        .collect();
    assert_eq!(members, expected);
}

#[test]
fn completion_event_abort_rolls_back_objects_members_and_event_preserving_cache() {
    completion_abort(false);
}

#[test]
fn completion_with_pin_abort_rolls_back_objects_members_pin_and_event() {
    completion_abort(true);
}

#[test]
fn prune_abort_preserves_records_raw_object_status_and_pins_then_retry_evicts_unpinned_children() {
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let pinned = Graph::load("one", 1);
    let unpinned = Graph::load("two", 2);
    let (config, _, cached) = cached_graphs(directory.path(), &[&pinned, &unpinned]);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_payload(
        recover_and_pin(&engine, pinned.root(), &[], pinned.limits(), scratch.path()).unwrap(),
        &pinned,
    );
    assert_payload(
        recover(
            &engine,
            unpinned.root(),
            &[],
            unpinned.limits(),
            scratch.path(),
        )
        .unwrap(),
        &unpinned,
    );
    let before = engine.status().unwrap();
    assert_status_eq(&before, &cached);
    let pinned_before = engine.object_status(pinned.root()).unwrap().unwrap();
    let unpinned_before = engine.object_status(unpinned.root()).unwrap().unwrap();
    assert_complete(&pinned_before, &pinned, true);
    assert_complete(&unpinned_before, &unpinned, false);
    drop(engine);
    let kept_bytes = expected_bytes(
        pinned
            .pairs
            .iter()
            .chain(std::iter::once(&unpinned.pairs[0])),
    );
    let db = temp_writer(directory.path());
    db.execute_batch(&format!("CREATE TRIGGER u4_prune_abort AFTER INSERT ON events WHEN NEW.kind='prune' BEGIN
        SELECT CASE WHEN (SELECT count(*) FROM records)=4 AND (SELECT count(*) FROM transactions)={} AND
            (SELECT count(*) FROM objects)=2 AND (SELECT count(*) FROM object_members)=7 AND
            (SELECT count(*) FROM pins)=1 AND EXISTS(SELECT 1 FROM pins WHERE root_txid='{}') AND
            (SELECT count(*) FROM events WHERE kind='prune')=1
        THEN RAISE(ABORT, 'u4 prune abort after staged deletion and raw gc')
        ELSE RAISE(ABORT, 'u4 fixture did not stage pruning') END;
        END;", kept_bytes.len(), pinned.root())).unwrap();
    let original = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_abort(
        engine.prune_cache().unwrap_err(),
        "u4 prune abort after staged deletion and raw gc",
    );
    assert_status_eq(&engine.status().unwrap(), &before);
    assert_object_eq(
        &engine.object_status(pinned.root()).unwrap().unwrap(),
        &pinned_before,
    );
    assert_object_eq(
        &engine.object_status(unpinned.root()).unwrap().unwrap(),
        &unpinned_before,
    );
    assert_cached(&engine, &pinned);
    assert_cached(&engine, &unpinned);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), original);
    drop(db);
    let restarted = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    assert_object_eq(
        &restarted.object_status(pinned.root()).unwrap().unwrap(),
        &pinned_before,
    );
    assert_object_eq(
        &restarted.object_status(unpinned.root()).unwrap().unwrap(),
        &unpinned_before,
    );
    drop(restarted);
    let db = temp_writer(directory.path());
    db.execute_batch("DROP TRIGGER u4_prune_abort;").unwrap();
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_eq!(engine.prune_cache().unwrap(), 3);
    let after = engine.status().unwrap();
    assert_coverage(&after, &before);
    assert_eq!(after.stored_transactions as usize, kept_bytes.len());
    assert_cached(&engine, &pinned);
    assert!(engine.record(unpinned.root()).unwrap().is_some());
    for pair in &unpinned.pairs[1..] {
        assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
    }
    assert_object_eq(
        &engine.object_status(pinned.root()).unwrap().unwrap(),
        &pinned_before,
    );
    let evicted = engine.object_status(unpinned.root()).unwrap().unwrap();
    assert_eq!(
        evicted.verified_generation,
        unpinned_before.verified_generation
    );
    assert_eq!(evicted.payload_bytes, unpinned_before.payload_bytes);
    assert_eq!(evicted.members_total, 4);
    assert_eq!(evicted.members_local, 1);
    assert_eq!(evicted.members_selected, 4);
    assert!(!evicted.pinned);
    assert!(!evicted.locally_complete());
    assert!(!evicted.selected_complete());
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &after);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(stored_bytes(&db), kept_bytes);
    assert_eq!(count(&db, "records"), 4);
    assert_eq!(event_count(&db, "prune"), 1);
    let pruned = snapshot(&db);
    for table in [
        "config",
        "state",
        "headers",
        "selected",
        "scans",
        "locators",
        "dependencies",
        "objects",
        "object_members",
        "pins",
    ] {
        assert_eq!(
            pruned.tables[table], original.tables[table],
            "prune changed retained {table}"
        );
    }
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &after);
    assert_object_eq(
        &restarted.object_status(pinned.root()).unwrap().unwrap(),
        &pinned_before,
    );
    assert_object_eq(
        &restarted.object_status(unpinned.root()).unwrap().unwrap(),
        &evicted,
    );
}

#[test]
fn schema1_legacy_pin_without_object_can_be_unpinned_once_and_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (config, before) = populated_schema1(directory.path());
    let root = SignedPair::load("multipart/one-root").reveal.compute_txid();
    let db = temp_writer(directory.path());
    // Schema1 permits this standalone pin intent; it carries no object evidence.
    db.execute("INSERT INTO pins VALUES(?1)", [root.to_string()])
        .unwrap();
    let old = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(engine.object_status(root).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    let migrated = snapshot(&db);
    assert_migration_only(&old, &migrated);
    assert_eq!(count(&db, "pins"), 1);
    drop(db);

    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    engine.set_pin(root, false).unwrap();
    engine.set_pin(root, false).unwrap();
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(engine.object_status(root).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    let unpinned = snapshot(&db);
    assert_eq!(count(&db, "pins"), 0);
    assert_eq!(count(&db, "objects"), 0);
    assert_eq!(count(&db, "object_members"), 0);
    assert_eq!(event_count(&db, "pin"), 1);
    assert_eq!(event_count(&db, "object"), 0);
    for (table, rows) in &migrated.tables {
        if !["pins", "events", "sqlite_sequence"].contains(&table.as_str()) {
            assert_eq!(&unpinned.tables[table], rows, "unpin changed {table}");
        }
    }
    assert_eq!(unpinned.schema, migrated.schema);
    assert_eq!(unpinned.version, 5);
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    restarted.set_pin(root, false).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    assert!(restarted.object_status(root).unwrap().is_none());
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), unpinned);
}

fn schema2_object_fixture(
    directory: &Path,
    graph: &Graph,
    evict_children: bool,
) -> (ArchiveConfig, ArchiveStatus, ObjectStatus) {
    let scratch = tempfile::tempdir().unwrap();
    let (config, _, _) = cached_graphs(directory, &[graph]);
    let engine = Engine::open(directory, config.clone(), None).unwrap();
    let recovered = if evict_children {
        recover(&engine, graph.root(), &[], graph.limits(), scratch.path())
    } else {
        recover_and_pin(&engine, graph.root(), &[], graph.limits(), scratch.path())
    }
    .unwrap();
    assert_payload(recovered, graph);
    if evict_children {
        assert_eq!(engine.prune_cache().unwrap(), 2);
    }
    let status = engine.status().unwrap();
    let object = engine.object_status(graph.root()).unwrap().unwrap();
    if evict_children {
        assert_eq!(object.members_total, 3);
        assert_eq!(object.members_local, 1);
        assert!(!object.pinned);
    } else {
        assert_complete(&object, graph, true);
    }
    drop(engine);

    // Project authenticated current-schema evidence into the exact schema2 column
    // contract. This fixture recreates the interim layout, not an old binary.
    // Only record_hash is omitted; all historical member links survive.
    let mut db = temp_writer(directory);
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let before_projection = snapshot(&db);
    let tx = db.transaction().unwrap();
    tx.execute_batch("CREATE TABLE object_members_v2 (
        root_txid TEXT NOT NULL REFERENCES objects(root_txid) ON DELETE CASCADE,
        txid TEXT NOT NULL, block_hash TEXT NOT NULL REFERENCES headers(hash),
        position INTEGER NOT NULL, wtxid TEXT NOT NULL, PRIMARY KEY(root_txid,txid));
        INSERT INTO object_members_v2 SELECT root_txid,txid,block_hash,position,wtxid FROM object_members;
        DROP TABLE object_members;
        ALTER TABLE object_members_v2 RENAME TO object_members;
        CREATE INDEX object_member_record ON object_members(block_hash,position,wtxid);
        DROP TABLE names_outcomes; DROP TABLE names_blocks; DROP TABLE names_pending;
        DROP TABLE names_states; DROP TABLE names_registries;
        DROP TABLE peer_omissions; DROP TABLE peer_coverage;
        PRAGMA user_version=2;").unwrap();
    tx.commit().unwrap();
    let interim = snapshot(&db);
    assert_eq!(interim.version, 2);
    for (table, rows) in &before_projection.tables {
        if table.starts_with("names_") || table.starts_with("peer_") {
            assert!(rows.is_empty());
            continue;
        }
        if table == "object_members" {
            let expected: Vec<Vec<Value>> = rows.iter().map(|row| row[..5].to_vec()).collect();
            assert_eq!(interim.tables[table], expected);
        } else {
            assert_eq!(
                &interim.tables[table], rows,
                "schema2 projection changed {table}"
            );
        }
    }
    (config, status, object)
}

#[test]
fn retained_schema2_members_migrate_to4_with_exact_record_identity_hashes() {
    let directory = tempfile::tempdir().unwrap();
    let graph = Graph::load("one", 1);
    let (config, before, object_before) = schema2_object_fixture(directory.path(), &graph, false);
    let db = readonly_archive(directory.path());
    let interim = snapshot(&db);
    assert_eq!(count(&db, "records"), 3);
    assert_eq!(count(&db, "object_members"), 3);
    assert_eq!(count(&db, "pins"), 1);
    drop(db);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&engine.status().unwrap(), &before);
    assert_object_eq(
        &engine.object_status(graph.root()).unwrap().unwrap(),
        &object_before,
    );
    assert_cached(&engine, &graph);
    drop(engine);
    let db = readonly_archive(directory.path());
    let migrated = snapshot(&db);
    assert_eq!(migrated.version, 5);
    let hashes: BTreeMap<_, _> = graph
        .pairs
        .iter()
        .map(|pair| {
            (
                pair.reveal.compute_txid().to_string(),
                pair.verified.reference().record_hash.to_vec(),
            )
        })
        .collect();
    for (table, rows) in &interim.tables {
        if table == "object_members" {
            let expected: Vec<Vec<Value>> = rows
                .iter()
                .map(|row| {
                    let Value::Text(txid) = &row[1] else {
                        panic!("member TXID")
                    };
                    let mut row = row.clone();
                    row.push(Value::Blob(hashes[txid].clone()));
                    row
                })
                .collect();
            assert_eq!(migrated.tables[table], expected);
        } else {
            assert_eq!(
                &migrated.tables[table], rows,
                "schema2 migration changed {table}"
            );
        }
    }
    assert_eq!(migrated.tables.len(), interim.tables.len() + 7);
    for entry in &interim.schema {
        if entry.2 != "object_members" {
            assert!(
                migrated.schema.contains(entry),
                "changed unrelated DDL: {entry:?}"
            );
        }
    }
    assert!(!migrated.tables.contains_key("object_members_v3"));
    assert_eq!(stored_bytes(&db), expected_bytes(graph.pairs.iter()));
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    assert_object_eq(
        &restarted.object_status(graph.root()).unwrap().unwrap(),
        &object_before,
    );
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), migrated);
}

#[test]
fn schema2_evicted_members_refuse_identity_migration_without_losing_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let graph = Graph::load("one", 1);
    let (config, before, object_before) = schema2_object_fixture(directory.path(), &graph, true);
    assert_eq!(before.stored_transactions, 2);
    assert_eq!(object_before.members_total, 3);
    assert_eq!(object_before.members_local, 1);
    let db = readonly_archive(directory.path());
    let original = snapshot(&db);
    assert_eq!(original.version, 2);
    assert_eq!(count(&db, "records"), 1);
    assert_eq!(count(&db, "object_members"), 3);
    let remaining = expected_bytes(std::iter::once(&graph.pairs[0]));
    assert_eq!(stored_bytes(&db), remaining);
    drop(db);
    for _ in 0..2 {
        match Engine::open(directory.path(), config.clone(), None) {
            Err(Error::Invalid(message)) => assert_eq!(
                message,
                "schema 2 member evidence was evicted; explicit identity migration required"
            ),
            Err(error) => panic!("wrong schema2 identity rejection: {error}"),
            Ok(_) => panic!("evicted schema2 member hashes were fabricated"),
        }
        let db = readonly_archive(directory.path());
        assert_eq!(snapshot(&db), original);
        assert_eq!(stored_bytes(&db), remaining);
        assert!(!original.tables.contains_key("object_members_v3"));
    }
}
