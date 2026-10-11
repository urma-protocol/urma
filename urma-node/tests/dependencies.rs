//! Missing-parent resolution using independently signed public vectors.
//! Mock blocks authenticate reveal inclusion, not PoW/UTXOs/full consensus.
//! Supplied commits are auxiliary prevout bytes: no parent placement or witness
//! authenticity is asserted. Fault injection touches disposable TEMP state only.

mod common;

use bitcoin::{Block, Transaction, Witness, consensus::serialize};
use common::*;
use rusqlite::{Connection, types::Value};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::{
    envelope,
    multipart::{MultipartRecord, VerifiedRecord},
};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, ArchiveStatus, ArchivedRecord, RecordPackage, Retention},
};

fn assert_status_eq(actual: &ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn unresolved_archive(
    directory: &Path,
    reveal: &Transaction,
    retention: Retention,
) -> (Engine, ArchiveConfig, Block, Arc<MemorySource>) {
    let block = witness_block(std::slice::from_ref(reveal), None, 1);
    let config = config(&block, retention);
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(directory, config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    let status = engine.scan_next().unwrap();
    assert_eq!(status.selected_tip, Some(config.application_start));
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.unresolved_dependencies, 1);
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.stored_transactions, 0);
    assert!(engine.record(reveal.compute_txid()).unwrap().is_none());
    (engine, config, block, source)
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn dependency_events(db: &Connection) -> i64 {
    db.query_row(
        "SELECT count(*) FROM events WHERE kind='dependency'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

// Exact row equality catches mutations invisible to status, including archived
// orphan dependencies, transaction bytes, event sequence and locator evidence.
fn snapshot(db: &Connection) -> Vec<(&'static str, Vec<Vec<Value>>)> {
    [
        ("config", "singleton"),
        ("state", "singleton"),
        ("headers", "hash"),
        ("selected", "height"),
        ("scans", "block_hash"),
        ("locators", "block_hash,position"),
        ("transactions", "wtxid"),
        ("records", "block_hash,position"),
        ("dependencies", "block_hash,position"),
        ("pins", "root_txid"),
        ("events", "sequence"),
        ("sqlite_sequence", "name"),
    ]
    .into_iter()
    .map(|(table, order)| {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table, rows)
    })
    .collect()
}

fn assert_retained(record: &ArchivedRecord, pair: &SignedPair, block: &Block) {
    assert_eq!(record.receipt.block, point(FIRST_HEIGHT, block));
    assert_eq!(record.receipt.position, 1);
    assert_eq!(record.receipt.txid, pair.reveal.compute_txid());
    assert_eq!(record.receipt.wtxid, pair.reveal.compute_wtxid());
    assert_eq!(record.package.block, record.receipt.block);
    assert_eq!(record.package.commit, pair.raw_commit);
    assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
    let included = record
        .package
        .reveal
        .verify(Chain::BitcoinRegtest, &block.header)
        .unwrap();
    assert_eq!(included.raw(), pair.raw_reveal);
    assert_eq!(included.position(), 1);
    assert_eq!(included.transaction(), &pair.reveal);
    assert_eq!(
        VerifiedRecord::verify(
            included.transaction().compute_txid(),
            included.transaction(),
            &pair.commit
        )
        .unwrap()
        .record_bytes(),
        pair.verified.record_bytes()
    );
}

fn assert_auxiliary_parent_only(db: &Connection, pair: &SignedPair, locators: i64) {
    assert_eq!(count(db, "locators"), locators);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM locators WHERE txid=?1",
            [pair.commit.compute_txid().to_string()],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn exact_parent_resolves_without_rescanning_wrong_parent_and_repeats_are_noops() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let wrong = SignedPair::load("proof-post");
    assert_ne!(wrong.commit.compute_txid(), pair.commit.compute_txid());
    let (engine, config, block, source) =
        unresolved_archive(directory.path(), &pair.reveal, Retention::Pruned);
    let missing = engine.status().unwrap();
    drop(engine);
    let db = readonly_archive(directory.path());
    let original = snapshot(&db);
    assert_eq!(count(&db, "dependencies"), 1);
    assert_eq!(
        db.query_row("SELECT commit_txid FROM dependencies", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        pair.commit.compute_txid().to_string()
    );
    assert_auxiliary_parent_only(&db, &pair, 2);
    drop(db);

    // Offline resolution needs no source fetch and cannot infer parent placement.
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_eq!(engine.resolve_commit(&wrong.raw_commit).unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &missing);
    assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), original);
    drop(db);

    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 1);
    let resolved = engine.status().unwrap();
    assert_eq!(resolved.scanned_blocks, missing.scanned_blocks);
    assert_eq!(resolved.selected_tip, missing.selected_tip);
    assert_eq!(resolved.generation, missing.generation);
    assert_eq!(resolved.indexed_through, Some(config.application_start));
    assert_eq!(resolved.unresolved_dependencies, 0);
    assert_eq!(resolved.stored_transactions, 2);
    let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
    assert_retained(&record, &pair, &block);
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &resolved);
    drop(engine);

    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "dependencies"), 0);
    assert_eq!(count(&db, "scans"), 1);
    assert_eq!(
        db.query_row("SELECT unresolved FROM scans", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(dependency_events(&db), 1);
    assert_eq!(
        db.query_row(
            "SELECT generation,height,block_hash FROM events WHERE kind='dependency'",
            [],
            |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?
            ))
        )
        .unwrap(),
        (0, FIRST_HEIGHT as i64, block.block_hash().to_string())
    );
    let stored = stored_bytes(&db);
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
    assert_eq!(
        stored[&pair.reveal.compute_wtxid().to_string()],
        pair.raw_reveal
    );
    assert_auxiliary_parent_only(&db, &pair, 2);
    let completed = snapshot(&db);
    drop(db);

    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &resolved);
    assert_retained(
        &restarted
            .record(pair.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &pair,
        &block,
    );
    assert_eq!(restarted.resolve_commit(&pair.raw_commit).unwrap(), 0);
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), completed);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn witness_invalid_but_included_candidate_is_classified_after_exact_parent() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let mut reveal = pair.reveal.clone();
    let mut witness: Vec<Vec<u8>> = reveal.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    witness[0][63] ^= 1;
    bitcoin::secp256k1::schnorr::Signature::from_slice(&witness[0]).unwrap();
    reveal.input[0].witness = Witness::from_slice(&witness);
    assert_eq!(reveal.compute_txid(), pair.reveal.compute_txid());
    assert_ne!(reveal.compute_wtxid(), pair.reveal.compute_wtxid());
    assert_eq!(
        envelope::extract_reveal(&reveal).unwrap().record,
        pair.verified.record_bytes()
    );
    match VerifiedRecord::verify(reveal.compute_txid(), &reveal, &pair.commit).unwrap_err() {
        urma_core::error::Error::Context { message, .. } => {
            assert_eq!(message, "invalid author signature")
        }
        error => panic!("wrong invalid-candidate guard: {error}"),
    }
    let (engine, config, block, _) =
        unresolved_archive(directory.path(), &reveal, Retention::Unpruned);
    let proof =
        TransactionProof::from_block(&block, 1, serialize(&reveal), serialize(&block.txdata[0]))
            .unwrap();
    assert_eq!(
        proof.verify(config.chain, &block.header).unwrap().raw(),
        serialize(&reveal)
    );
    let before = engine.status().unwrap();
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 1);
    let after = engine.status().unwrap();
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(after.selected_tip, before.selected_tip);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.indexed_through, Some(config.application_start));
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(after.stored_transactions, 0);
    assert!(engine.record(reveal.compute_txid()).unwrap().is_none());
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &after);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "dependencies"), 0);
    assert_eq!(count(&db, "records"), 0);
    assert!(stored_bytes(&db).is_empty());
    assert_eq!(dependency_events(&db), 1);
    assert_auxiliary_parent_only(&db, &pair, 2);
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &after);
    assert!(restarted.record(reveal.compute_txid()).unwrap().is_none());
}

#[test]
fn orphan_dependency_survives_but_cannot_resolve_the_current_view() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let first = witness_block(&[], None, 1);
    let orphan = witness_block(std::slice::from_ref(&pair.reveal), Some(&first), 2);
    let replacement = witness_block(&[], Some(&first), 3);
    let config = config(&first, Retention::Unpruned);
    let source = Arc::new(MemorySource::new(&[first.clone(), orphan.clone()]));
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let missing = engine.scan_next().unwrap();
    assert_eq!(missing.scanned_blocks, 2);
    assert_eq!(missing.unresolved_dependencies, 1);
    assert_eq!(missing.indexed_through, Some(point(FIRST_HEIGHT, &first)));
    source.replace_branch(&[first, replacement.clone()]);
    let reorg = engine.synchronize_headers().unwrap();
    assert_eq!(reorg.generation, missing.generation + 1);
    assert_eq!(reorg.unresolved_dependencies, 0);
    assert_eq!(reorg.scanned_blocks, 1);
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &reorg);
    let current = engine.scan_next().unwrap();
    assert_eq!(current.scanned_blocks, 2);
    assert_eq!(
        current.indexed_through,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(current.stored_transactions, 0);
    drop(engine);
    let db = readonly_archive(directory.path());
    let original = snapshot(&db);
    assert_eq!(count(&db, "dependencies"), 1);
    assert_eq!(
        db.query_row("SELECT block_hash FROM dependencies", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        orphan.block_hash().to_string()
    );
    assert_eq!(
        db.query_row(
            "SELECT unresolved FROM scans WHERE block_hash=?1",
            [orphan.block_hash().to_string()],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(dependency_events(&db), 0);
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_eq!(restarted.resolve_commit(&pair.raw_commit).unwrap(), 0);
    assert_status_eq(&restarted.status().unwrap(), &current);
    assert!(
        restarted
            .record(pair.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), original);
}

#[test]
fn leaf_resolution_obeys_pruned_and_unpruned_retention_without_parent_placement() {
    let pair = SignedPair::load("multipart/one-leaf");
    assert!(matches!(
        pair.verified.decode().unwrap(),
        MultipartRecord::Leaf(_)
    ));
    for retention in [Retention::Pruned, Retention::Unpruned] {
        let directory = tempfile::tempdir().unwrap();
        let (engine, config, block, _) =
            unresolved_archive(directory.path(), &pair.reveal, retention);
        assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 1);
        let after = engine.status().unwrap();
        assert_eq!(after.scanned_blocks, 1);
        assert_eq!(after.unresolved_dependencies, 0);
        assert_eq!(after.indexed_through, Some(config.application_start));
        let kept = retention == Retention::Unpruned;
        assert_eq!(after.stored_transactions, if kept { 2 } else { 0 });
        let record = engine.record(pair.reveal.compute_txid()).unwrap();
        if kept {
            assert_retained(&record.unwrap(), &pair, &block);
        } else {
            assert!(record.is_none());
        }
        assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 0);
        assert_status_eq(&engine.status().unwrap(), &after);
        drop(engine);
        let db = readonly_archive(directory.path());
        assert_eq!(count(&db, "dependencies"), 0);
        assert_eq!(count(&db, "records"), if kept { 1 } else { 0 });
        assert_eq!(dependency_events(&db), 1);
        assert_auxiliary_parent_only(&db, &pair, 2);
        let stored = stored_bytes(&db);
        if kept {
            assert_eq!(
                stored[&pair.commit.compute_wtxid().to_string()],
                pair.raw_commit
            );
            assert_eq!(
                stored[&pair.reveal.compute_wtxid().to_string()],
                pair.raw_reveal
            );
        } else {
            assert!(stored.is_empty());
        }
        drop(db);
        let restarted = Engine::open(directory.path(), config, None).unwrap();
        assert_status_eq(&restarted.status().unwrap(), &after);
        assert_eq!(
            restarted
                .record(pair.reveal.compute_txid())
                .unwrap()
                .is_some(),
            kept
        );
    }
}

#[test]
fn shared_parent_resolution_processes_at_most_128_active_references_per_call() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    // Reuse one real reveal in separate mock blocks solely to exercise the
    // archive reference bound. This is not a consensus-valid spend history.
    let mut blocks = Vec::new();
    for nonce in 1..=129 {
        blocks.push(witness_block(
            std::slice::from_ref(&pair.reveal),
            blocks.last(),
            nonce,
        ));
    }
    let config = config(&blocks[0], Retention::Unpruned);
    let source = Arc::new(MemorySource::new(&blocks));
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    for _ in &blocks {
        engine.scan_next().unwrap();
    }
    let before = engine.status().unwrap();
    assert_eq!(before.scanned_blocks, 129);
    assert_eq!(before.unresolved_dependencies, 129);
    assert_eq!(before.indexed_through, None);
    let calls = (
        source.body_calls.load(Ordering::Relaxed),
        source.header_calls.load(Ordering::Relaxed),
    );
    assert_eq!(engine.resolve_commit(&pair.raw_commit).unwrap(), 128);
    let partial = engine.status().unwrap();
    assert_eq!(partial.scanned_blocks, 129);
    assert_eq!(partial.unresolved_dependencies, 1);
    assert_eq!(
        partial.indexed_through,
        Some(point(FIRST_HEIGHT + 127, &blocks[127]))
    );
    assert_eq!(partial.selected_tip, before.selected_tip);
    assert_eq!(partial.generation, before.generation);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "records"), 128);
    assert_eq!(count(&db, "dependencies"), 1);
    assert_eq!(dependency_events(&db), 128);
    assert_eq!(
        db.query_row("SELECT block_hash FROM dependencies", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        blocks[128].block_hash().to_string()
    );
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &partial);
    assert_eq!(restarted.resolve_commit(&pair.raw_commit).unwrap(), 1);
    let after = restarted.status().unwrap();
    assert_eq!(after.scanned_blocks, 129);
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(
        after.indexed_through,
        Some(point(FIRST_HEIGHT + 128, &blocks[128]))
    );
    assert_eq!(after.stored_transactions, 2);
    assert_eq!(restarted.resolve_commit(&pair.raw_commit).unwrap(), 0);
    assert_status_eq(&restarted.status().unwrap(), &after);
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "records"), 129);
    assert_eq!(dependency_events(&db), 129);
    assert_auxiliary_parent_only(&db, &pair, 258);
    assert_eq!(
        (
            source.body_calls.load(Ordering::Relaxed),
            source.header_calls.load(Ordering::Relaxed)
        ),
        calls
    );
}

#[test]
fn scans_update_abort_rolls_back_dependency_removal_record_bytes_and_event() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let (engine, config, _, _) =
        unresolved_archive(directory.path(), &pair.reveal, Retention::Unpruned);
    let before = engine.status().unwrap();
    drop(engine);
    let db = readonly_archive(directory.path());
    let original = snapshot(&db);
    drop(db);
    // This additional writer is deliberately limited to the TEMP fault harness.
    let fault = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER dependency_scan_abort BEFORE UPDATE ON scans BEGIN
        SELECT CASE WHEN
            (SELECT count(*) FROM dependencies)=0 AND
            (SELECT count(*) FROM records)=1 AND
            (SELECT count(*) FROM transactions)=2 AND NEW.unresolved=0
        THEN RAISE(ABORT, 'u4 dependency scan update abort after staged evidence')
        ELSE RAISE(ABORT, 'u4 fixture did not stage dependency resolution') END;
        END;",
        )
        .unwrap();
    drop(fault);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    match engine.resolve_commit(&pair.raw_commit).unwrap_err() {
        Error::Database(rusqlite::Error::SqliteFailure(code, detail)) => {
            assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
            assert_eq!(
                detail.as_deref(),
                Some("u4 dependency scan update abort after staged evidence")
            );
        }
        error => panic!("expected injected trigger abort, got {error}"),
    }
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), original);
    assert_eq!(dependency_events(&db), 0);
    drop(db);
    let restarted = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
    drop(restarted);
    let fault = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
    fault
        .execute_batch("DROP TRIGGER dependency_scan_abort;")
        .unwrap();
    drop(fault);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_eq!(restarted.resolve_commit(&pair.raw_commit).unwrap(), 1);
    let after = restarted.status().unwrap();
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(after.indexed_through, Some(before.application_start));
}

#[test]
fn selective_import_caches_parent_without_resolving_or_creating_scan_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let (engine, config, block, source) =
        unresolved_archive(directory.path(), &pair.reveal, Retention::Pruned);
    let missing = engine.status().unwrap();
    let calls = (
        source.body_calls.load(Ordering::Relaxed),
        source.header_calls.load(Ordering::Relaxed),
    );
    assert_eq!(engine.resolve_cached_dependency().unwrap(), 0);
    assert_status_eq(&engine.status().unwrap(), &missing);
    let package = RecordPackage {
        version: API_VERSION,
        chain_genesis: config.chain.genesis().unwrap().0,
        block: config.application_start,
        reveal: TransactionProof::from_block(
            &block,
            1,
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    };
    let receipt = engine.admit_record(package).unwrap();
    assert_eq!(receipt.block, config.application_start);
    let imported = engine.status().unwrap();
    assert_eq!(imported.scanned_blocks, missing.scanned_blocks);
    assert_eq!(
        imported.unresolved_dependencies,
        missing.unresolved_dependencies
    );
    assert_eq!(imported.indexed_through, None);
    assert_eq!(imported.selected_tip, missing.selected_tip);
    assert_eq!(imported.generation, missing.generation);
    assert_eq!(imported.stored_transactions, 2);
    assert_retained(
        &engine.record(pair.reveal.compute_txid()).unwrap().unwrap(),
        &pair,
        &block,
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "scans"), 1);
    assert_eq!(count(&db, "dependencies"), 1);
    assert_eq!(
        db.query_row("SELECT unresolved FROM scans", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(dependency_events(&db), 0);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM events WHERE kind='record'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_auxiliary_parent_only(&db, &pair, 2);
    drop(db);

    // The selective import persists, but only explicit dependency completion
    // advances the already scanned interval. It cannot create a scan mark.
    let restarted = Engine::open(directory.path(), config.clone(), None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &imported);
    assert_eq!(restarted.resolve_cached_dependency().unwrap(), 1);
    let resolved = restarted.status().unwrap();
    assert_eq!(resolved.scanned_blocks, missing.scanned_blocks);
    assert_eq!(resolved.unresolved_dependencies, 0);
    assert_eq!(resolved.indexed_through, Some(config.application_start));
    assert_eq!(resolved.stored_transactions, imported.stored_transactions);
    assert_eq!(resolved.generation, missing.generation);
    assert_eq!(resolved.selected_tip, missing.selected_tip);
    assert_eq!(restarted.resolve_cached_dependency().unwrap(), 0);
    assert_status_eq(&restarted.status().unwrap(), &resolved);
    assert_retained(
        &restarted
            .record(pair.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &pair,
        &block,
    );
    drop(restarted);
    let db = readonly_archive(directory.path());
    assert_eq!(count(&db, "scans"), 1);
    assert_eq!(count(&db, "dependencies"), 0);
    assert_eq!(dependency_events(&db), 1);
    assert_auxiliary_parent_only(&db, &pair, 2);
    assert_eq!(
        (
            source.body_calls.load(Ordering::Relaxed),
            source.header_calls.load(Ordering::Relaxed)
        ),
        calls
    );
}
