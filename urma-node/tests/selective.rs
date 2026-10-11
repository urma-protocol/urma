mod common;

use bitcoin::{
    Block, BlockHash, Transaction, Txid, Witness,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use common::*;
use rusqlite::{Connection, types::Value as SqlValue};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_core::{envelope, multipart::VerifiedRecord};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveStatus, ArchivedRecord, RecordPackage, Retention},
};

fn package(block: &Block, height: u64, position: u32, raw_commit: Vec<u8>) -> RecordPackage {
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(height, block),
        reveal: TransactionProof::from_block(
            block,
            position,
            serialize(&block.txdata[position as usize]),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: raw_commit,
    }
}

fn assert_status_eq(actual: &ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn assert_export(record: &ArchivedRecord, package: &RecordPackage, generation: u64) {
    // Equality includes all raw bytes and four Merkle paths, not just record payloads.
    assert_eq!(
        serde_json::to_vec(&record.package).unwrap(),
        serde_json::to_vec(package).unwrap()
    );
    let reveal: Transaction = deserialize(&package.reveal.transaction).unwrap();
    assert_eq!(record.receipt.generation, generation);
    assert_eq!(record.receipt.block, package.block);
    assert_eq!(record.receipt.position, package.reveal.txid_path.index);
    assert_eq!(record.receipt.txid, reveal.compute_txid());
    assert_eq!(record.receipt.wtxid, reveal.compute_wtxid());
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

// Use only after Engine has been dropped, as required by common::readonly_archive.
// Full rows detect overwrites and event changes as well as inserted transactions.
fn snapshot(db: &Connection) -> BTreeMap<&'static str, Vec<Vec<SqlValue>>> {
    [
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
        "sqlite_sequence",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<SqlValue>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table, rows)
    })
    .collect()
}

#[test]
fn two_engines_selective_import_omits_a_record_until_full_audit_without_claiming_coverage() {
    let first = profile();
    let second = SignedPair::load("proof-post");
    let transactions = [first.transactions(), second.transactions()].concat();
    let block = witness_block(&transactions, None, 10);
    let archive_config = config(&block, Retention::Unpruned);
    let directory_a = tempfile::tempdir().unwrap();
    let directory_b = tempfile::tempdir().unwrap();
    let source_a = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let source_b = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine_a = Engine::open(
        directory_a.path(),
        archive_config.clone(),
        Some(source_a.clone()),
    )
    .unwrap();
    let engine_b = Engine::open(
        directory_b.path(),
        archive_config.clone(),
        Some(source_b.clone()),
    )
    .unwrap();
    engine_a.synchronize_headers().unwrap();
    let audited = engine_a.scan_next().unwrap();
    assert_eq!(audited.scanned_blocks, 1);
    assert_eq!(audited.indexed_through, Some(point(FIRST_HEIGHT, &block)));
    assert_eq!(audited.stored_transactions, 4);
    let exported_first = engine_a
        .record(first.reveal.compute_txid())
        .unwrap()
        .unwrap();
    let exported_second = engine_a
        .record(second.reveal.compute_txid())
        .unwrap()
        .unwrap();
    assert_export(
        &exported_first,
        &package(&block, FIRST_HEIGHT, 2, first.raw_commit.clone()),
        audited.generation,
    );
    assert_export(
        &exported_second,
        &package(&block, FIRST_HEIGHT, 4, second.raw_commit.clone()),
        audited.generation,
    );

    let before = engine_b.synchronize_headers().unwrap();
    assert_eq!(before.selected_tip, audited.selected_tip);
    assert_eq!(before.scanned_blocks, 0);
    assert_eq!(before.indexed_through, None);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    let receipt = engine_b
        .admit_record(exported_first.package.clone())
        .unwrap();
    let cached = engine_b.status().unwrap();
    assert_eq!(receipt.generation, before.generation);
    assert_eq!(cached.generation, before.generation);
    assert_eq!(cached.scanned_blocks, 0);
    assert_eq!(cached.indexed_through, None);
    assert_eq!(cached.unresolved_dependencies, 0);
    assert_eq!(cached.stored_transactions, 2);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    assert_export(
        &engine_b
            .record(first.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &exported_first.package,
        cached.generation,
    );
    assert!(
        engine_b
            .record(second.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    drop(engine_b);
    let db = readonly_archive(directory_b.path());
    for table in ["scans", "locators", "dependencies", "pins"] {
        assert_eq!(count(&db, table), 0, "{table}");
    }
    assert_eq!(count(&db, "records"), 1);
    let bytes = stored_bytes(&db);
    assert_eq!(bytes.len(), 2);
    assert_eq!(
        bytes[&first.reveal.compute_wtxid().to_string()],
        first.raw_reveal
    );
    assert_eq!(
        bytes[&first.commit.compute_wtxid().to_string()],
        first.raw_commit
    );
    drop(db);

    let engine_b =
        Engine::open(directory_b.path(), archive_config, Some(source_b.clone())).unwrap();
    assert_status_eq(&engine_b.status().unwrap(), &cached);
    let complete = engine_b.scan_next().unwrap();
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 1);
    assert_eq!(complete.scanned_blocks, 1);
    assert_eq!(complete.indexed_through, Some(point(FIRST_HEIGHT, &block)));
    assert_eq!(complete.unresolved_dependencies, 0);
    assert_eq!(complete.stored_transactions, 4);
    assert_export(
        &engine_b
            .record(first.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &exported_first.package,
        complete.generation,
    );
    assert_export(
        &engine_b
            .record(second.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &exported_second.package,
        complete.generation,
    );
}

#[test]
fn rejected_packages_do_not_write_or_overwrite_any_archive_state() {
    let existing = profile();
    let target = SignedPair::load("proof-post");
    let block = witness_block(
        &[existing.transactions(), target.transactions()].concat(),
        None,
        20,
    );
    let archive_config = config(&block, Retention::Unpruned);
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        archive_config.clone(),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let kept = package(&block, FIRST_HEIGHT, 2, existing.raw_commit.clone());
    engine.admit_record(kept.clone()).unwrap();
    let before = engine.status().unwrap();
    drop(engine);
    let db = readonly_archive(directory.path());
    let saved = snapshot(&db);
    drop(db);
    let valid = package(&block, FIRST_HEIGHT, 4, target.raw_commit.clone());
    let mut cases = Vec::new();
    let mut wrong = valid.clone();
    wrong.version += 1;
    cases.push(("version", wrong, "version or network mismatch"));
    let mut wrong = valid.clone();
    wrong.chain_genesis = Chain::LitecoinTestnet.genesis().unwrap().0;
    cases.push(("chain", wrong, "version or network mismatch"));
    let mut wrong = valid.clone();
    wrong.block.height += 1;
    cases.push((
        "unselected height",
        wrong,
        "block is not in the selected view",
    ));
    let mut wrong = valid.clone();
    wrong.block.hash = BlockHash::all_zeros();
    cases.push(("hash", wrong, "superseded chain view"));
    let mut wrong = valid.clone();
    let mut reveal = target.reveal.clone();
    let mut items = reveal.input[0].witness.to_vec();
    items[0][0] ^= 1;
    reveal.input[0].witness = Witness::from_slice(&items);
    assert_eq!(reveal.compute_txid(), target.reveal.compute_txid());
    assert_ne!(reveal.compute_wtxid(), target.reveal.compute_wtxid());
    wrong.reveal.transaction = serialize(&reveal);
    cases.push(("same TXID modified witness", wrong, "selective inclusion"));
    let mut wrong = valid.clone();
    wrong.reveal.coinbase_witness_path.siblings[0][0] ^= 1;
    cases.push(("coinbase zero witness path", wrong, "selective inclusion"));
    let mut wrong = valid.clone();
    let mut commit = target.commit.clone();
    commit.input[0].previous_output.txid = Txid::all_zeros();
    assert_eq!(commit.output, target.commit.output);
    assert_ne!(commit.compute_txid(), target.commit.compute_txid());
    wrong.commit = serialize(&commit);
    cases.push((
        "same outputs alternate commit TXID",
        wrong,
        "selective URMA proof",
    ));
    let mut wrong = valid.clone();
    wrong.commit = vec![1];
    cases.push(("malformed commit", wrong, "selective commit"));
    let mut wrong = kept.clone();
    wrong.commit = vec![1];
    cases.push((
        "invalid overwrite of existing record",
        wrong,
        "selective commit",
    ));

    for (name, wrong, message) in cases {
        let engine = Engine::open(directory.path(), archive_config.clone(), None).unwrap();
        let error = engine.admit_record(wrong).unwrap_err();
        assert!(
            matches!(error, Error::Invalid(_) | Error::Stale),
            "{name}: {error}"
        );
        assert!(error.to_string().contains(message), "{name}: {error}");
        assert_status_eq(&engine.status().unwrap(), &before);
        assert_export(
            &engine
                .record(existing.reveal.compute_txid())
                .unwrap()
                .unwrap(),
            &kept,
            before.generation,
        );
        assert!(
            engine
                .record(target.reveal.compute_txid())
                .unwrap()
                .is_none()
        );
        drop(engine);
        let db = readonly_archive(directory.path());
        assert_eq!(
            snapshot(&db),
            saved,
            "{name}: rejection wrote archive state"
        );
    }
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

// Both the malformed URMA record and the bad signature are included under the
// independently selected header, so admission must reach URMA verification.
fn assert_included_but_invalid_urma_is_refused(
    commit: Transaction,
    reveal: Transaction,
    raw_commit: Vec<u8>,
    nonce: u32,
    expected_error: &str,
) {
    let directory = tempfile::tempdir().unwrap();
    let block = witness_block(&[commit, reveal.clone()], None, nonce);
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let package = package(&block, FIRST_HEIGHT, 2, raw_commit);
    assert_eq!(
        package
            .reveal
            .verify(Chain::BitcoinRegtest, &block.header)
            .unwrap()
            .transaction(),
        &reveal
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    let saved = snapshot(&db);
    drop(db);
    let engine = Engine::open(directory.path(), config(&block, Retention::Unpruned), None).unwrap();
    let error = engine.admit_record(package).unwrap_err();
    assert!(matches!(error, Error::Invalid(_)), "{error}");
    assert!(error.to_string().contains(expected_error), "{error}");
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(engine.record(reveal.compute_txid()).unwrap().is_none());
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(snapshot(&db), saved);
}

#[test]
fn included_invalid_schnorr_signature_is_rejected_after_inclusion_without_writes() {
    let pair = profile();
    let mut reveal = pair.reveal.clone();
    let mut items = reveal.input[0].witness.to_vec();
    items[0][63] ^= 1;
    reveal.input[0].witness = Witness::from_slice(&items);
    assert_eq!(reveal.compute_txid(), pair.reveal.compute_txid());
    assert!(envelope::extract_reveal(&reveal).is_ok());
    assert!(VerifiedRecord::verify(reveal.compute_txid(), &reveal, &pair.commit).is_err());
    assert_included_but_invalid_urma_is_refused(
        pair.commit,
        reveal,
        pair.raw_commit,
        30,
        "selective URMA proof",
    );
}

#[test]
fn authentically_signed_invalid_v0_record_is_rejected_without_writes() {
    let raw_commit = vector("proof-profile-utf8-two-byte129.commit");
    let commit = deserialize(&raw_commit).unwrap();
    let reveal: Transaction =
        deserialize(&vector("proof-profile-utf8-two-byte129.reveal")).unwrap();
    let proof = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(
        proof.record_bytes(),
        vector("profile-utf8-two-byte129.record")
    );
    assert!(envelope::verify_reveal(&reveal, &commit).is_err());
    assert_included_but_invalid_urma_is_refused(
        commit,
        reveal,
        raw_commit,
        31,
        "selective V0 record",
    );
}

#[test]
fn selective_commit_bytes_do_not_assert_commit_inclusion_or_authenticate_its_witness() {
    let pair = profile();
    let mut unasserted_commit = pair.commit.clone();
    unasserted_commit.input[0].witness = Witness::from_slice(&[b"unasserted commit witness"]);
    assert_eq!(unasserted_commit.compute_txid(), pair.commit.compute_txid());
    assert_ne!(
        unasserted_commit.compute_wtxid(),
        pair.commit.compute_wtxid()
    );
    envelope::verify_reveal(&pair.reveal, &unasserted_commit).unwrap();
    let block = witness_block(std::slice::from_ref(&pair.reveal), None, 40);
    assert!(
        block
            .txdata
            .iter()
            .all(|tx| tx.compute_txid() != pair.commit.compute_txid())
    );
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let package = package(&block, FIRST_HEIGHT, 1, serialize(&unasserted_commit));
    engine.admit_record(package.clone()).unwrap();
    let status = engine.status().unwrap();
    assert_eq!(status.scanned_blocks, 0);
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.unresolved_dependencies, 0);
    assert_export(
        &engine.record(pair.reveal.compute_txid()).unwrap().unwrap(),
        &package,
        before.generation,
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(
        stored_bytes(&db)[&unasserted_commit.compute_wtxid().to_string()],
        package.commit
    );
    for table in ["locators", "dependencies", "scans", "pins"] {
        assert_eq!(count(&db, table), 0, "{table}");
    }
}

#[test]
fn selective_admission_does_not_resolve_an_existing_scan_dependency_or_locator() {
    let pair = profile();
    let block = witness_block(std::slice::from_ref(&pair.reveal), None, 41);
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Unpruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.scanned_blocks, 1);
    assert_eq!(before.indexed_through, None);
    assert_eq!(before.unresolved_dependencies, 1);
    drop(engine);
    let db = readonly_archive(directory.path());
    let saved = snapshot(&db);
    assert_eq!(count(&db, "locators"), 2);
    drop(db);
    let engine = Engine::open(directory.path(), config(&block, Retention::Unpruned), None).unwrap();
    let package = package(&block, FIRST_HEIGHT, 1, pair.raw_commit);
    engine.admit_record(package.clone()).unwrap();
    let after = engine.status().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(after.indexed_through, None);
    assert_eq!(after.unresolved_dependencies, 1);
    assert_export(
        &engine.record(pair.reveal.compute_txid()).unwrap().unwrap(),
        &package,
        before.generation,
    );
    drop(engine);
    let db = readonly_archive(directory.path());
    let after = snapshot(&db);
    for table in [
        "scans",
        "locators",
        "dependencies",
        "pins",
        "selected",
        "state",
    ] {
        assert_eq!(after[table], saved[table], "{table}");
    }
}

#[test]
fn reorg_hides_selective_orphan_exports_and_keeps_original_bytes_across_restart() {
    let pair = profile();
    let anchor = witness_block(&[], None, 50);
    let original = witness_block(&pair.transactions(), Some(&anchor), 51);
    let replacement = witness_block(&[], Some(&anchor), 52);
    let directory_a = tempfile::tempdir().unwrap();
    let directory_b = tempfile::tempdir().unwrap();
    let archive_config = config(&anchor, Retention::Unpruned);
    let engine_a = Engine::open(
        directory_a.path(),
        archive_config.clone(),
        Some(Arc::new(MemorySource::new(&[
            anchor.clone(),
            original.clone(),
        ]))),
    )
    .unwrap();
    engine_a.synchronize_headers().unwrap();
    engine_a.scan_next().unwrap();
    engine_a.scan_next().unwrap();
    let exported = engine_a
        .record(pair.reveal.compute_txid())
        .unwrap()
        .unwrap();
    let source_b = Arc::new(MemorySource::new(&[anchor.clone(), original.clone()]));
    let engine_b = Engine::open(
        directory_b.path(),
        archive_config.clone(),
        Some(source_b.clone()),
    )
    .unwrap();
    engine_b.synchronize_headers().unwrap();
    engine_b.admit_record(exported.package.clone()).unwrap();
    let before = engine_b.status().unwrap();
    source_b.replace_branch(&[anchor, replacement.clone()]);
    let after = engine_b.synchronize_headers().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(
        after.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(after.scanned_blocks, 0);
    assert_eq!(after.indexed_through, None);
    assert_eq!(after.stored_transactions, 2);
    assert!(
        engine_b
            .record(pair.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        engine_b.admit_record(exported.package.clone()),
        Err(Error::Stale)
    ));
    assert_status_eq(&engine_b.status().unwrap(), &after);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    drop(engine_b);
    let db = readonly_archive(directory_b.path());
    let stored = stored_bytes(&db);
    assert_eq!(
        stored[&pair.reveal.compute_wtxid().to_string()],
        pair.raw_reveal
    );
    assert_eq!(
        stored[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
    assert_eq!(count(&db, "records"), 1);
    for table in ["scans", "dependencies", "locators", "pins"] {
        assert_eq!(count(&db, table), 0);
    }
    drop(db);
    let engine_b = Engine::open(directory_b.path(), archive_config, None).unwrap();
    assert_status_eq(&engine_b.status().unwrap(), &after);
    assert!(
        engine_b
            .record(pair.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
}

#[test]
fn pruned_receiver_caches_an_explicit_leaf_without_pin_or_complete_object() {
    let root = SignedPair::load("multipart/one-root");
    let leaf = SignedPair::load("multipart/one-leaf");
    let data = SignedPair::load("multipart/one-part-0");
    let block = witness_block(
        &[
            root.transactions(),
            leaf.transactions(),
            data.transactions(),
        ]
        .concat(),
        None,
        60,
    );
    let directory_a = tempfile::tempdir().unwrap();
    let directory_b = tempfile::tempdir().unwrap();
    let engine_a = Engine::open(
        directory_a.path(),
        config(&block, Retention::Unpruned),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine_a.synchronize_headers().unwrap();
    engine_a.scan_next().unwrap();
    let exported = engine_a
        .record(leaf.reveal.compute_txid())
        .unwrap()
        .unwrap();
    let archive_config = config(&block, Retention::Pruned);
    let source_b = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine_b = Engine::open(
        directory_b.path(),
        archive_config.clone(),
        Some(source_b.clone()),
    )
    .unwrap();
    engine_b.synchronize_headers().unwrap();
    engine_b.admit_record(exported.package.clone()).unwrap();
    let status = engine_b.status().unwrap();
    assert_eq!(status.retention, Retention::Pruned);
    assert_eq!(status.scanned_blocks, 0);
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.unresolved_dependencies, 0);
    assert_eq!(status.stored_transactions, 2);
    assert_export(
        &engine_b
            .record(leaf.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &exported.package,
        status.generation,
    );
    assert!(
        engine_b
            .record(root.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    assert!(
        engine_b
            .record(data.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    drop(engine_b);
    let db = readonly_archive(directory_b.path());
    assert_eq!(count(&db, "records"), 1);
    for table in ["pins", "scans", "locators", "dependencies"] {
        assert_eq!(count(&db, table), 0, "{table}");
    }
    let stored = stored_bytes(&db);
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[&leaf.reveal.compute_wtxid().to_string()],
        leaf.raw_reveal
    );
    assert_eq!(
        stored[&leaf.commit.compute_wtxid().to_string()],
        leaf.raw_commit
    );
    assert!(!stored.contains_key(&root.reveal.compute_wtxid().to_string()));
    assert!(!stored.contains_key(&data.reveal.compute_wtxid().to_string()));
    drop(db);
    let engine_b = Engine::open(directory_b.path(), archive_config, None).unwrap();
    assert_status_eq(&engine_b.status().unwrap(), &status);
    assert_export(
        &engine_b
            .record(leaf.reveal.compute_txid())
            .unwrap()
            .unwrap(),
        &exported.package,
        status.generation,
    );
}
