mod common;

use bitcoin::{Witness, consensus::serialize};
use common::*;
use std::sync::{Arc, atomic::Ordering};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, Retention},
};

fn assert_status_eq(actual: &ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn offline_open_restart_and_exclusive_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let block = witness_block(&[], None, 1);
    let config = config(&block, Retention::Pruned);
    let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
    let before = engine.status().unwrap();
    assert_eq!(before.application_start, config.application_start);
    assert_eq!(before.chain_genesis, config.chain.genesis().unwrap().0);
    assert_eq!(before.retention, Retention::Pruned);
    assert_eq!(before.selected_tip, None);
    assert_eq!(before.indexed_through, None);
    assert_eq!(before.scanned_blocks, 0);
    assert_eq!(before.unresolved_dependencies, 0);
    assert_eq!(before.stored_transactions, 0);
    assert!(matches!(
        engine.synchronize_headers(),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(engine.scan_next(), Err(Error::Invalid(_))));
    assert_status_eq(&engine.status().unwrap(), &before);
    assert!(matches!(
        Engine::open(directory.path(), config.clone(), None),
        Err(Error::Busy(_))
    ));
    drop(engine);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &before);
}

#[test]
fn chain_and_application_start_mismatches_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let block = witness_block(&[], None, 1);
    let config = config(&block, Retention::Pruned);
    drop(Engine::open(directory.path(), config.clone(), None).unwrap());
    let mut wrong_chain = config.clone();
    wrong_chain.chain = Chain::LitecoinTestnet;
    assert!(matches!(
        Engine::open(directory.path(), wrong_chain, None),
        Err(Error::Invalid(_))
    ));
    let mut wrong_height = config.clone();
    wrong_height.application_start.height += 1;
    assert!(matches!(
        Engine::open(directory.path(), wrong_height, None),
        Err(Error::Invalid(_))
    ));
    let mut wrong_hash = config.clone();
    wrong_hash.application_start.hash = witness_block(&[], None, 2).block_hash();
    assert!(matches!(
        Engine::open(directory.path(), wrong_hash, None),
        Err(Error::Invalid(_))
    ));

    let mut source = MemorySource::new(std::slice::from_ref(&block));
    source.chain = Chain::LitecoinTestnet;
    assert!(matches!(
        Engine::open(directory.path(), config.clone(), Some(Arc::new(source))),
        Err(Error::Invalid(_))
    ));
    let engine = Engine::open(
        directory.path(),
        config,
        Some(Arc::new(MemorySource::new(&[witness_block(&[], None, 2)]))),
    )
    .unwrap();
    assert!(matches!(
        engine.synchronize_headers(),
        Err(Error::Invalid(_))
    ));
    assert_eq!(engine.status().unwrap().selected_tip, None);
}

#[test]
fn header_synchronization_does_not_claim_a_scan() {
    let directory = tempfile::tempdir().unwrap();
    let first = witness_block(&[], None, 1);
    let second = witness_block(&[], Some(&first), 2);
    let source = Arc::new(MemorySource::new(&[first.clone(), second.clone()]));
    let engine = Engine::open(
        directory.path(),
        config(&first, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    assert_eq!(source.header_calls.load(Ordering::Relaxed), 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    let status = engine.synchronize_headers().unwrap();
    assert_eq!(status.selected_tip, Some(point(FIRST_HEIGHT + 1, &second)));
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.scanned_blocks, 0);
    assert_eq!(status.unresolved_dependencies, 0);
    assert_eq!(status.stored_transactions, 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_public_litecoin_witness_block_scans_without_fabricating_records() {
    let directory = tempfile::tempdir().unwrap();
    let (block, body) = public_litecoin_block();
    let config = ArchiveConfig {
        chain: Chain::LitecoinTestnet,
        application_start: point(4_892_705, &block),
        retention: Retention::Unpruned,
    };
    let source = Arc::new(MemorySource::with_bodies(
        config.chain,
        config.application_start.height,
        vec![body],
    ));
    let engine = Engine::open(directory.path(), config.clone(), Some(source)).unwrap();
    assert_eq!(engine.synchronize_headers().unwrap().scanned_blocks, 0);
    let status = engine.scan_next().unwrap();
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.indexed_through, Some(config.application_start));
    assert_eq!(status.unresolved_dependencies, 0);
    assert_eq!(status.stored_transactions, 0);
    drop(engine);
    let db = readonly_archive(directory.path());
    let ids: Vec<(String, String)> = db
        .prepare("SELECT txid,wtxid FROM locators ORDER BY position")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        ids,
        block
            .txdata
            .iter()
            .map(|tx| (
                tx.compute_txid().to_string(),
                tx.compute_wtxid().to_string()
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn same_block_profile_and_commit_are_archived_with_exact_bytes_and_real_inclusion() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let block = witness_block(&pair.transactions(), None, 1);
    let config = config(&block, Retention::Pruned);
    let engine = Engine::open(
        directory.path(),
        config.clone(),
        Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let status = engine.scan_next().unwrap();
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.indexed_through, Some(config.application_start));
    assert_eq!(status.unresolved_dependencies, 0);
    assert_eq!(status.stored_transactions, 2);
    assert_status_eq(&engine.scan_next().unwrap(), &status);
    drop(engine);
    let db = readonly_archive(directory.path());
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
    let (author, record, proof): (String, Vec<u8>, Vec<u8>) = db
        .query_row("SELECT author,record,proof FROM records", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(author, pair.verified.author().to_string());
    assert_eq!(record, vector("profile-utf8-two-byte128.record"));
    assert_eq!(record, pair.verified.record_bytes());
    let proof: TransactionProof = serde_json::from_slice(&proof).unwrap();
    let included = proof.verify(config.chain, &block.header).unwrap();
    assert_eq!(included.position(), 2);
    assert_eq!(included.raw(), pair.raw_reveal);
    assert_eq!(included.transaction(), &pair.reveal);
    assert_eq!(proof.coinbase, serialize(&block.txdata[0]));
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &status);
}

#[test]
fn missing_parent_is_unresolved_and_never_indexed() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let block = witness_block(std::slice::from_ref(&pair.reveal), None, 1);
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let status = engine.scan_next().unwrap();
    assert_eq!(status.scanned_blocks, 1);
    assert_eq!(status.unresolved_dependencies, 1);
    assert_eq!(status.indexed_through, None);
    assert_eq!(status.stored_transactions, 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 1);
    drop(engine);
    let db = readonly_archive(directory.path());
    let (commit, proof): (String, Vec<u8>) = db
        .query_row("SELECT commit_txid,proof FROM dependencies", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(commit, pair.commit.compute_txid().to_string());
    let proof: TransactionProof = serde_json::from_slice(&proof).unwrap();
    assert_eq!(
        proof
            .verify(Chain::BitcoinRegtest, &block.header)
            .unwrap()
            .raw(),
        pair.raw_reveal
    );
    assert!(stored_bytes(&db).is_empty());
}

#[test]
fn stripped_witness_block_is_refused_without_progress() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let block = witness_block(&pair.transactions(), None, 1);
    let mut stripped = block.clone();
    for tx in &mut stripped.txdata {
        for input in &mut tx.input {
            input.witness = Witness::new();
        }
    }
    assert_eq!(stripped.block_hash(), block.block_hash());
    assert!(stripped.check_merkle_root());
    let source = Arc::new(MemorySource::with_bodies(
        Chain::BitcoinRegtest,
        FIRST_HEIGHT,
        vec![Body {
            header: block.header,
            raw: serialize(&stripped),
        }],
    ));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    let error = engine.scan_next().unwrap_err();
    assert!(matches!(error, Error::Invalid(_)), "{error}");
    assert!(error.to_string().contains("witness commitment"));
    assert_status_eq(&engine.status().unwrap(), &before);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert_eq!(
        db.query_row("SELECT count(*) FROM scans", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(stored_bytes(&db).is_empty());
}

#[test]
fn reorg_invalidates_coverage_but_preserves_archived_bytes_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let first = witness_block(&[], None, 1);
    let second = witness_block(&pair.transactions(), Some(&first), 2);
    let replacement = witness_block(&[], Some(&first), 3);
    let config = config(&first, Retention::Pruned);
    let source = Arc::new(MemorySource::new(&[first.clone(), second.clone()]));
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.scanned_blocks, 2);
    assert_eq!(
        before.indexed_through,
        Some(point(FIRST_HEIGHT + 1, &second))
    );
    assert_eq!(before.stored_transactions, 2);
    source.replace_branch(&[first.clone(), replacement.clone()]);
    let after = engine.synchronize_headers().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(
        after.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(after.indexed_through, Some(point(FIRST_HEIGHT, &first)));
    assert_eq!(after.scanned_blocks, 1);
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(after.stored_transactions, before.stored_transactions);
    drop(engine);
    let db = readonly_archive(directory.path());
    let stored = stored_bytes(&db);
    assert_eq!(
        stored[&pair.reveal.compute_wtxid().to_string()],
        pair.raw_reveal
    );
    assert_eq!(
        stored[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM scans", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    drop(db);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_status_eq(&restarted.status().unwrap(), &after);
}

#[test]
fn reorg_during_body_fetch_refuses_stale_result_without_progress() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let first = witness_block(&[], None, 1);
    let second = witness_block(&pair.transactions(), Some(&first), 2);
    let replacement = witness_block(&[], Some(&first), 3);
    let source = Arc::new(MemorySource::new(&[first.clone(), second]));
    let engine = Engine::open(
        directory.path(),
        config(&first, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    source.reorg_during_next_fetch(&[first, replacement]);
    assert!(matches!(engine.scan_next(), Err(Error::Stale)));
    assert_status_eq(&engine.status().unwrap(), &before);
    drop(engine);
    let db = readonly_archive(directory.path());
    assert!(stored_bytes(&db).is_empty());
    assert_eq!(
        db.query_row("SELECT count(*) FROM scans", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM locators", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn retention_keeps_root_and_commit_in_pruned_mode_and_leaf_data_in_unpruned_mode() {
    let pairs = [
        SignedPair::load("multipart/one-root"),
        SignedPair::load("multipart/one-leaf"),
        SignedPair::load("multipart/one-part-0"),
    ];
    let transactions: Vec<_> = pairs.iter().flat_map(SignedPair::transactions).collect();
    let block = witness_block(&transactions, None, 1);
    for retention in [Retention::Pruned, Retention::Unpruned] {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            directory.path(),
            config(&block, retention),
            Some(Arc::new(MemorySource::new(std::slice::from_ref(&block)))),
        )
        .unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        let kept = if retention == Retention::Pruned { 1 } else { 3 };
        assert_eq!(status.retention, retention);
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.indexed_through, Some(point(FIRST_HEIGHT, &block)));
        assert_eq!(status.unresolved_dependencies, 0);
        assert_eq!(status.stored_transactions, 2 * kept);
        drop(engine);
        let db = readonly_archive(directory.path());
        let stored = stored_bytes(&db);
        for (i, pair) in pairs.iter().enumerate() {
            let reveal = stored.get(&pair.reveal.compute_wtxid().to_string());
            let commit = stored.get(&pair.commit.compute_wtxid().to_string());
            if i == 0 || retention == Retention::Unpruned {
                assert_eq!(reveal, Some(&pair.raw_reveal));
                assert_eq!(commit, Some(&pair.raw_commit));
            } else {
                assert_eq!(reveal, None);
                assert_eq!(commit, None);
            }
        }
        let records: Vec<(Vec<u8>, Vec<u8>)> = db
            .prepare("SELECT record,proof FROM records ORDER BY position")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len() as u64, kept);
        for ((record, proof), pair) in records.iter().zip(&pairs) {
            assert_eq!(record, pair.verified.record_bytes());
            let proof: TransactionProof = serde_json::from_slice(proof).unwrap();
            assert_eq!(
                proof
                    .verify(Chain::BitcoinRegtest, &block.header)
                    .unwrap()
                    .raw(),
                pair.raw_reveal
            );
        }
        // This is record retention and scan coverage, not a complete-object API.
        assert_eq!(
            db.query_row("SELECT count(*) FROM locators", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            7
        );
    }
}
