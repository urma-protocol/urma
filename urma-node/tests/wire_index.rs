#[allow(dead_code)]
mod common;

use bitcoin::{Block, consensus::serialize};
use common::*;
use std::sync::{Arc, atomic::Ordering};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, RecordPackage, Retention},
    projection::WirePage,
};

fn package(block: &Block, position: u32, pair: &SignedPair) -> RecordPackage {
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(FIRST_HEIGHT, block),
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

fn exact(
    page: &WirePage,
    index: usize,
    pair: &SignedPair,
    block: &Block,
    position: u32,
    height: u64,
) {
    let record = &page.records[index];
    let returned = &pair.reveal.output[0].script_pubkey;
    let expected =
        urma_wire::index::entry_from_verified(&pair.verified, Some(returned), height, position)
            .unwrap()
            .unwrap();
    assert_eq!(
        record.entry.return_script.as_deref(),
        Some(hex::encode(returned.as_bytes()).as_str())
    );
    assert_eq!(
        serde_json::to_value(&record.entry).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(record.block_hash, block.block_hash());
    assert_eq!(record.wtxid, pair.reveal.compute_wtxid());
}

#[test]
fn selective_pages_keep_coverage_separate_and_invalidate_on_same_generation_admission() {
    let profile = profile();
    let post = SignedPair::load("proof-post");
    let block = witness_block(
        &[profile.transactions(), post.transactions()].concat(),
        None,
        17,
    );
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let no_headers = engine.wire_page(None, 128).unwrap();
    assert!(no_headers.records.is_empty());
    assert!(no_headers.archive.selected_tip.is_none());
    engine.synchronize_headers().unwrap();
    engine.admit_record(package(&block, 2, &profile)).unwrap();
    let first = engine.wire_page(None, 1).unwrap();
    assert_eq!(first.records.len(), 1);
    assert!(first.next.is_none());
    assert_eq!(first.archive.scanned_blocks, 0);
    assert!(first.archive.indexed_through.is_none());
    exact(&first, 0, &profile, &block, 2, FIRST_HEIGHT);
    let before = serde_json::to_value(engine.status().unwrap()).unwrap();
    assert_eq!(engine.wire_page(None, 1).unwrap().snapshot, first.snapshot);
    assert_eq!(
        serde_json::to_value(engine.status().unwrap()).unwrap(),
        before
    );
    // An explicit continuation from the old endpoint cannot hide a late admission.
    let cursor = urma_node::projection::WireCursor {
        snapshot: first.snapshot,
        height: FIRST_HEIGHT,
        position: 2,
    };
    engine.admit_record(package(&block, 4, &post)).unwrap();
    assert_eq!(engine.status().unwrap().generation, 0);
    assert!(matches!(
        engine.wire_page(Some(&cursor), 1),
        Err(Error::Busy(_))
    ));
    let page1 = engine.wire_page(None, 1).unwrap();
    let page2 = engine.wire_page(page1.next.as_ref(), 1).unwrap();
    assert_eq!(page1.snapshot, page2.snapshot);
    exact(&page2, 0, &post, &block, 4, FIRST_HEIGHT);
    assert!(page2.next.is_none());
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 0);
    engine.scan_next().unwrap();
    assert!(matches!(
        engine.wire_page(page1.next.as_ref(), 1),
        Err(Error::Busy(_))
    ));
    let audited = engine.wire_page(None, 128).unwrap();
    assert_eq!(audited.records.len(), 2);
    assert_eq!(audited.archive.scanned_blocks, 1);
    assert_eq!(
        audited.archive.indexed_through,
        Some(point(FIRST_HEIGHT, &block))
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn reorg_hides_orphan_entries_and_restart_invalidates_cursors_without_losing_index() {
    let first = profile();
    let second = SignedPair::load("proof-post");
    let root = witness_block(&first.transactions(), None, 41);
    let old = witness_block(&second.transactions(), Some(&root), 42);
    let replacement = witness_block(&[], Some(&root), 43);
    let source = Arc::new(MemorySource::new(&[root.clone(), old]));
    let dir = tempfile::tempdir().unwrap();
    let config = config(&root, Retention::Pruned);
    let engine = Engine::open(dir.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    engine.scan_next().unwrap();
    let first_page = engine.wire_page(None, 1).unwrap();
    let cursor = first_page.next.unwrap();
    source.replace_branch(&[root.clone(), replacement]);
    engine.synchronize_headers().unwrap();
    assert!(matches!(
        engine.wire_page(Some(&cursor), 1),
        Err(Error::Busy(_))
    ));
    let page = engine.wire_page(None, 128).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.archive.generation, 1);
    exact(&page, 0, &first, &root, 2, FIRST_HEIGHT);
    let cursor = urma_node::projection::WireCursor {
        snapshot: page.snapshot,
        height: FIRST_HEIGHT,
        position: 2,
    };
    drop(engine);
    let engine = Engine::open(dir.path(), config, None).unwrap();
    assert!(matches!(
        engine.wire_page(Some(&cursor), 1),
        Err(Error::Busy(_))
    ));
    let restarted = engine.wire_page(None, 128).unwrap();
    assert_eq!(
        serde_json::to_value(restarted.records).unwrap(),
        serde_json::to_value(page.records).unwrap()
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn shared_archive_excludes_non_wire_records_and_rejects_limits_without_mutation() {
    let profile = profile();
    let leaf = SignedPair::load("multipart/one-leaf");
    let block = witness_block(
        &[profile.transactions(), leaf.transactions()].concat(),
        None,
        24,
    );
    let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path(),
        config(&block, Retention::Unpruned),
        Some(source.clone()),
    )
    .unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    assert!(engine.record(leaf.reveal.compute_txid()).unwrap().is_some());
    let before = serde_json::to_value(engine.status().unwrap()).unwrap();
    for limit in [0, 129, u32::MAX] {
        assert!(matches!(
            engine.wire_page(None, limit),
            Err(Error::Invalid(_))
        ));
    }
    let page = engine.wire_page(None, 128).unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.next.is_none());
    exact(&page, 0, &profile, &block, 2, FIRST_HEIGHT);
    assert_eq!(
        serde_json::to_value(engine.status().unwrap()).unwrap(),
        before
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 1);
}
