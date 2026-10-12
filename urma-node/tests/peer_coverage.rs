//! Peer inventory coverage at Engine level. Coverage is a peer's listing claim
//! over selected heights, never scan evidence; omissions come only from this
//! node's own full-block scans. Genuine signed vectors in mock-selected
//! witness-authenticated blocks: no PoW, UTXO or consensus claim.
#[allow(dead_code)]
mod common;
use bitcoin::{Block, Transaction, consensus::serialize};
use common::{FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, witness_block};
use libp2p::identity::Keypair;
use std::{path::Path, sync::Arc};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, RecordPackage, Retention},
};

const BLOCKS: u64 = 5;
const TIP: u64 = FIRST_HEIGHT + BLOCKS - 1;

fn peer() -> String {
    Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string()
}

// One block per offset; `records` places signed pairs at block offsets.
fn blocks(records: &[(u64, &SignedPair)], salt: u32) -> Vec<Block> {
    let mut chain: Vec<Block> = Vec::new();
    for offset in 0..BLOCKS {
        let transactions: Vec<Transaction> = records
            .iter()
            .filter(|(at, _)| *at == offset)
            .flat_map(|(_, pair)| pair.transactions())
            .collect();
        let nonce = salt + u32::try_from(offset).unwrap();
        let block = witness_block(&transactions, chain.last(), nonce);
        chain.push(block);
    }
    chain
}

struct Fixture {
    config: ArchiveConfig,
    source: Arc<MemorySource>,
    blocks: Vec<Block>,
}

fn fixture(records: &[(u64, &SignedPair)]) -> Fixture {
    let blocks = blocks(records, 1);
    Fixture {
        config: config(&blocks[0], Retention::Unpruned),
        source: Arc::new(MemorySource::new(&blocks)),
        blocks,
    }
}

// Headers only: coverage needs a selected view, not scanned blocks.
fn synced(directory: &Path, fixture: &Fixture) -> Engine {
    let source = fixture.source.clone();
    let engine = Engine::open(directory, fixture.config.clone(), Some(source)).unwrap();
    let status = engine.synchronize_headers().unwrap();
    assert_eq!(status.selected_tip, Some(point(TIP, &fixture.blocks[4])));
    assert_eq!(status.scanned_blocks, 0);
    engine
}

fn cover(engine: &Engine, peer: &str, from: u64, to: u64) -> Result<(), Error> {
    let generation = engine.status().unwrap().generation;
    engine.record_peer_coverage(peer, from, to, generation)
}

// The Engine accessor and the status field must agree.
fn synced_through(engine: &Engine) -> Option<u64> {
    let direct = engine.peer_synced_through().unwrap();
    assert_eq!(engine.status().unwrap().peer_synced_through, direct);
    direct.map(|point| point.height)
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
            u32::try_from(position).unwrap(),
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

#[test]
fn union_of_two_peers_counts_only_the_contiguous_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = fixture(&[]);
    let engine = synced(directory.path(), &fixture);
    let (p, q) = (peer(), peer());
    assert_eq!(synced_through(&engine), None);
    cover(&engine, &p, FIRST_HEIGHT, FIRST_HEIGHT + 1).unwrap();
    cover(&engine, &q, FIRST_HEIGHT + 3, TIP).unwrap();
    // The gap at 102 stops the union even though 103..104 are covered.
    assert_eq!(synced_through(&engine), Some(FIRST_HEIGHT + 1));
    assert_eq!(engine.peer_cursor(&q).unwrap(), FIRST_HEIGHT);
    cover(&engine, &q, FIRST_HEIGHT + 2, FIRST_HEIGHT + 2).unwrap();
    assert_eq!(synced_through(&engine), Some(TIP));
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT + 2);
    let status = engine.status().unwrap();
    assert_eq!(status.scanned_blocks, 0);
    assert_eq!(
        status.indexed_through, None,
        "coverage is not scan evidence"
    );
}

#[test]
fn adjacent_and_overlapping_ranges_merge_into_one_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = fixture(&[]);
    let engine = synced(directory.path(), &fixture);
    let p = peer();
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT);
    cover(&engine, &p, FIRST_HEIGHT, FIRST_HEIGHT + 1).unwrap();
    cover(&engine, &p, FIRST_HEIGHT + 2, FIRST_HEIGHT + 3).unwrap();
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT + 4);
    cover(&engine, &p, FIRST_HEIGHT + 1, FIRST_HEIGHT + 2).unwrap();
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT + 4);
    assert_eq!(synced_through(&engine), Some(FIRST_HEIGHT + 3));
    cover(&engine, &p, TIP, TIP).unwrap();
    assert_eq!(engine.peer_cursor(&p).unwrap(), TIP + 1);
}

#[test]
fn coverage_outside_the_selected_view_or_stale_is_refused_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = fixture(&[]);
    let engine = synced(directory.path(), &fixture);
    let p = peer();
    let before = serde_json::to_value(engine.status().unwrap()).unwrap();
    assert!(cover(&engine, &p, TIP, TIP + 1).is_err());
    assert!(cover(&engine, &p, FIRST_HEIGHT + 2, FIRST_HEIGHT + 1).is_err());
    assert!(cover(&engine, &p, FIRST_HEIGHT - 1, FIRST_HEIGHT).is_err());
    assert!(cover(&engine, "", FIRST_HEIGHT, FIRST_HEIGHT).is_err());
    let stale = engine.status().unwrap().generation + 1;
    let refused = engine.record_peer_coverage(&p, FIRST_HEIGHT, TIP, stale);
    assert!(matches!(refused, Err(Error::Stale)), "{refused:?}");
    let after = serde_json::to_value(engine.status().unwrap()).unwrap();
    assert_eq!(after, before);
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT);
    cover(&engine, &p, FIRST_HEIGHT, TIP).unwrap();
    assert_eq!(synced_through(&engine), Some(TIP));
}

#[test]
fn cursor_and_union_resume_from_durable_coverage_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = fixture(&[]);
    let engine = synced(directory.path(), &fixture);
    let (p, q) = (peer(), peer());
    cover(&engine, &p, FIRST_HEIGHT, FIRST_HEIGHT + 2).unwrap();
    cover(&engine, &q, FIRST_HEIGHT + 4, TIP).unwrap();
    drop(engine);
    let reopened = Engine::open(directory.path(), fixture.config.clone(), None).unwrap();
    assert_eq!(reopened.peer_cursor(&p).unwrap(), FIRST_HEIGHT + 3);
    assert_eq!(reopened.peer_cursor(&q).unwrap(), FIRST_HEIGHT);
    assert_eq!(synced_through(&reopened), Some(FIRST_HEIGHT + 2));
}

// Omissions are detected by this node's scan of covered blocks; an admitted
// (listed) record is held and therefore never an omission.
fn scan_with_coverage(engine: &Engine, fixture: &Fixture, p: &str, listed: &SignedPair) {
    cover(engine, p, FIRST_HEIGHT, TIP).unwrap();
    let block = &fixture.blocks[3];
    let package = package(block, FIRST_HEIGHT + 3, listed);
    engine.admit_record(package).unwrap();
    for _ in 0..BLOCKS {
        engine.scan_next().unwrap();
    }
}

#[test]
fn own_scan_omissions_persist_and_reorg_removes_deselected_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let (hidden, listed) = (profile(), SignedPair::load("proof-post"));
    let fixture = fixture(&[(2, &hidden), (3, &listed)]);
    let engine = synced(directory.path(), &fixture);
    let p = peer();
    scan_with_coverage(&engine, &fixture, &p, &listed);
    let found = engine.peer_omissions().unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].peer, p);
    assert_eq!(found[0].txid, hidden.reveal.compute_txid());
    assert_eq!(found[0].block, point(FIRST_HEIGHT + 2, &fixture.blocks[2]));
    assert_eq!(engine.omitting_peers().unwrap(), vec![p.clone()]);
    assert_eq!(engine.status().unwrap().peer_omissions, 1);
    drop(engine);
    let source = fixture.source.clone();
    let engine = Engine::open(directory.path(), fixture.config.clone(), Some(source)).unwrap();
    assert_eq!(
        engine.peer_omissions().unwrap(),
        found,
        "omissions are durable"
    );
    // Replace heights 102.. with empty blocks: the omitted placement leaves
    // the selected view and coverage truncates below the fork.
    let mut branch = fixture.blocks[..2].to_vec();
    for nonce in 900..903 {
        let block = witness_block(&[], branch.last(), nonce);
        branch.push(block);
    }
    fixture.source.replace_branch(&branch);
    engine.synchronize_headers().unwrap();
    assert_eq!(synced_through(&engine), Some(FIRST_HEIGHT + 1));
    assert_eq!(engine.peer_cursor(&p).unwrap(), FIRST_HEIGHT + 2);
    assert!(engine.peer_omissions().unwrap().is_empty());
    assert!(engine.omitting_peers().unwrap().is_empty());
    assert_eq!(engine.status().unwrap().peer_omissions, 0);
}

#[test]
fn coverage_recorded_after_a_reorg_needs_the_new_generation() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = fixture(&[]);
    let engine = synced(directory.path(), &fixture);
    let p = peer();
    let old = engine.status().unwrap().generation;
    let mut branch = fixture.blocks[..4].to_vec();
    branch.push(witness_block(&[], branch.last(), 777));
    fixture.source.replace_branch(&branch);
    engine.synchronize_headers().unwrap();
    let current = engine.status().unwrap().generation;
    assert_ne!(current, old);
    let stale = engine.record_peer_coverage(&p, FIRST_HEIGHT, TIP, old);
    assert!(matches!(stale, Err(Error::Stale)), "{stale:?}");
    engine
        .record_peer_coverage(&p, FIRST_HEIGHT, TIP, current)
        .unwrap();
    assert_eq!(synced_through(&engine), Some(TIP));
}
