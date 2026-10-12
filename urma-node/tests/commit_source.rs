//! Genuine signed public records in witness-authenticated mock-selected blocks.
//! Auxiliary parents have no fabricated locator, inclusion or consensus claim.
//! All source callbacks are deterministic in memory; no sockets or live nodes.
#[allow(dead_code)]
mod common;

use bitcoin::{Block, Transaction, Txid, consensus::serialize};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive, stored_bytes,
};
use rusqlite::types::Value;
use serde_json::json;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use urma_chain::{decode, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, Retention},
    source::{CommitSource, RuntimeCommitSource},
};
use urma_runtime::{
    error::Error as RuntimeError,
    node::Node,
    transport::{BlockEncoding, Evidence, Provider},
};

struct Source<F> {
    chain: Chain,
    fetch: F,
}
impl<F: Fn(Txid) -> Result<Option<Vec<u8>>, Error>> CommitSource for Source<F> {
    fn chain(&self) -> Chain {
        self.chain
    }
    fn fetch(&self, id: Txid, _cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        (self.fetch)(id)
    }
}
fn source<F: Fn(Txid) -> Result<Option<Vec<u8>>, Error>>(fetch: F) -> Source<F> {
    Source {
        chain: Chain::BitcoinRegtest,
        fetch,
    }
}

type Snapshot = BTreeMap<String, Vec<Vec<Value>>>;
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
fn calls(chain: &MemorySource) -> (usize, usize) {
    (
        chain.body_calls.load(Ordering::Relaxed),
        chain.header_calls.load(Ordering::Relaxed),
    )
}
fn status(engine: &Engine) -> serde_json::Value {
    serde_json::to_value(engine.status().unwrap()).unwrap()
}
fn selected_coverage(engine: &Engine, before: &ArchiveStatus) {
    let after = engine.status().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.selected_tip, before.selected_tip);
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(after.scan_rules_version, before.scan_rules_version);
    // Resolving real dependencies may advance the contiguous already-scanned
    // prefix. It never adds a scan or changes the selected branch.
}
fn open(directory: &Path, cfg: &ArchiveConfig, chain: &Arc<MemorySource>) -> Engine {
    Engine::open(directory, cfg.clone(), Some(chain.clone())).unwrap()
}
fn unresolved(
    directory: &Path,
    pair: &SignedPair,
    retention: Retention,
) -> (Engine, ArchiveConfig, Arc<MemorySource>) {
    let block = common::witness_block(std::slice::from_ref(&pair.reveal), None, 1);
    let cfg = config(&block, retention);
    let chain = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let engine = open(directory, &cfg, &chain);
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.unresolved_dependencies, 1);
    assert_eq!(before.indexed_through, None);
    assert_eq!(before.stored_transactions, 0);
    (engine, cfg, chain)
}

#[test]
fn exact_requested_parent_validation_retention_and_legacy_resolution_equivalence() {
    let wrong = SignedPair::load("proof-post");
    for retention in [Retention::Pruned, Retention::Unpruned] {
        for pair in [profile(), SignedPair::load("multipart/one-leaf")] {
            let directory = tempfile::tempdir().unwrap();
            let (engine, _, chain) = unresolved(directory.path(), &pair, retention);
            let before = engine.status().unwrap();
            let source_calls = calls(&chain);
            let initial = snapshot(directory.path());
            for bad in [
                wrong.raw_commit.clone(),
                vec![0],
                [pair.raw_commit.as_slice(), &[0]].concat(),
                vec![0; 8_000_001],
            ] {
                let requests = RefCell::new(Vec::new());
                let fetch = source(|id| {
                    requests.borrow_mut().push(id);
                    Ok(Some(bad.clone()))
                });
                assert!(matches!(
                    engine.resolve_next_dependency(&fetch, &AtomicBool::new(false)),
                    Err(Error::Invalid(_))
                ));
                assert_eq!(*requests.borrow(), vec![pair.commit.compute_txid()]);
                assert_eq!(snapshot(directory.path()), initial);
                assert_eq!(status(&engine), serde_json::to_value(&before).unwrap());
            }
            let fetch = source(|id| {
                assert_eq!(id, pair.commit.compute_txid());
                Ok(Some(pair.raw_commit.clone()))
            });
            assert_eq!(
                engine
                    .resolve_next_dependency(&fetch, &AtomicBool::new(false))
                    .unwrap(),
                1
            );
            let after = engine.status().unwrap();
            assert_eq!(after.unresolved_dependencies, 0);
            assert_eq!(after.indexed_through, Some(before.application_start));
            selected_coverage(&engine, &before);
            assert_eq!(calls(&chain), source_calls);
            let kept = matches!(retention, Retention::Unpruned)
                || pair.verified.txid() == profile().verified.txid();
            if kept {
                let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
                assert_eq!(record.package.commit, pair.raw_commit);
                assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
            } else {
                assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
            }
            let never = source(|_| -> Result<Option<Vec<u8>>, Error> {
                panic!("resolved parent was refetched")
            });
            assert_eq!(
                engine
                    .resolve_next_dependency(&never, &AtomicBool::new(false))
                    .unwrap(),
                0
            );
            drop(engine);
            let actual = snapshot(directory.path());
            let legacy_directory = tempfile::tempdir().unwrap();
            let (legacy, _, _) = unresolved(legacy_directory.path(), &pair, retention);
            assert_eq!(legacy.resolve_commit(&wrong.raw_commit).unwrap(), 0);
            assert_eq!(legacy.resolve_commit(&pair.raw_commit).unwrap(), 1);
            assert_eq!(legacy.resolve_commit(&pair.raw_commit).unwrap(), 0);
            drop(legacy);
            assert_eq!(
                actual,
                snapshot(legacy_directory.path()),
                "legacy persisted semantics changed"
            );
            let db = readonly_archive(directory.path());
            let stored = stored_bytes(&db);
            assert_eq!(stored.len(), if kept { 2 } else { 0 });
            if kept {
                assert_eq!(
                    stored[&pair.commit.compute_wtxid().to_string()],
                    pair.raw_commit
                );
            }
            let parents: i64 = db
                .query_row(
                    "SELECT count(*) FROM locators WHERE txid=?1",
                    [pair.commit.compute_txid().to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(parents, 0, "auxiliary parent invented placement");
        }
    }
}

#[test]
fn pre_cancel_chain_mismatch_callback_cancel_reentrancy_and_same_parent_reorg_refusal() {
    let mut pairs = [profile(), SignedPair::load("proof-post")];
    pairs.sort_by_key(|pair| pair.commit.compute_txid().to_string());
    let first = common::witness_block(&[], None, 10);
    let reveals: Vec<Transaction> = pairs.iter().map(|pair| pair.reveal.clone()).collect();
    let old = common::witness_block(&reveals, Some(&first), 11);
    let replacement = common::witness_block(&reveals, Some(&first), 12);
    let directory = tempfile::tempdir().unwrap();
    let chain = Arc::new(MemorySource::new(&[first.clone(), old.clone()]));
    let cfg = config(&first, Retention::Unpruned);
    let engine = open(directory.path(), &cfg, &chain);
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    engine.scan_next().unwrap();
    let before = status(&engine);
    let initial = snapshot(directory.path());
    let source_calls = calls(&chain);
    let never =
        source(|_| -> Result<Option<Vec<u8>>, Error> { panic!("pre-cancel must not fetch") });
    assert!(matches!(
        engine.resolve_next_dependency(&never, &AtomicBool::new(true)),
        Err(Error::Busy(_))
    ));
    let wrong_chain = Source {
        chain: Chain::LitecoinTestnet,
        fetch: |_| -> Result<Option<Vec<u8>>, Error> { panic!("wrong chain must not fetch") },
    };
    assert!(matches!(
        engine.resolve_next_dependency(&wrong_chain, &AtomicBool::new(false)),
        Err(Error::Invalid(_))
    ));
    assert_eq!(snapshot(directory.path()), initial);
    assert_eq!(status(&engine), before);
    let cancelled = AtomicBool::new(false);
    let requests = RefCell::new(Vec::new());
    let callback = source(|id| {
        requests.borrow_mut().push(id);
        assert_eq!(id, pairs[0].commit.compute_txid());
        assert_eq!(status(&engine), before);
        assert!(matches!(
            engine.resolve_next_dependency(&never, &AtomicBool::new(false)),
            Err(Error::Busy(_))
        ));
        cancelled.store(true, Ordering::Release);
        Ok(Some(pairs[0].raw_commit.clone()))
    });
    assert!(matches!(
        engine.resolve_next_dependency(&callback, &cancelled),
        Err(Error::Busy(_))
    ));
    assert_eq!(snapshot(directory.path()), initial);
    assert_eq!(*requests.borrow(), vec![pairs[0].commit.compute_txid()]);
    cancelled.store(false, Ordering::Release);
    let second = source(|id| {
        assert_eq!(
            id,
            pairs[1].commit.compute_txid(),
            "cancelled callback consumed the first cursor position only"
        );
        Ok(Some(pairs[1].raw_commit.clone()))
    });
    assert_eq!(
        engine.resolve_next_dependency(&second, &cancelled).unwrap(),
        1
    );
    assert_eq!(calls(&chain), source_calls);
    let after_reorg = RefCell::new(None);
    let reorg = source(|id| {
        assert_eq!(id, pairs[0].commit.compute_txid());
        chain.replace_branch(&[first.clone(), replacement.clone()]);
        engine.synchronize_headers().unwrap();
        engine.scan_next().unwrap();
        assert_eq!(
            engine.status().unwrap().unresolved_dependencies,
            1,
            "same parent remains pending in the newer selected view"
        );
        *after_reorg.borrow_mut() = Some(snapshot(directory.path()));
        Ok(Some(pairs[0].raw_commit.clone()))
    });
    assert!(matches!(
        engine.resolve_next_dependency(&reorg, &cancelled),
        Err(Error::Stale)
    ));
    assert_eq!(
        snapshot(directory.path()),
        after_reorg.borrow().as_ref().unwrap().clone(),
        "callback result mutated new generation"
    );
    assert!(
        engine
            .record(pairs[0].reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    let correct = source(|id| {
        assert_eq!(id, pairs[0].commit.compute_txid());
        Ok(Some(pairs[0].raw_commit.clone()))
    });
    assert_eq!(
        engine
            .resolve_next_dependency(&correct, &cancelled)
            .unwrap(),
        1
    );
    let record = engine
        .record(pairs[0].reveal.compute_txid())
        .unwrap()
        .unwrap();
    assert_eq!(record.receipt.block, point(FIRST_HEIGHT + 1, &replacement));
}

#[test]
fn display_hex_fair_missing_only_cursor_restart_and_cached_128_reference_remainder() {
    let mut pairs = [
        profile(),
        SignedPair::load("proof-post"),
        SignedPair::load("multipart/one-root"),
    ];
    pairs.sort_by_key(|pair| pair.commit.compute_txid().to_string());
    let reveals: Vec<Transaction> = pairs.iter().map(|pair| pair.reveal.clone()).collect();
    let block = common::witness_block(&reveals, None, 20);
    let directory = tempfile::tempdir().unwrap();
    let chain = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let cfg = config(&block, Retention::Unpruned);
    let engine = open(directory.path(), &cfg, &chain);
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let initial = snapshot(directory.path());
    let requests = RefCell::new(Vec::new());
    let fetch = source(|id| {
        requests.borrow_mut().push(id);
        if id == pairs[0].commit.compute_txid() {
            Ok(None)
        } else if id == pairs[1].commit.compute_txid() {
            Err(Error::Busy("owned source failure".into()))
        } else {
            assert_eq!(id, pairs[2].commit.compute_txid());
            Ok(Some(pairs[2].raw_commit.clone()))
        }
    });
    assert_eq!(
        engine
            .resolve_next_dependency(&fetch, &AtomicBool::new(false))
            .unwrap(),
        0
    );
    assert_eq!(snapshot(directory.path()), initial);
    assert!(matches!(
        engine.resolve_next_dependency(&fetch, &AtomicBool::new(false)),
        Err(Error::Busy(_))
    ));
    assert_eq!(snapshot(directory.path()), initial);
    assert_eq!(
        engine
            .resolve_next_dependency(&fetch, &AtomicBool::new(false))
            .unwrap(),
        1
    );
    assert_eq!(
        engine
            .resolve_next_dependency(&fetch, &AtomicBool::new(false))
            .unwrap(),
        0
    );
    assert_eq!(
        *requests.borrow(),
        vec![
            pairs[0].commit.compute_txid(),
            pairs[1].commit.compute_txid(),
            pairs[2].commit.compute_txid(),
            pairs[0].commit.compute_txid()
        ]
    );
    drop(engine);
    let engine = open(directory.path(), &cfg, &chain);
    let restarted = source(|id| {
        assert_eq!(
            id,
            pairs[0].commit.compute_txid(),
            "cursor is not persisted"
        );
        Ok(None)
    });
    assert_eq!(
        engine
            .resolve_next_dependency(&restarted, &AtomicBool::new(false))
            .unwrap(),
        0
    );
    drop(engine);

    let pair = profile();
    let mut blocks: Vec<Block> = Vec::new();
    for nonce in 1..=129 {
        blocks.push(common::witness_block(
            std::slice::from_ref(&pair.reveal),
            blocks.last(),
            100 + nonce,
        ));
    }
    let directory = tempfile::tempdir().unwrap();
    let chain = Arc::new(MemorySource::new(&blocks));
    let cfg = config(&blocks[0], Retention::Unpruned);
    let engine = open(directory.path(), &cfg, &chain);
    engine.synchronize_headers().unwrap();
    for _ in &blocks {
        engine.scan_next().unwrap();
    }
    let before = engine.status().unwrap();
    let source_calls = calls(&chain);
    let requests = RefCell::new(Vec::new());
    let fetch = source(|id| {
        requests.borrow_mut().push(id);
        assert_eq!(id, pair.commit.compute_txid());
        Ok(Some(pair.raw_commit.clone()))
    });
    assert_eq!(
        engine
            .resolve_next_dependency(&fetch, &AtomicBool::new(false))
            .unwrap(),
        128
    );
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    assert_eq!(
        engine
            .resolve_next_dependency(&fetch, &AtomicBool::new(false))
            .unwrap(),
        0
    );
    assert_eq!(
        requests.borrow().len(),
        1,
        "cached remainder must not be refetched"
    );
    assert_eq!(engine.resolve_cached_dependency().unwrap(), 1);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
    assert_eq!(
        engine.status().unwrap().indexed_through,
        Some(point(FIRST_HEIGHT + 128, &blocks[128]))
    );
    assert_eq!(engine.resolve_cached_dependency().unwrap(), 0);
    selected_coverage(&engine, &before);
    assert_eq!(calls(&chain), source_calls);
    drop(engine);
    let db = readonly_archive(directory.path());
    let raw = stored_bytes(&db);
    assert_eq!(raw.len(), 2);
    assert_eq!(
        raw[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
    let parent_locators: i64 = db
        .query_row(
            "SELECT count(*) FROM locators WHERE txid=?1",
            [pair.commit.compute_txid().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(parent_locators, 0);
}

type Queries = Arc<Mutex<Vec<(String, Vec<serde_json::Value>)>>>;
struct OwnedProvider {
    chain: Chain,
    reply: Mutex<Option<Result<serde_json::Value, RuntimeError>>>,
    queries: Queries,
}
impl Provider for OwnedProvider {
    fn label(&self) -> String {
        "owned in-memory parent provider".into()
    }
    fn evidence(&self) -> Evidence {
        Evidence::PublicProviderObservation
    }
    fn block_encoding(&self) -> BlockEncoding {
        BlockEncoding::Core
    }
    fn supports(&self, method: &str) -> bool {
        matches!(method, "getblockhash" | "getrawtransaction")
    }
    fn call(
        &self,
        chain: Chain,
        method: &str,
        args: &[serde_json::Value],
    ) -> Result<serde_json::Value, RuntimeError> {
        assert_eq!(chain.genesis().unwrap().0, self.chain.genesis().unwrap().0);
        self.queries
            .lock()
            .unwrap()
            .push((method.into(), args.to_vec()));
        if method == "getblockhash" {
            assert_eq!(args, &[json!(0)]);
            return Ok(json!(chain.genesis().unwrap().0));
        }
        assert_eq!(method, "getrawtransaction");
        self.reply.lock().unwrap().take().expect("one owned fetch")
    }
}
fn owner_node(chain: Chain, reply: Result<serde_json::Value, RuntimeError>) -> (Node, Queries) {
    let queries = Arc::new(Mutex::new(Vec::new()));
    let node = Node::with_providers(
        chain,
        vec![Box::new(OwnedProvider {
            chain,
            reply: Mutex::new(Some(reply)),
            queries: queries.clone(),
        })],
    )
    .unwrap();
    assert_eq!(
        queries.lock().unwrap().as_slice(),
        &[("getblockhash".to_owned(), vec![json!(0)])]
    );
    (node, queries)
}

#[test]
fn shared_runtime_node_preserves_original_bitcoin_and_litecoin_hex_without_implicit_work() {
    let pair = profile();
    let raw_block = common::vector("litecoin-mweb/block-4892705.bin");
    let hash = "2b70f30e5c2a5e9e8510cc6a9c86339b2f7ffe618a32bc40902fd4cb842fd459"
        .parse()
        .unwrap();
    let decoded =
        decode::esplora_block_with_transactions(&raw_block, Chain::LitecoinTestnet, hash).unwrap();
    let hogex = decoded.raw_transactions().last().unwrap().clone();
    let tx = decode::transaction(&hogex, Chain::LitecoinTestnet).unwrap();
    assert_ne!(
        serialize(&tx),
        hogex,
        "public HogEx must exercise normalization loss"
    );
    for (chain, raw, id) in [
        (
            Chain::BitcoinRegtest,
            pair.raw_commit.clone(),
            pair.commit.compute_txid(),
        ),
        (Chain::LitecoinTestnet, hogex, tx.compute_txid()),
    ] {
        let (node, queries) = owner_node(chain, Ok(json!(hex::encode_upper(&raw))));
        let adapter = RuntimeCommitSource {
            node: Arc::new(node),
        };
        assert_eq!(
            adapter.chain().genesis().unwrap().0,
            chain.genesis().unwrap().0
        );
        assert_eq!(queries.lock().unwrap().len(), 1, "wrapper/chain did I/O");
        assert_eq!(
            adapter.fetch(id, &AtomicBool::new(false)).unwrap(),
            Some(raw)
        );
        assert_eq!(
            queries.lock().unwrap().as_slice(),
            &[
                ("getblockhash".to_owned(), vec![json!(0)]),
                (
                    "getrawtransaction".to_owned(),
                    vec![json!(id), json!(false)]
                )
            ]
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let (engine, _, _) = unresolved(directory.path(), &pair, Retention::Pruned);
    let initial = snapshot(directory.path());
    let (node, queries) = owner_node(
        Chain::LitecoinTestnet,
        Ok(json!(hex::encode(&pair.raw_commit))),
    );
    let adapter = RuntimeCommitSource {
        node: Arc::new(node),
    };
    assert!(matches!(
        engine.resolve_next_dependency(&adapter, &AtomicBool::new(false)),
        Err(Error::Invalid(_))
    ));
    assert_eq!(queries.lock().unwrap().len(), 1);
    assert_eq!(snapshot(directory.path()), initial);
    let (node, queries) = owner_node(
        Chain::BitcoinRegtest,
        Err(RuntimeError::Missing(
            urma_runtime::config::ABSENT_TRANSACTION.into(),
        )),
    );
    let adapter = RuntimeCommitSource {
        node: Arc::new(node),
    };
    assert!(
        adapter
            .fetch(pair.commit.compute_txid(), &AtomicBool::new(false))
            .unwrap()
            .is_none()
    );
    assert_eq!(queries.lock().unwrap().len(), 2);
    // Router may reject malformed/oversized values before the adapter sees
    // them. This checks no broad absence conversion, not transport preallocation
    // or isolated adapter-cap coverage. Raw engine cap is exercised above.
    for reply in [
        Ok(json!(null)),
        Ok(json!("zz")),
        Ok(json!("0")),
        Ok(json!("00".repeat(8_000_001))),
        Err(RuntimeError::Unsupported(
            "missing is not a typed absence".into(),
        )),
    ] {
        let (node, _) = owner_node(Chain::BitcoinRegtest, reply);
        let adapter = RuntimeCommitSource {
            node: Arc::new(node),
        };
        let error = adapter
            .fetch(pair.commit.compute_txid(), &AtomicBool::new(false))
            .unwrap_err();
        assert!(
            matches!(error, Error::CommitSource(_) | Error::Invalid(_)),
            "{error}"
        );
    }
}
