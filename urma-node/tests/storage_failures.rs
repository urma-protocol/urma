//! SQLite statement-abort rollback tests in disposable archives only.
//! A second connection injects faults; it is not a supported production writer.
//! These tests do not simulate a process crash or power loss, or validate PoW.

use bitcoin::{
    Amount, Block, BlockHash, Network, ScriptBuf, Transaction, Witness,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use rusqlite::{Connection, types::Value};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};
use tempfile::TempDir;
use urma_chain::{observation::Chain, validation::validate_block_integrity};
use urma_core::multipart::VerifiedRecord;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, ChainPoint, Retention},
    source::ChainSource,
};

const START: u64 = 100;
const SCAN_ABORT: &str = "u4 scan abort after staged evidence";
const SELECT_ABORT: &str = "u4 selected abort after staged prefix";

fn signed_block() -> Block {
    // Independently signed, valid fixtures named in tests/vectors/manifest.json.
    // Keep their transactions unchanged so Taproot/BIP340 verification is real.
    let commit: Transaction =
        deserialize(include_bytes!("../../tests/vectors/proof-profile.commit")).unwrap();
    let reveal: Transaction =
        deserialize(include_bytes!("../../tests/vectors/proof-profile.reveal")).unwrap();
    let missing_commit: Transaction =
        deserialize(include_bytes!("../../tests/vectors/proof-post.commit")).unwrap();
    let unresolved_reveal: Transaction =
        deserialize(include_bytes!("../../tests/vectors/proof-post.reveal")).unwrap();
    VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    VerifiedRecord::verify(
        unresolved_reveal.compute_txid(),
        &unresolved_reveal,
        &missing_commit,
    )
    .unwrap();
    assert_ne!(commit.compute_txid(), missing_commit.compute_txid());

    let mut block = genesis_block(Network::Regtest);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    // One retained record and one unresolved dependency exercise both tables.
    block.txdata.extend([commit, reveal, unresolved_reveal]);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

struct MockSource {
    headers: RwLock<Vec<Header>>,
    block: Block,
}

impl MockSource {
    fn new(block: Block) -> Self {
        Self {
            headers: RwLock::new(vec![block.header]),
            block,
        }
    }

    fn select(&self, headers: Vec<Header>) {
        assert_eq!(headers[0], self.block.header);
        for pair in headers.windows(2) {
            assert_eq!(pair[1].prev_blockhash, pair[0].block_hash());
        }
        *self.headers.write().unwrap() = headers;
    }
}

impl ChainSource for MockSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(Chain::BitcoinRegtest.genesis().unwrap().0)
    }

    fn tip(&self) -> Result<ChainPoint, Error> {
        let headers = self.headers.read().unwrap();
        Ok(ChainPoint {
            height: START + headers.len() as u64 - 1,
            hash: headers.last().unwrap().block_hash(),
        })
    }

    fn header(&self, height: u64) -> Result<Header, Error> {
        let index = height
            .checked_sub(START)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| Error::Invalid("mock header below start".into()))?;
        self.headers
            .read()
            .unwrap()
            .get(index)
            .copied()
            .ok_or_else(|| Error::Invalid("mock header absent".into()))
    }

    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        if height != START {
            return Err(Error::Invalid("unexpected mock block request".into()));
        }
        Ok(serialize(&self.block))
    }
}

fn config(block: &Block) -> ArchiveConfig {
    ArchiveConfig {
        chain: Chain::BitcoinRegtest,
        application_start: ChainPoint {
            height: START,
            hash: block.block_hash(),
        },
        retention: Retention::Unpruned,
    }
}

fn child(parent: Header, nonce: u32) -> Header {
    Header {
        prev_blockhash: parent.block_hash(),
        time: parent.time + 1,
        nonce,
        ..parent
    }
}

fn fault_connection(directory: &Path) -> Connection {
    // The caller supplies a fresh TempDir; never point this at a real archive.
    Connection::open(directory.join("archive.sqlite3")).unwrap()
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    user_version: i64,
    tables: Vec<(&'static str, Vec<Vec<Value>>)>,
}

fn snapshot(db: &Connection) -> Snapshot {
    let tables = [
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
    .collect();
    Snapshot {
        user_version: db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap(),
        tables,
    }
}

fn assert_status_eq(actual: ArchiveStatus, expected: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn assert_injected_abort(error: Error, message: &str) {
    match error {
        Error::Database(rusqlite::Error::SqliteFailure(code, detail)) => {
            assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
            assert_eq!(detail.as_deref(), Some(message));
        }
        other => panic!("expected injected SQLite trigger abort, got {other:?}"),
    }
}

#[test]
fn scan_insert_abort_rolls_back_all_evidence_and_survives_reopen() {
    let directory = TempDir::new().unwrap();
    let block = signed_block();
    let config = config(&block);
    let source = Arc::new(MockSource::new(block));
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    let before = engine.synchronize_headers().unwrap();
    assert_eq!(before.selected_tip, Some(config.application_start));
    assert_eq!(before.scanned_blocks, 0);
    let db = fault_connection(directory.path());
    let original = snapshot(&db);
    // The distinct failure message proves that records, raw transactions,
    // locators and a dependency were staged before the fault was reached.
    db.execute_batch(
        "CREATE TRIGGER scan_insert_abort BEFORE INSERT ON scans BEGIN
        SELECT CASE WHEN
            (SELECT count(*) FROM records)=1 AND
            (SELECT count(*) FROM transactions)=2 AND
            (SELECT count(*) FROM locators)=4 AND
            (SELECT count(*) FROM dependencies)=1
        THEN RAISE(ABORT, 'u4 scan abort after staged evidence')
        ELSE RAISE(ABORT, 'u4 fixture did not stage expected scan evidence') END;
        END;",
    )
    .unwrap();

    assert_injected_abort(engine.scan_next().unwrap_err(), SCAN_ABORT);
    assert_status_eq(engine.status().unwrap(), &before);
    assert_eq!(snapshot(&db), original);
    for table in [
        "records",
        "transactions",
        "locators",
        "dependencies",
        "scans",
    ] {
        assert_eq!(count(&db, table), 0, "{table} leaked across abort");
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM events WHERE kind='scan'", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    drop(db);
    drop(engine);

    let engine = Engine::open(directory.path(), config, Some(source)).unwrap();
    assert_status_eq(engine.status().unwrap(), &before);
    let db = fault_connection(directory.path());
    assert_eq!(snapshot(&db), original);
    db.execute_batch("DROP TRIGGER scan_insert_abort;").unwrap();
    // Positive control: the same block reaches commit once the fault is removed.
    let after = engine.scan_next().unwrap();
    assert_eq!(after.selected_tip, before.selected_tip);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.scanned_blocks, 1);
    assert_eq!(after.unresolved_dependencies, 1);
    assert_eq!(after.stored_transactions, 2);
    assert_eq!(after.indexed_through, None);
    for (table, expected) in [
        ("records", 1),
        ("transactions", 2),
        ("locators", 4),
        ("dependencies", 1),
        ("scans", 1),
    ] {
        assert_eq!(count(&db, table), expected, "{table} positive control");
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM events WHERE kind='scan'", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}

fn selected_insert_abort(reorg: bool) {
    let directory = TempDir::new().unwrap();
    let block = signed_block();
    let anchor = block.header;
    let config = config(&block);
    let source = Arc::new(MockSource::new(block));
    if reorg {
        let first = child(anchor, 11);
        source.select(vec![anchor, first, child(first, 12)]);
    }
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    let before = engine.synchronize_headers().unwrap();
    let db = fault_connection(directory.path());
    let original = snapshot(&db);
    let first = child(anchor, 21);
    let second = child(first, 22);
    source.select(vec![anchor, first, second]);
    // Abort the second INSERT, after the first new header has been selected.
    // For reorg, also prove the generation and reorg event were staged first.
    let staged_generation = i64::from(reorg);
    db.execute_batch(&format!(
        "CREATE TRIGGER selected_insert_abort BEFORE INSERT ON selected
        WHEN NEW.height=102 BEGIN
        SELECT CASE WHEN
            EXISTS(SELECT 1 FROM selected WHERE height=101 AND hash='{}') AND
            (SELECT generation FROM state WHERE singleton=1)={} AND
            (SELECT count(*) FROM events WHERE kind='reorg')={}
        THEN RAISE(ABORT, 'u4 selected abort after staged prefix')
        ELSE RAISE(ABORT, 'u4 fixture did not stage expected selected prefix') END;
        END;",
        first.block_hash(),
        staged_generation,
        staged_generation
    ))
    .unwrap();

    assert_injected_abort(engine.synchronize_headers().unwrap_err(), SELECT_ABORT);
    assert_status_eq(engine.status().unwrap(), &before);
    assert_eq!(snapshot(&db), original);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM headers WHERE hash IN (?1,?2)",
            [
                first.block_hash().to_string(),
                second.block_hash().to_string()
            ],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    drop(db);
    drop(engine);

    let engine = Engine::open(directory.path(), config, Some(source)).unwrap();
    assert_status_eq(engine.status().unwrap(), &before);
    let db = fault_connection(directory.path());
    assert_eq!(snapshot(&db), original);
    db.execute_batch("DROP TRIGGER selected_insert_abort;")
        .unwrap();
    let after = engine.synchronize_headers().unwrap();
    assert_eq!(
        after.selected_tip,
        Some(ChainPoint {
            height: START + 2,
            hash: second.block_hash()
        })
    );
    assert_eq!(after.generation, before.generation + u64::from(reorg));
    assert_eq!(count(&db, "selected"), 3);
    assert_eq!(count(&db, "events"), 2 + i64::from(reorg));
}

#[test]
fn extension_second_insert_abort_leaves_no_new_prefix_or_event() {
    selected_insert_abort(false);
}

#[test]
fn reorg_second_insert_abort_restores_old_selection_generation_and_events() {
    selected_insert_abort(true);
}

#[test]
fn configuration_mismatch_refuses_without_resetting_populated_archive() {
    let directory = TempDir::new().unwrap();
    let block = signed_block();
    let config = config(&block);
    let source = Arc::new(MockSource::new(block));
    let engine = Engine::open(directory.path(), config.clone(), Some(source)).unwrap();
    engine.synchronize_headers().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.stored_transactions, 2);
    assert_eq!(before.scanned_blocks, 1);
    let db = fault_connection(directory.path());
    let original = snapshot(&db);
    drop(db);
    drop(engine);

    let mut different_configs = Vec::new();
    let mut different = config.clone();
    different.retention = Retention::Pruned;
    different_configs.push(different);
    let mut different = config.clone();
    different.application_start.height += 1;
    different_configs.push(different);
    let mut different = config.clone();
    different.application_start.hash = BlockHash::from_byte_array([42; 32]);
    different_configs.push(different);
    let mut different = config.clone();
    different.chain = Chain::BitcoinTestnet4;
    different_configs.push(different);
    for different in different_configs {
        match Engine::open(directory.path(), different, None) {
            Err(Error::Invalid(message)) => assert_eq!(
                message,
                "archive configuration differs; explicit migration required"
            ),
            Err(other) => panic!("wrong configuration rejection: {other:?}"),
            Ok(_) => panic!("configuration mismatch accepted"),
        }
        let db = fault_connection(directory.path());
        assert_eq!(snapshot(&db), original);
        drop(db);
        // The failed open also releases ownership; the original config reopens.
        let engine = Engine::open(directory.path(), config.clone(), None).unwrap();
        assert_status_eq(engine.status().unwrap(), &before);
    }
}
