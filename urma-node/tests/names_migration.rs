//! Names schema3->5 and retained undo-floor boundaries in owned TEMP archives.
//! Schema3 construction/DDL faults occur only after Engine release. Inspections
//! use READONLY connections; these are not live writers or crash simulations.
//! Real signatures/inclusion and mock-selected integrity-valid blocks establish
//! fixture evidence, not PoW, UTXO, script or full-consensus validity.
#[allow(dead_code)]
mod common;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive, vector,
    witness_block,
};
use rusqlite::{Connection, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
    sync::Arc,
    time::Duration,
};
use urma_chain::observation::Chain;
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::{MultipartRecord, VerifiedRecord},
};
use urma_names::{name::Name, payload::Payload, state::Resolution};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, ObjectStatus, Retention},
    retrieval::recover_and_pin,
};
use urma_runtime::multipart::RecoveryLimits;

const NAMES_TABLES: [&str; 5] = [
    "names_registries",
    "names_states",
    "names_pending",
    "names_blocks",
    "names_outcomes",
];
const PEER_TABLES: [&str; 2] = ["peer_coverage", "peer_omissions"];

// Same public genesis corpus and genuine Taproot/BIP340 construction as the
// Names projection tests; no VerifiedRecord/scan mark/undo frame is fabricated.
fn signed_genesis() -> (Transaction, Transaction) {
    let bytes = vector("names/genesis-open.record");
    assert!(matches!(
        Payload::from_record(&PublicRecord::decode(&bytes).unwrap()).unwrap(),
        Payload::Genesis(_)
    ));
    let secp = Secp256k1::new();
    let signer = Keypair::from_seckey_slice(&secp, &[4; 32]).unwrap();
    let author = signer.x_only_public_key().0;
    let mut builder = Builder::new()
        .push_x_only_key(&author)
        .push_opcode(OP_CHECKSIG)
        .push_int(0)
        .push_opcode(OP_IF)
        .push_slice(Urma::MAGIC);
    for chunk in bytes.chunks(520) {
        builder = match chunk {
            [value @ 1..=16] => builder.push_int(i64::from(*value)),
            [0x81] => builder.push_int(-1),
            bytes => builder.push_slice(PushBytesBuf::try_from(bytes.to_vec()).unwrap()),
        };
    }
    let script = builder.push_opcode(OP_ENDIF).into_script();
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, author)
        .unwrap();
    let commit = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(3000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
            },
        ],
    };
    let mut reveal = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit.compute_txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1500),
            script_pubkey: ScriptBuf::from_bytes([vec![0, 20], vec![4; 20]].concat()),
        }],
    };
    let hash = SighashCache::new(&reveal)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&commit.output[1])),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &signer);
    reveal.input[0].witness = envelope::witness(signature.as_ref(), &script, &info).unwrap();
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(verified.record_bytes(), bytes);
    assert_eq!(verified.author(), author);
    (commit, reveal)
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<Value>>>,
}
fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn snapshot(directory: &Path) -> Snapshot {
    // Every caller releases Engine before this READONLY connection is opened.
    let db = readonly_archive(directory);
    let schema: Vec<(String, String, String, Option<String>)> = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables = schema
        .iter()
        .filter(|row| row.0 == "table")
        .map(|row| {
            let name = &row.1;
            let mut query = db
                .prepare(&format!(
                    "SELECT * FROM {} ORDER BY rowid",
                    identifier(name)
                ))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |r| {
                    (0..columns)
                        .map(|i| r.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            (name.clone(), rows)
        })
        .collect();
    Snapshot {
        version: db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap(),
        schema,
        tables,
    }
}
fn serialized<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}
fn empty_names(snapshot: &Snapshot) {
    for name in NAMES_TABLES {
        assert!(
            snapshot.tables[name].is_empty(),
            "unexpected backfill in {name}"
        );
    }
}
fn assert_additive(old: &Snapshot, new: &Snapshot) {
    assert_eq!(old.version, 3);
    assert_eq!(new.version, 5);
    for (table, rows) in &old.tables {
        assert_eq!(&new.tables[table], rows, "migration changed {table}");
    }
    for ddl in &old.schema {
        assert!(
            new.schema.contains(ddl),
            "migration changed old DDL {ddl:?}"
        );
    }
    let added_tables: BTreeSet<_> = new
        .tables
        .keys()
        .filter(|name| !old.tables.contains_key(*name))
        .map(String::as_str)
        .collect();
    let expected_tables: BTreeSet<_> = NAMES_TABLES.into_iter().chain(PEER_TABLES).collect();
    assert_eq!(added_tables, expected_tables);
    let added_ddl: BTreeSet<_> = new
        .schema
        .iter()
        .filter(|row| !old.schema.contains(row))
        .map(|row| row.1.as_str())
        .collect();
    assert_eq!(
        added_ddl,
        BTreeSet::from([
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
    empty_names(new);
}
struct Legacy {
    config: ArchiveConfig,
    status: ArchiveStatus,
    object: ObjectStatus,
    genesis: Txid,
    root: Txid,
}
fn legacy_schema3(directory: &Path) -> Legacy {
    let (commit, reveal) = signed_genesis();
    let genesis = reveal.compute_txid();
    let pairs: Vec<_> = ["one-root", "one-leaf", "one-part-0"]
        .map(|name| SignedPair::load(&format!("multipart/{name}")))
        .into_iter()
        .collect();
    let root = pairs[0].reveal.compute_txid();
    let name = profile();
    let mut transactions = vec![commit, reveal];
    transactions.extend(name.transactions());
    transactions.extend(pairs.iter().flat_map(SignedPair::transactions));
    let first = witness_block(&transactions, None, 9121);
    let missing = SignedPair::load("proof-post");
    let second = witness_block(&[missing.reveal], Some(&first), 9122);
    let config = config(&first, Retention::Unpruned);
    let source = Arc::new(MemorySource::new(&[first, second]));
    let engine = Engine::open(directory, config.clone(), Some(source)).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let MultipartRecord::Data(part) = pairs[2].verified.decode().unwrap() else {
        panic!("public data fixture")
    };
    let scratch = tempfile::tempdir().unwrap();
    let limits = RecoveryLimits {
        timeout: Duration::from_secs(5),
        ..RecoveryLimits::new(part.payload.len() as u64, 3)
    };
    let mut recovered = recover_and_pin(&engine, root, &[], limits, scratch.path()).unwrap();
    let mut payload = Vec::new();
    recovered.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, part.payload);
    drop(recovered);
    let object = engine.object_status(root).unwrap().unwrap();
    assert!(object.pinned);
    assert!(object.locally_complete());
    assert!(object.selected_complete());
    let status = engine.scan_next().unwrap();
    assert_eq!(status.scanned_blocks, 2);
    assert_eq!(status.unresolved_dependencies, 1);
    assert_eq!(status.indexed_through.unwrap().height, FIRST_HEIGHT);
    assert!(engine.names_status(genesis).unwrap().is_none());
    drop(engine);
    let current = snapshot(directory);
    assert_eq!(current.version, 5);
    empty_names(&current);
    // Recreate the exact predecessor layout in this disposable fixture only:
    // object schema3 identity columns and every authenticated row remain intact.
    let mut db = Connection::open(directory.join("archive.sqlite3")).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch(
        "DROP TABLE names_outcomes; DROP TABLE names_blocks; DROP TABLE names_pending;
        DROP TABLE names_states; DROP TABLE names_registries;
        DROP TABLE peer_omissions; DROP TABLE peer_coverage; PRAGMA user_version=3;",
    )
    .unwrap();
    tx.commit().unwrap();
    drop(db);
    let old = snapshot(directory);
    assert_eq!(old.version, 3);
    assert_eq!(
        old.tables.len() + NAMES_TABLES.len() + PEER_TABLES.len(),
        current.tables.len()
    );
    for (table, rows) in &old.tables {
        assert_eq!(
            rows, &current.tables[table],
            "schema3 construction changed {table}"
        );
    }
    for ddl in &old.schema {
        assert!(current.schema.contains(ddl));
    }
    assert_eq!(old.tables["objects"].len(), 1);
    assert_eq!(old.tables["object_members"].len(), 3);
    assert_eq!(old.tables["pins"].len(), 1);
    assert_eq!(old.tables["dependencies"].len(), 1);
    Legacy {
        config,
        status,
        object,
        genesis,
        root,
    }
}
fn unchanged_status(engine: &Engine, legacy: &Legacy) {
    assert_eq!(
        serialized(&engine.status().unwrap()),
        serialized(&legacy.status)
    );
    assert_eq!(
        serialized(&engine.object_status(legacy.root).unwrap().unwrap()),
        serialized(&legacy.object)
    );
}

#[test]
fn schema3_config_mismatch_refuses_before_migration_and_preserves_exact_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = legacy_schema3(directory.path());
    let before = snapshot(directory.path());
    let mut variants = Vec::new();
    let mut other = legacy.config.clone();
    other.chain = Chain::BitcoinTestnet4;
    variants.push(other);
    let mut other = legacy.config.clone();
    other.retention = Retention::Pruned;
    variants.push(other);
    let mut other = legacy.config.clone();
    other.application_start.height += 1;
    variants.push(other);
    let mut other = legacy.config.clone();
    other.application_start.hash = BlockHash::from_byte_array([42; 32]);
    variants.push(other);
    for other in variants {
        match Engine::open(directory.path(), other, None) {
            Err(Error::Invalid(message)) => assert_eq!(
                message,
                "archive configuration differs; explicit migration required"
            ),
            Err(error) => panic!("wrong refusal {error}"),
            Ok(_) => panic!("mismatched schema3 configuration accepted"),
        }
        assert_eq!(snapshot(directory.path()), before);
    }
    // Successful exact-config retry also verifies every refusal released owner.
    let engine = Engine::open(directory.path(), legacy.config.clone(), None).unwrap();
    unchanged_status(&engine, &legacy);
    drop(engine);
    assert_additive(&before, &snapshot(directory.path()));
}

#[test]
fn schema3_additive_migration_keeps_existing_evidence_and_names_empty_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = legacy_schema3(directory.path());
    let before = snapshot(directory.path());
    let engine = Engine::open(directory.path(), legacy.config.clone(), None).unwrap();
    unchanged_status(&engine, &legacy);
    // Even a fully scanned genuine local genesis does not imply registration.
    assert!(engine.record(legacy.genesis).unwrap().is_some());
    assert!(engine.names_status(legacy.genesis).unwrap().is_none());
    assert!(matches!(
        engine.names_step(legacy.genesis),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        engine.names_resolve(legacy.genesis, &Name::parse("unregistered").unwrap()),
        Err(Error::Invalid(_))
    ));
    unchanged_status(&engine, &legacy);
    drop(engine);
    let migrated = snapshot(directory.path());
    assert_additive(&before, &migrated);
    let engine = Engine::open(directory.path(), legacy.config.clone(), None).unwrap();
    unchanged_status(&engine, &legacy);
    assert!(engine.names_status(legacy.genesis).unwrap().is_none());
    drop(engine);
    assert_eq!(snapshot(directory.path()), migrated);
}

#[test]
fn schema3_mid_ddl_collision_rolls_back_every_staged_names_table_then_retries() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = legacy_schema3(directory.path());
    let db = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
    // The last CREATE collides after four tables have been staged. This ordinary
    // TEMP table/sentinel is a DDL error control, not a corruption/power-loss test.
    db.execute_batch(
        "CREATE TABLE names_outcomes(id INTEGER PRIMARY KEY,note TEXT NOT NULL);
        INSERT INTO names_outcomes VALUES(1,'owned late DDL collision');",
    )
    .unwrap();
    drop(db);
    let before = snapshot(directory.path());
    for _ in 0..2 {
        match Engine::open(directory.path(), legacy.config.clone(), None) {
            Err(Error::Database(error)) => assert!(error.to_string().contains("names_outcomes")),
            Err(error) => panic!("wrong DDL failure {error}"),
            Ok(_) => panic!("colliding schema3 migration succeeded"),
        }
        let after = snapshot(directory.path());
        assert_eq!(after, before);
        for name in &NAMES_TABLES[..4] {
            assert!(!after.tables.contains_key(*name));
        }
    }
    let db = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE names_outcomes;").unwrap();
    drop(db);
    let clean = snapshot(directory.path());
    let engine = Engine::open(directory.path(), legacy.config.clone(), None).unwrap();
    unchanged_status(&engine, &legacy);
    drop(engine);
    assert_additive(&clean, &snapshot(directory.path()));
}

fn clone_closed_archive(from: &Path, to: &Path) {
    // After the final Engine/SQLite handle closes, WAL has been checkpointed.
    // Copy only a complete, quiescent DB; never discard outstanding WAL bytes.
    let wal = from.join("archive.sqlite3-wal");
    match fs::metadata(&wal) {
        Ok(meta) => assert_eq!(meta.len(), 0, "closed seed retained outstanding WAL bytes"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => panic!("cannot inspect closed seed WAL: {error}"),
    }
    fs::create_dir_all(to).unwrap();
    fs::copy(from.join("archive.sqlite3"), to.join("archive.sqlite3")).unwrap();
    assert_eq!(snapshot(from), snapshot(to));
}
fn fork(original: &[Block], common: usize, nonce: u32) -> Vec<Block> {
    let mut branch = original[..=common].to_vec();
    while branch.len() < original.len() {
        branch.push(witness_block(
            &[],
            branch.last(),
            nonce + branch.len() as u32,
        ));
    }
    assert_eq!(branch.len(), original.len());
    branch
}
fn names_busy_without_progress(
    directory: &Path,
    cfg: &ArchiveConfig,
    genesis: Txid,
    before: &Snapshot,
    status: &ArchiveStatus,
) {
    for _ in 0..2 {
        let engine = Engine::open(directory, cfg.clone(), None).unwrap();
        assert_eq!(serialized(&engine.status().unwrap()), serialized(status));
        assert!(matches!(engine.names_status(genesis), Err(Error::Stale)));
        assert!(matches!(
            engine.names_resolve(genesis, &Name::parse("absent").unwrap()),
            Err(Error::Stale)
        ));
        for _ in 0..2 {
            match engine.names_step(genesis) {
                Err(Error::Busy(message)) => assert!(
                    message.contains("retained undo") && message.contains("explicit rebuild")
                ),
                Err(error) => panic!("wrong deep reorg refusal {error}"),
                Ok(_) => panic!("deep reorg crossed retained undo floor"),
            }
            assert_eq!(serialized(&engine.status().unwrap()), serialized(status));
            assert!(matches!(engine.names_status(genesis), Err(Error::Stale)));
        }
        drop(engine);
        assert_eq!(
            &snapshot(directory),
            before,
            "failed Names step partially mutated SQL/evidence/events"
        );
    }
}

#[test]
fn exactly_1000_undos_survive_reopen_but_floor_cannot_restore_a_1001st_undo() {
    let seed = tempfile::tempdir().unwrap();
    let exact = tempfile::tempdir().unwrap();
    let deep = tempfile::tempdir().unwrap();
    let (commit, reveal) = signed_genesis();
    let genesis = reveal.compute_txid();
    let first = witness_block(&[commit, reveal], None, 9201);
    let mut original = vec![first.clone()];
    while original.len() < 1002 {
        original.push(witness_block(
            &[],
            original.last(),
            9300 + original.len() as u32,
        ));
    }
    let cfg = config(&first, Retention::Unpruned);
    let source = Arc::new(MemorySource::new(&original));
    let engine = Engine::open(seed.path(), cfg.clone(), Some(source)).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let initial = engine
        .register_names(genesis, point(FIRST_HEIGHT, &first))
        .unwrap();
    assert_eq!(initial.projected.height, FIRST_HEIGHT);
    for (i, block) in original.iter().enumerate().skip(1) {
        engine.scan_next().unwrap();
        let step = engine.names_step(genesis).unwrap();
        assert_eq!(step.applied, Some(point(FIRST_HEIGHT + i as u64, block)));
        assert_eq!(step.rolled_back, 0);
        assert!(step.outcomes.is_empty());
    }
    let projected = engine.names_status(genesis).unwrap().unwrap();
    assert_eq!(projected.projected.height, FIRST_HEIGHT + 1001);
    assert!(projected.complete_to_tip);
    assert_eq!(
        engine
            .names_resolve(genesis, &Name::parse("absent").unwrap())
            .unwrap()
            .resolution,
        Resolution::Unbound
    );
    drop(engine);
    let db = readonly_archive(seed.path());
    let (count, minimum, maximum, frames): (i64, i64, i64, i64) = db
        .query_row(
            "SELECT count(*),min(height),max(height),count(delta) FROM names_blocks",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((count, minimum, maximum, frames), (1001, 101, 1101, 1000));
    let floor: Option<Vec<u8>> = db
        .query_row("SELECT delta FROM names_blocks WHERE height=101", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        floor.is_none(),
        "floor is a checkpoint, not an extra reversible frame"
    );
    drop(db);
    clone_closed_archive(seed.path(), exact.path());
    clone_closed_archive(seed.path(), deep.path());

    // Both scenarios cold-load the same genuine seed through public Engine APIs.
    let exact_source = Arc::new(MemorySource::new(&original));
    let engine = Engine::open(exact.path(), cfg.clone(), Some(exact_source.clone())).unwrap();
    assert_eq!(
        serialized(&engine.names_status(genesis).unwrap().unwrap()),
        serialized(&projected)
    );
    exact_source.replace_branch(&fork(&original, 1, 12000));
    engine.synchronize_headers().unwrap();
    assert!(matches!(engine.names_status(genesis), Err(Error::Stale)));
    let status = engine.status().unwrap();
    let step = engine.names_step(genesis).unwrap();
    assert_eq!(step.rolled_back, 1000);
    assert!(step.applied.is_none());
    assert!(step.outcomes.is_empty());
    assert_eq!(step.status.projected, point(FIRST_HEIGHT + 1, &original[1]));
    assert!(!step.status.complete_to_tip);
    assert_eq!(serialized(&engine.status().unwrap()), serialized(&status));
    drop(engine);
    let at_floor = snapshot(exact.path());
    assert_eq!(at_floor.tables["names_blocks"].len(), 1);
    assert_eq!(at_floor.tables["names_blocks"][0][3], Value::Null);

    // Reopen after the successful rollback. A persisted floor delta must never
    // resurrect one more undo than the in-memory registry retained.
    let engine = Engine::open(exact.path(), cfg.clone(), Some(exact_source.clone())).unwrap();
    assert_eq!(
        engine.names_status(genesis).unwrap().unwrap().projected,
        point(FIRST_HEIGHT + 1, &original[1])
    );
    assert_eq!(
        engine
            .names_resolve(genesis, &Name::parse("absent").unwrap())
            .unwrap()
            .resolution,
        Resolution::Unbound
    );
    exact_source.replace_branch(&fork(&original, 0, 14000));
    engine.synchronize_headers().unwrap();
    let status = engine.status().unwrap();
    drop(engine);
    let before = snapshot(exact.path());
    names_busy_without_progress(exact.path(), &cfg, genesis, &before, &status);

    let deep_source = Arc::new(MemorySource::new(&original));
    let engine = Engine::open(deep.path(), cfg.clone(), Some(deep_source.clone())).unwrap();
    deep_source.replace_branch(&fork(&original, 0, 16000));
    engine.synchronize_headers().unwrap();
    let status = engine.status().unwrap();
    drop(engine);
    let before = snapshot(deep.path());
    names_busy_without_progress(deep.path(), &cfg, genesis, &before, &status);
}
