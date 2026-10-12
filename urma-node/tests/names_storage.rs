//! Names storage through public Engine APIs, with disposable SQLite inspection.
//! Real Taproot signatures follow urma-names/tests/projection.rs::Proof::signed.
//! The mock selects headers: these blocks do not assert PoW, scripts/UTXO
//! consensus, or validity of duplicate-TXID placements on a consensus chain.
//! Statement ABORT checks transaction rollback, not crash/power-loss durability.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, XOnlyPublicKey, absolute,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::serialize,
    hashes::{Hash, sha256},
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use rusqlite::{Connection, OpenFlags, params, types::Value};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use urma_chain::{observation::Chain, validation::validate_block_integrity};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{
    payload::{Approval, Genesis, OwnerOp, Payload},
    state::{Outcome, PendingKind, PendingRecord, Resolution, Target, Verdict},
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    names::NamesStep,
    source::ChainSource,
};

const START: u64 = 100;
const ABORT: &str = "u4 Names abort after rollback delta outcomes checkpoint event";

struct Signed {
    commit: Transaction,
    reveal: Transaction,
    bytes: Vec<u8>,
    author: XOnlyPublicKey,
}

impl Signed {
    fn new(bytes: Vec<u8>, secret: [u8; 32]) -> Self {
        let secp = Secp256k1::new();
        let signer = Keypair::from_seckey_slice(&secp, &secret).unwrap();
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
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(3_000),
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
                value: Amount::from_sat(1_500),
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
        Self {
            commit,
            reveal,
            bytes,
            author,
        }
    }

    fn id(&self) -> Txid {
        self.reveal.compute_txid()
    }
}

fn scalar(value: u8) -> [u8; 32] {
    let mut secret = [0; 32];
    secret[31] = value;
    secret
}

struct Fixture {
    genesis: Signed,
    claim: Signed,
    approvals: [Signed; 3],
    rules: Genesis,
    op: OwnerOp,
    blocks: Vec<Block>,
}

impl Fixture {
    fn new() -> Self {
        // Public CC0 payload corpus, not downloaded fixtures or invented proofs.
        let genesis_bytes = include_bytes!("../../tests/vectors/names/genesis-administered.record");
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(genesis_bytes).unwrap()).unwrap()
        else {
            panic!("genesis vector")
        };
        let genesis = Signed::new(genesis_bytes.to_vec(), [4; 32]);
        let Payload::Claim(mut op) = Payload::from_record(
            &PublicRecord::decode(include_bytes!("../../tests/vectors/names/claim.record"))
                .unwrap(),
        )
        .unwrap() else {
            panic!("claim vector")
        };
        op.registry = genesis.id();
        let claim = Signed::new(
            Payload::Claim(op.clone())
                .to_record()
                .unwrap()
                .encode()
                .unwrap(),
            [5; 32],
        );
        let approval = Payload::Approve(Approval {
            registry: genesis.id(),
            record_txid: claim.id(),
            record_sha256: sha256::Hash::hash(&claim.bytes).to_byte_array(),
        })
        .to_record()
        .unwrap()
        .encode()
        .unwrap();
        let approvals = [11, 12, 13].map(|key| Signed::new(approval.clone(), scalar(key)));
        for signed in &approvals {
            assert!(rules.is_approver(&signed.author));
        }
        assert_eq!(rules.threshold, 2);
        assert_eq!(rules.reveal_max_blocks, 144);
        let bodies = vec![
            vec![genesis.commit.clone()],
            vec![genesis.reveal.clone()],
            vec![claim.commit.clone()],
            vec![claim.reveal.clone()],
            vec![approvals[0].commit.clone()],
            vec![approvals[0].reveal.clone()],
            vec![approvals[1].commit.clone(), approvals[2].commit.clone()],
            vec![approvals[1].reveal.clone()],
        ];
        let blocks = branch(bodies, 0);
        Self {
            genesis,
            claim,
            approvals,
            rules,
            op,
            blocks,
        }
    }

    fn config(&self) -> ArchiveConfig {
        config(&self.blocks[0])
    }
    fn point(&self, height: u64) -> ChainPoint {
        point(height, &self.blocks[(height - START) as usize])
    }
    fn bound(&self, engine: &Engine, approval: usize, height: u64) {
        let resolution = engine
            .names_resolve(self.genesis.id(), &self.op.name)
            .unwrap();
        let Resolution::Bound(bound) = resolution.resolution else {
            panic!("expected binding")
        };
        assert_eq!(bound.owner, self.claim.author);
        assert_eq!(bound.target, Target::Publication(self.op.target));
        assert_eq!(bound.claim_txid, self.claim.id());
        assert_eq!(bound.last_txid, self.approvals[approval].id());
        assert_eq!(bound.expiry, height + u64::from(self.rules.expiry_blocks));
    }

    fn unbound(&self, engine: &Engine) {
        assert_eq!(
            engine
                .names_resolve(self.genesis.id(), &self.op.name)
                .unwrap()
                .resolution,
            Resolution::Unbound
        );
    }
}

fn block(txs: &[Transaction], previous: Option<&Block>, height: u64, salt: u32) -> Block {
    let mut block = genesis_block(Network::Regtest);
    if let Some(parent) = previous {
        block.header.prev_blockhash = parent.block_hash();
    }
    block.header.time = 1_700_000_000 + height as u32;
    block.header.nonce = height as u32 + salt;
    block.header.bits = CompactTarget::from_consensus(0);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    block.txdata.extend_from_slice(txs);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

fn branch(bodies: Vec<Vec<Transaction>>, salt: u32) -> Vec<Block> {
    let mut blocks = Vec::new();
    for (i, txs) in bodies.iter().enumerate() {
        blocks.push(block(txs, blocks.last(), START + i as u64, salt));
    }
    blocks
}

fn fork(original: &[Block], first: u64, bodies: Vec<Vec<Transaction>>, salt: u32) -> Vec<Block> {
    let mut blocks = original[..(first - START) as usize].to_vec();
    for (i, txs) in bodies.iter().enumerate() {
        blocks.push(block(txs, blocks.last(), first + i as u64, salt));
    }
    assert_eq!(blocks.len(), original.len());
    blocks
}

fn point(height: u64, block: &Block) -> ChainPoint {
    ChainPoint {
        height,
        hash: block.block_hash(),
    }
}
fn config(block: &Block) -> ArchiveConfig {
    ArchiveConfig {
        chain: Chain::BitcoinRegtest,
        application_start: point(START, block),
        retention: Retention::Pruned,
    }
}

struct Source(Mutex<Vec<Block>>);
impl Source {
    fn new(blocks: &[Block]) -> Self {
        Self(Mutex::new(blocks.to_vec()))
    }
    fn select(&self, blocks: &[Block]) {
        let mut old = self.0.lock().unwrap();
        assert_eq!(blocks[0].block_hash(), old[0].block_hash());
        assert_eq!(blocks.len(), old.len());
        for pair in blocks.windows(2) {
            assert_eq!(pair[1].header.prev_blockhash, pair[0].block_hash());
        }
        *old = blocks.to_vec();
    }
    fn at(&self, height: u64) -> Result<Block, Error> {
        let index = height
            .checked_sub(START)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| Error::Invalid("mock height below start".into()))?;
        self.0
            .lock()
            .unwrap()
            .get(index)
            .cloned()
            .ok_or_else(|| Error::Invalid("mock block absent".into()))
    }
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(Chain::BitcoinRegtest.genesis().unwrap().0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        let blocks = self.0.lock().unwrap();
        Ok(point(
            START + blocks.len() as u64 - 1,
            blocks.last().unwrap(),
        ))
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        Ok(self.at(height)?.header)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        Ok(serialize(&self.at(height)?))
    }
}

fn open(directory: &TempDir, blocks: &[Block]) -> (Engine, Arc<Source>) {
    let source = Arc::new(Source::new(blocks));
    let engine = Engine::open(directory.path(), config(&blocks[0]), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    (engine, source)
}

fn scan_to(engine: &Engine, height: u64) {
    let count = height - START + 1;
    for _ in 0..count {
        let before = engine.status().unwrap().scanned_blocks;
        if before == count {
            return;
        }
        assert!(before < count);
        assert_eq!(engine.scan_next().unwrap().scanned_blocks, before + 1);
    }
    assert_eq!(engine.status().unwrap().scanned_blocks, count);
}

fn json(value: impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn readonly(directory: &TempDir) -> Connection {
    Connection::open_with_flags(
        directory.path().join("archive.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<Vec<Value>>,
    rows: Vec<(String, Vec<Vec<Value>>)>,
}

fn rows(db: &Connection, query: &str) -> Vec<Vec<Value>> {
    let mut stmt = db.prepare(query).unwrap();
    let columns = stmt.column_count();
    stmt.query_map([], |row| {
        (0..columns)
            .map(|i| row.get(i))
            .collect::<rusqlite::Result<Vec<Value>>>()
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

fn snapshot(directory: &TempDir) -> Snapshot {
    // Only inspect this owned TEMP archive between completed public API calls.
    let db = readonly(directory);
    let schema = rows(
        &db,
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
    );
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let rows = tables
        .into_iter()
        .map(|table| {
            let escaped = table.replace('"', "\"\"");
            let data = rows(&db, &format!("SELECT * FROM \"{escaped}\" ORDER BY rowid"));
            (table, data)
        })
        .collect();
    Snapshot {
        version: db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap(),
        schema,
        rows,
    }
}

fn no_write<T: std::fmt::Debug>(
    directory: &TempDir,
    call: impl FnOnce() -> Result<T, Error>,
    kind: &str,
) {
    let before = snapshot(directory);
    let error = call().unwrap_err();
    assert!(
        match kind {
            "Busy" => matches!(error, Error::Busy(_)),
            "Stale" => matches!(error, Error::Stale),
            "Invalid" => matches!(error, Error::Invalid(_)),
            _ => panic!("unknown error oracle"),
        },
        "expected {kind}, got {error:?}"
    );
    assert_eq!(snapshot(directory), before);
}

fn step(
    engine: &Engine,
    fixture: &Fixture,
    expected: ChainPoint,
    verdict: Option<(Txid, Verdict)>,
    rolled_back: u64,
) -> NamesStep {
    let archive_before = json(engine.status().unwrap());
    let result = engine.names_step(fixture.genesis.id()).unwrap();
    assert_eq!(result.applied, Some(expected));
    assert_eq!(result.rolled_back, rolled_back);
    assert_eq!(result.status.projected, expected);
    assert_eq!(result.status.genesis, fixture.genesis.id());
    assert_eq!(result.status.genesis_block.height, 101);
    assert_eq!(
        result.status.genesis_block,
        engine
            .record(fixture.genesis.id())
            .unwrap()
            .unwrap()
            .package
            .block
    );
    let status = engine.status().unwrap();
    assert_eq!(json(&status), archive_before);
    assert_eq!(result.status.generation, status.generation);
    assert_eq!(result.status.selected_tip, status.selected_tip);
    assert_eq!(
        result.status.complete_to_tip,
        status.selected_tip == Some(expected)
    );
    let outcomes = verdict
        .into_iter()
        .map(|(txid, verdict)| Outcome {
            txid,
            position: 1,
            verdict,
        })
        .collect::<Vec<_>>();
    assert_eq!(result.outcomes, outcomes);
    result
}

fn pending(directory: &TempDir, fixture: &Fixture) -> PendingRecord {
    let bytes: Vec<u8> = readonly(directory)
        .query_row(
            "SELECT state FROM names_pending WHERE registry=?1 AND txid=?2",
            params![
                fixture.genesis.id().to_string(),
                fixture.claim.id().to_string()
            ],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn assert_pending(
    directory: &TempDir,
    fixture: &Fixture,
    height: u64,
    approvers: &[usize],
    completed: bool,
) {
    let p = pending(directory, fixture);
    assert_eq!(p.kind, PendingKind::Request);
    assert_eq!(p.name, fixture.op.name);
    assert_eq!(p.author, fixture.claim.author);
    assert_eq!(p.target, fixture.op.target);
    assert_eq!(
        p.sha256,
        sha256::Hash::hash(&fixture.claim.bytes).to_byte_array()
    );
    assert_eq!(p.height, height);
    assert_eq!(
        p.approvals,
        approvers
            .iter()
            .map(|i| fixture.approvals[*i].author)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(p.completed, completed);
}

fn project_all(engine: &Engine, fixture: &Fixture) {
    engine
        .register_names(fixture.genesis.id(), fixture.point(101))
        .unwrap();
    for height in 102..=107 {
        let verdict = match height {
            103 => Some((fixture.claim.id(), Verdict::Pending)),
            105 => Some((fixture.approvals[0].id(), Verdict::Applied)),
            107 => Some((fixture.approvals[1].id(), Verdict::Applied)),
            _ => None,
        };
        step(engine, fixture, fixture.point(height), verdict, 0);
    }
}

fn assert_raw(engine: &Engine, signed: &Signed) {
    let record = engine.record(signed.id()).unwrap().unwrap();
    assert_eq!(record.package.reveal.transaction, serialize(&signed.reveal));
    assert_eq!(record.package.commit, serialize(&signed.commit));
}

#[test]
fn registration_admin_lifecycle_prune_and_restart_preserve_evidence() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (engine, _) = open(&directory, &fixture.blocks);
    let unknown = Txid::from_byte_array([99; 32]);
    assert!(engine.names_status(unknown).unwrap().is_none());
    no_write(
        &directory,
        || engine.names_resolve(unknown, &fixture.op.name),
        "Invalid",
    );
    no_write(
        &directory,
        || engine.register_names(fixture.genesis.id(), fixture.point(101)),
        "Busy",
    );
    scan_to(&engine, 107);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
    no_write(
        &directory,
        || engine.register_names(unknown, fixture.point(101)),
        "Invalid",
    );
    no_write(
        &directory,
        || engine.register_names(fixture.claim.id(), fixture.point(103)),
        "Invalid",
    );
    let registered = engine
        .register_names(fixture.genesis.id(), fixture.point(101))
        .unwrap();
    assert_eq!(registered.projected, fixture.point(101));
    assert!(!registered.complete_to_tip);
    let before = snapshot(&directory);
    assert_eq!(
        json(
            engine
                .register_names(fixture.genesis.id(), fixture.point(101))
                .unwrap()
        ),
        json(&registered)
    );
    assert_eq!(snapshot(&directory), before);
    no_write(
        &directory,
        || engine.register_names(fixture.genesis.id(), fixture.point(102)),
        "Stale",
    );
    no_write(
        &directory,
        || {
            engine.register_names(
                fixture.genesis.id(),
                ChainPoint {
                    height: 101,
                    hash: BlockHash::all_zeros(),
                },
            )
        },
        "Stale",
    );
    for height in 102..=107 {
        let verdict = match height {
            103 => Some((fixture.claim.id(), Verdict::Pending)),
            105 => Some((fixture.approvals[0].id(), Verdict::Applied)),
            107 => Some((fixture.approvals[1].id(), Verdict::Applied)),
            _ => None,
        };
        step(&engine, &fixture, fixture.point(height), verdict, 0);
        if height < 107 {
            fixture.unbound(&engine);
        }
        if height == 103 {
            assert_pending(&directory, &fixture, 103, &[], false);
        }
        if height == 105 {
            assert_pending(&directory, &fixture, 103, &[0], false);
        }
    }
    fixture.bound(&engine, 1, 107);
    assert_pending(&directory, &fixture, 103, &[0, 1], true);
    let db = readonly(&directory);
    let rules: Vec<u8> = db
        .query_row("SELECT rules FROM names_registries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Genesis>(&rules).unwrap(),
        fixture.rules
    );
    let names: Vec<String> = db
        .prepare("SELECT name FROM names_states")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(names, vec![fixture.op.name.as_str().to_string()]);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM names_blocks WHERE delta IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        6
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM names_outcomes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    drop(db);
    let before = snapshot(&directory);
    let idle = engine.names_step(fixture.genesis.id()).unwrap();
    assert!(idle.applied.is_none());
    assert_eq!(idle.rolled_back, 0);
    assert!(idle.outcomes.is_empty());
    assert_eq!(snapshot(&directory), before);
    // Profiles are not evictable multipart children. This does not claim child
    // deletion coverage; it proves explicit prune retains Names state/raw data.
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_eq!(snapshot(&directory), before);
    for signed in [
        &fixture.genesis,
        &fixture.claim,
        &fixture.approvals[0],
        &fixture.approvals[1],
    ] {
        assert_raw(&engine, signed);
    }
    let resolution = json(
        engine
            .names_resolve(fixture.genesis.id(), &fixture.op.name)
            .unwrap(),
    );
    let status = json(engine.status().unwrap());
    drop(engine);
    let reopened = Engine::open(directory.path(), fixture.config(), None).unwrap();
    assert_eq!(json(reopened.status().unwrap()), status);
    assert_eq!(
        json(
            reopened
                .names_resolve(fixture.genesis.id(), &fixture.op.name)
                .unwrap()
        ),
        resolution
    );
    assert_eq!(snapshot(&directory), before);
    for signed in [
        &fixture.genesis,
        &fixture.claim,
        &fixture.approvals[0],
        &fixture.approvals[1],
    ] {
        assert_raw(&reopened, signed);
    }
}

#[test]
fn coverage_and_selected_commit_placement_are_separate_requirements() {
    let fixture = Fixture::new();
    let blocks = branch(
        vec![
            vec![fixture.genesis.commit.clone()],
            vec![fixture.genesis.reveal.clone()],
            vec![],
            vec![fixture.claim.reveal.clone()],
        ],
        0,
    );
    let directory = TempDir::new().unwrap();
    let (engine, _) = open(&directory, &blocks);
    scan_to(&engine, 101);
    engine
        .register_names(fixture.genesis.id(), fixture.point(101))
        .unwrap();
    let before = snapshot(&directory);
    let gap = engine.names_step(fixture.genesis.id()).unwrap();
    assert_eq!(gap.status.projected, fixture.point(101));
    assert!(gap.applied.is_none());
    assert_eq!(gap.rolled_back, 0);
    assert!(gap.outcomes.is_empty());
    assert!(!gap.status.complete_to_tip);
    assert_eq!(snapshot(&directory), before);
    scan_to(&engine, 102);
    step(&engine, &fixture, point(102, &blocks[2]), None, 0);
    scan_to(&engine, 103);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    assert_eq!(
        engine.status().unwrap().indexed_through,
        Some(point(102, &blocks[2]))
    );
    let before = snapshot(&directory);
    let unresolved = engine.names_step(fixture.genesis.id()).unwrap();
    assert!(unresolved.applied.is_none());
    assert!(unresolved.outcomes.is_empty());
    assert_eq!(snapshot(&directory), before);
    assert_eq!(
        engine
            .resolve_commit(&serialize(&fixture.claim.commit))
            .unwrap(),
        1
    );
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
    assert_eq!(
        engine.status().unwrap().indexed_through,
        Some(point(103, &blocks[3]))
    );
    assert_raw(&engine, &fixture.claim);
    let count: i64 = readonly(&directory).query_row("SELECT count(*) FROM locators l JOIN selected s ON s.hash=l.block_hash WHERE l.txid=?1", [fixture.claim.commit.compute_txid().to_string()], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
    no_write(
        &directory,
        || engine.names_step(fixture.genesis.id()),
        "Busy",
    );
    fixture.unbound(&engine);
    assert_eq!(
        engine
            .names_status(fixture.genesis.id())
            .unwrap()
            .unwrap()
            .projected
            .height,
        102
    );

    // Two controlled duplicate-TXID cases: old pre-genesis, then old expired.
    // These assert selected membership/window semantics, not UTXO consensus.
    for (old, live, reveal) in [(100, 102, 103), (102, 247, 248)] {
        let mut bodies = vec![vec![]; (reveal - START + 1) as usize];
        bodies[0].push(fixture.genesis.commit.clone());
        bodies[1].push(fixture.genesis.reveal.clone());
        bodies[(old - START) as usize].push(fixture.claim.commit.clone());
        bodies[(live - START) as usize].push(fixture.claim.commit.clone());
        bodies[(reveal - START) as usize].push(fixture.claim.reveal.clone());
        let blocks = branch(bodies, 0);
        let directory = TempDir::new().unwrap();
        let (engine, _) = open(&directory, &blocks);
        scan_to(&engine, reveal);
        assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
        let placements: Vec<u64> = readonly(&directory).prepare("SELECT s.height FROM locators l JOIN selected s ON s.hash=l.block_hash WHERE l.txid=?1 ORDER BY s.height,l.position").unwrap()
            .query_map([fixture.claim.commit.compute_txid().to_string()], |r| {
            let height: u64 = r.get::<_, i64>(0)?.try_into().expect("selected locator height is nonnegative");
            Ok(height)
        }).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(placements, vec![old, live]);
        engine
            .register_names(fixture.genesis.id(), point(101, &blocks[1]))
            .unwrap();
        for height in 102..=reveal {
            let outcome = (height == reveal).then_some((fixture.claim.id(), Verdict::Pending));
            step(
                &engine,
                &fixture,
                point(height, &blocks[(height - START) as usize]),
                outcome,
                0,
            );
        }
        assert_pending(&directory, &fixture, reveal, &[], false);
        fixture.unbound(&engine);
        assert!(
            engine
                .names_status(fixture.genesis.id())
                .unwrap()
                .unwrap()
                .complete_to_tip
        );
    }

    // Known selected/fullscan placement, but expired-only: omit the observation
    // and still apply its fully scanned block. This is distinct from the above
    // genuinely absent placement, whose raw parent alone cannot justify progress.
    let mut bodies = vec![vec![]; 149];
    bodies[0].push(fixture.genesis.commit.clone());
    bodies[1].push(fixture.genesis.reveal.clone());
    bodies[2].push(fixture.claim.commit.clone());
    bodies[148].push(fixture.claim.reveal.clone());
    assert!(248 - 102 > u64::from(fixture.rules.reveal_max_blocks));
    let blocks = branch(bodies, 0);
    let directory = TempDir::new().unwrap();
    let (engine, _) = open(&directory, &blocks);
    scan_to(&engine, 248);
    assert_eq!(
        engine.status().unwrap().indexed_through,
        Some(point(248, &blocks[148]))
    );
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
    assert_raw(&engine, &fixture.claim);
    let placements: Vec<u64> = readonly(&directory).prepare("SELECT s.height FROM locators l JOIN selected s ON s.hash=l.block_hash JOIN scans c ON c.block_hash=s.hash WHERE l.txid=?1 AND c.unresolved=0 ORDER BY s.height,l.position").unwrap()
        .query_map([fixture.claim.commit.compute_txid().to_string()], |r| {
            let height: u64 = r.get::<_, i64>(0)?.try_into().expect("selected locator height is nonnegative");
            Ok(height)
        }).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    assert_eq!(placements, vec![102]);
    engine
        .register_names(fixture.genesis.id(), point(101, &blocks[1]))
        .unwrap();
    for height in 102..=248 {
        step(
            &engine,
            &fixture,
            point(height, &blocks[(height - START) as usize]),
            None,
            0,
        );
    }
    fixture.unbound(&engine);
    let db = readonly(&directory);
    assert_eq!(
        db.query_row("SELECT count(*) FROM names_pending", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM names_outcomes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let names = engine.names_status(fixture.genesis.id()).unwrap().unwrap();
    assert_eq!(names.projected, point(248, &blocks[148]));
    assert!(names.complete_to_tip);
}

#[test]
fn reorg_reverses_approvals_claim_and_refuses_orphan_genesis() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (mut engine, source) = open(&directory, &fixture.blocks);
    scan_to(&engine, 107);
    project_all(&engine, &fixture);
    fixture.bound(&engine, 1, 107);
    let generation = engine.status().unwrap().generation;
    let without_approval = fork(&fixture.blocks, 107, vec![vec![]], 10_000);
    source.select(&without_approval);
    engine.synchronize_headers().unwrap();
    assert!(engine.status().unwrap().generation > generation);
    no_write(
        &directory,
        || engine.names_status(fixture.genesis.id()),
        "Stale",
    );
    no_write(
        &directory,
        || engine.names_resolve(fixture.genesis.id(), &fixture.op.name),
        "Stale",
    );
    scan_to(&engine, 107);
    step(&engine, &fixture, point(107, &without_approval[7]), None, 1);
    fixture.unbound(&engine);
    assert_pending(&directory, &fixture, 103, &[0], false);
    let before = snapshot(&directory);
    let resolution = json(
        engine
            .names_resolve(fixture.genesis.id(), &fixture.op.name)
            .unwrap(),
    );
    drop(engine);
    engine = Engine::open(directory.path(), fixture.config(), Some(source.clone())).unwrap();
    assert_eq!(
        json(
            engine
                .names_resolve(fixture.genesis.id(), &fixture.op.name)
                .unwrap()
        ),
        resolution
    );
    assert_eq!(snapshot(&directory), before);
    let without_claim = fork(&fixture.blocks, 103, vec![vec![]; 5], 20_000);
    source.select(&without_claim);
    engine.synchronize_headers().unwrap();
    scan_to(&engine, 107);
    step(&engine, &fixture, point(103, &without_claim[3]), None, 5);
    fixture.unbound(&engine);
    let count: i64 = readonly(&directory)
        .query_row("SELECT count(*) FROM names_pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    for height in 104..=107 {
        step(
            &engine,
            &fixture,
            point(height, &without_claim[(height - START) as usize]),
            None,
            0,
        );
    }
    let orphan_genesis = fork(&fixture.blocks, 101, vec![vec![]; 7], 30_000);
    source.select(&orphan_genesis);
    engine.synchronize_headers().unwrap();
    no_write(
        &directory,
        || engine.names_status(fixture.genesis.id()),
        "Stale",
    );
    no_write(
        &directory,
        || engine.names_resolve(fixture.genesis.id(), &fixture.op.name),
        "Stale",
    );
    no_write(
        &directory,
        || engine.names_step(fixture.genesis.id()),
        "Stale",
    );
    no_write(
        &directory,
        || engine.register_names(fixture.genesis.id(), fixture.point(101)),
        "Stale",
    );
    let before = snapshot(&directory);
    drop(engine);
    let reopened = Engine::open(directory.path(), fixture.config(), None).unwrap();
    no_write(
        &directory,
        || reopened.names_status(fixture.genesis.id()),
        "Stale",
    );
    no_write(
        &directory,
        || reopened.names_step(fixture.genesis.id()),
        "Stale",
    );
    assert_eq!(snapshot(&directory), before);
}

#[test]
fn sqlite_abort_rolls_back_undo_new_delta_outcomes_checkpoint_and_event() {
    let fixture = Fixture::new();
    // Same-instance retry tests discarded temporary Registry state; a second
    // archive tests reopening after failure before retrying from persisted undo.
    for reopen_before_retry in [false, true] {
        let directory = TempDir::new().unwrap();
        let (mut engine, source) = open(&directory, &fixture.blocks);
        scan_to(&engine, 107);
        project_all(&engine, &fixture);
        fixture.bound(&engine, 1, 107);
        let replacement = fork(
            &fixture.blocks,
            107,
            vec![vec![fixture.approvals[2].reveal.clone()]],
            40_000,
        );
        source.select(&replacement);
        engine.synchronize_headers().unwrap();
        scan_to(&engine, 107);
        no_write(
            &directory,
            || engine.names_status(fixture.genesis.id()),
            "Stale",
        );
        let original = snapshot(&directory);
        assert_eq!(original.version, 5);
        let db = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
        // Every interpolated value is a locally computed fixed hash/height;
        // this writer only injects a fault into its own disposable archive.
        db.execute_batch(&format!(
            "CREATE TRIGGER u4_names_abort AFTER INSERT ON events
             WHEN NEW.kind='names' AND NEW.height=107 BEGIN
             SELECT CASE WHEN
             NEW.block_hash='{hash}' AND
             EXISTS(SELECT 1 FROM names_registries WHERE genesis='{registry}' AND height=107 AND block_hash='{hash}') AND
             EXISTS(SELECT 1 FROM names_blocks WHERE registry='{registry}' AND height=107 AND block_hash='{hash}' AND delta IS NOT NULL) AND
             EXISTS(SELECT 1 FROM names_outcomes WHERE registry='{registry}' AND height=107 AND txid='{new}') AND
             NOT EXISTS(SELECT 1 FROM names_outcomes WHERE registry='{registry}' AND height=107 AND txid='{old}') AND
             EXISTS(SELECT 1 FROM names_states WHERE registry='{registry}' AND name='atelier') AND
             EXISTS(SELECT 1 FROM names_pending WHERE registry='{registry}' AND txid='{claim}' AND instr(CAST(state AS TEXT),'{new_author}')>0 AND instr(CAST(state AS TEXT),'{old_author}')=0)
             THEN RAISE(ABORT,'{ABORT}') ELSE RAISE(ABORT,'u4 Names staging missing') END;
             END;",
            hash = replacement[7].block_hash(), registry = fixture.genesis.id(),
            new = fixture.approvals[2].id(), old = fixture.approvals[1].id(), claim = fixture.claim.id(),
            new_author = fixture.approvals[2].author, old_author = fixture.approvals[1].author,
        )).unwrap();
        let error = engine.names_step(fixture.genesis.id()).unwrap_err();
        match error {
            Error::Database(rusqlite::Error::SqliteFailure(code, detail)) => {
                assert_eq!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER);
                assert_eq!(detail.as_deref(), Some(ABORT));
            }
            other => panic!("expected staged SQLite ABORT, got {other:?}"),
        }
        db.execute_batch("DROP TRIGGER u4_names_abort").unwrap();
        drop(db);
        assert_eq!(snapshot(&directory), original);
        assert_pending(&directory, &fixture, 103, &[0, 1], true);
        no_write(
            &directory,
            || engine.names_status(fixture.genesis.id()),
            "Stale",
        );
        no_write(
            &directory,
            || engine.names_resolve(fixture.genesis.id(), &fixture.op.name),
            "Stale",
        );
        if reopen_before_retry {
            drop(engine);
            engine = Engine::open(directory.path(), fixture.config(), None).unwrap();
            assert_eq!(snapshot(&directory), original);
            no_write(
                &directory,
                || engine.names_status(fixture.genesis.id()),
                "Stale",
            );
        }
        step(
            &engine,
            &fixture,
            point(107, &replacement[7]),
            Some((fixture.approvals[2].id(), Verdict::Applied)),
            1,
        );
        assert_pending(&directory, &fixture, 103, &[0, 2], true);
        fixture.bound(&engine, 2, 107);
        let result = json(
            engine
                .names_resolve(fixture.genesis.id(), &fixture.op.name)
                .unwrap(),
        );
        let final_db = snapshot(&directory);
        drop(engine);
        let reopened = Engine::open(directory.path(), fixture.config(), None).unwrap();
        assert_eq!(
            json(
                reopened
                    .names_resolve(fixture.genesis.id(), &fixture.op.name)
                    .unwrap()
            ),
            result
        );
        assert_eq!(snapshot(&directory), final_db);
    }
}
