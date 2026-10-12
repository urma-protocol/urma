//! Public Engine Names pages from genuine local signed history.
//! Header selection is mocked; no PoW/UTXO/consensus claim or live source.
//! Corruption writes occur only in owned TEMP archives with Engine closed.
//! Runtime corruption assertions prove refusal, not allocator instrumentation.

#[allow(dead_code)]
mod common;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, XOnlyPublicKey, absolute,
    block::Header,
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
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tempfile::TempDir;
use urma_chain::observation::Chain;
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{
    name::Name,
    payload::{Approval, Genesis, NameOp, OwnerOp, Payload},
    state::{Binding, Bound, NameState, PendingKind, PendingRecord, Target},
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    names::{MAX_NAMES_STATE_BYTES, NamesCursor, NamesEntry, NamesKey, NamesPage},
    source::ChainSource,
};

// Same real signer/verification pattern as names_storage and Names Proof::signed.
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
    other_genesis: Signed,
    claim: Signed,
    extra: Signed,
    vote: Signed,
    approvals: [Signed; 2],
    rules: Genesis,
    op: OwnerOp,
    blocks: Vec<Block>,
}

impl Fixture {
    fn new() -> Self {
        let raw = include_bytes!("../../tests/vectors/names/genesis-administered.record");
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(raw).unwrap()).unwrap()
        else {
            panic!("public Genesis")
        };
        let genesis = Signed::new(raw.to_vec(), [4; 32]);
        // A second genuinely verified registry makes cross-registry refusal
        // independent of an unknown/unregistered-ID failure.
        let other_genesis = Signed::new(raw.to_vec(), [6; 32]);
        assert_ne!(genesis.id(), other_genesis.id());
        let Payload::Claim(mut op) = Payload::from_record(
            &PublicRecord::decode(include_bytes!("../../tests/vectors/names/claim.record"))
                .unwrap(),
        )
        .unwrap() else {
            panic!("public Claim")
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
        // Only one additional claim is included. A bounded public-salt search
        // ensures these two real IDs distinguish display-hex from Txid::Ord;
        // no guessed IDs, SQL seeds or hundreds of signed records are used.
        let extra = (0..16)
            .find_map(|salt| {
                let mut extra_op = op.clone();
                extra_op.name = Name::parse("alpha").unwrap();
                extra_op.salt[0] = salt;
                let signed = Signed::new(
                    Payload::Claim(extra_op)
                        .to_record()
                        .unwrap()
                        .encode()
                        .unwrap(),
                    [5; 32],
                );
                (claim.id().to_string().cmp(&signed.id().to_string())
                    != claim.id().cmp(&signed.id()))
                .then_some(signed)
            })
            .expect("bounded fixture search distinguishes displayed and internal TXID order");
        let approval = Payload::Approve(Approval {
            registry: genesis.id(),
            record_txid: claim.id(),
            record_sha256: sha256::Hash::hash(&claim.bytes).to_byte_array(),
        })
        .to_record()
        .unwrap()
        .encode()
        .unwrap();
        let approvals = [11, 12].map(|key| Signed::new(approval.clone(), scalar(key)));
        for signed in &approvals {
            assert!(rules.is_approver(&signed.author));
        }
        assert_eq!(rules.threshold, 2);
        // One vote persists an unbound zulu NameState (including the vote),
        // before atelier is bound, reversing insertion versus ASCII ordering.
        let vote = Signed::new(
            Payload::Suspend(NameOp {
                registry: genesis.id(),
                name: Name::parse("zulu").unwrap(),
            })
            .to_record()
            .unwrap()
            .encode()
            .unwrap(),
            scalar(11),
        );
        let bodies = [
            vec![genesis.commit.clone(), other_genesis.commit.clone()],
            vec![genesis.reveal.clone(), other_genesis.reveal.clone()],
            vec![
                claim.commit.clone(),
                extra.commit.clone(),
                vote.commit.clone(),
            ],
            vec![
                claim.reveal.clone(),
                extra.reveal.clone(),
                vote.reveal.clone(),
            ],
            vec![approvals[0].commit.clone()],
            vec![approvals[0].reveal.clone()],
            vec![approvals[1].commit.clone()],
            vec![approvals[1].reveal.clone()],
        ];
        let mut blocks = Vec::new();
        for (i, txs) in bodies.iter().enumerate() {
            blocks.push(common::witness_block(txs, blocks.last(), (100 + i) as u32));
        }
        Self {
            genesis,
            other_genesis,
            claim,
            extra,
            vote,
            approvals,
            rules,
            op,
            blocks,
        }
    }

    fn config(&self) -> ArchiveConfig {
        common::config(&self.blocks[0], Retention::Pruned)
    }
    fn point(&self, height: u64) -> ChainPoint {
        common::point(height, &self.blocks[(height - 100) as usize])
    }
    fn setup(&self, directory: &TempDir) -> (Engine, Arc<Source>) {
        let source = Arc::new(Source {
            inner: common::MemorySource::new(&self.blocks),
            calls: AtomicUsize::new(0),
        });
        let engine = Engine::open(directory.path(), self.config(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        scan_all(&engine);
        assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
        for genesis in [&self.genesis, &self.other_genesis] {
            let archived = engine.record(genesis.id()).unwrap().unwrap();
            assert_eq!(
                archived.package.reveal.transaction,
                bitcoin::consensus::serialize(&genesis.reveal)
            );
            engine
                .register_names(genesis.id(), self.point(101))
                .unwrap();
        }
        (engine, source)
    }

    fn advance(&self, engine: &Engine, through: u64) {
        let current = engine
            .names_status(self.genesis.id())
            .unwrap()
            .unwrap()
            .projected
            .height;
        for height in current + 1..=through {
            let step = engine.names_step(self.genesis.id()).unwrap();
            assert_eq!(step.applied, Some(self.point(height)));
            assert_eq!(step.rolled_back, 0);
        }
    }

    fn expected(&self, bound: bool, approvals: &[usize]) -> Vec<NamesEntry> {
        let mut entries = Vec::new();
        if bound {
            entries.push(NamesEntry::Name {
                name: self.op.name.clone(),
                state: NameState {
                    binding: Binding::Bound(Bound {
                        owner: self.claim.author,
                        target: Target::Publication(self.op.target),
                        expiry: 107 + u64::from(self.rules.expiry_blocks),
                        claim_txid: self.claim.id(),
                        last_txid: self.approvals[1].id(),
                    }),
                    suspended: false,
                    suspend_votes: BTreeSet::new(),
                    restore_votes: BTreeSet::new(),
                },
            });
        }
        entries.push(NamesEntry::Name {
            name: Name::parse("zulu").unwrap(),
            state: NameState {
                binding: Binding::Unbound,
                suspended: false,
                suspend_votes: BTreeSet::from([self.vote.author]),
                restore_votes: BTreeSet::new(),
            },
        });
        let mut pending = vec![
            (&self.claim, self.op.name.clone(), bound),
            (&self.extra, Name::parse("alpha").unwrap(), false),
        ];
        pending.sort_by_key(|(signed, _, _)| signed.id().to_string());
        for (signed, name, completed) in pending {
            entries.push(NamesEntry::Pending {
                txid: signed.id(),
                record: PendingRecord {
                    kind: PendingKind::Request,
                    name,
                    author: signed.author,
                    target: self.op.target,
                    sha256: sha256::Hash::hash(&signed.bytes).to_byte_array(),
                    height: 103,
                    approvals: if signed.id() == self.claim.id() {
                        approvals
                            .iter()
                            .map(|i| self.approvals[*i].author)
                            .collect()
                    } else {
                        BTreeSet::new()
                    },
                    completed,
                },
            });
        }
        entries
    }

    fn fork(&self, first: u64, salt: u32) -> Vec<Block> {
        let mut blocks = self.blocks[..(first - 100) as usize].to_vec();
        for height in first..=107 {
            blocks.push(common::witness_block(
                &[],
                blocks.last(),
                salt + height as u32,
            ));
        }
        blocks
    }
}

struct Source {
    inner: common::MemorySource,
    calls: AtomicUsize,
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.block(height)
    }
}

fn scan_all(engine: &Engine) {
    for _ in 0..8 {
        let before = engine.status().unwrap().scanned_blocks;
        if before == 8 {
            return;
        }
        assert!(before < 8);
        assert_eq!(engine.scan_next().unwrap().scanned_blocks, before + 1);
    }
    assert_eq!(engine.status().unwrap().scanned_blocks, 8);
}

fn json(value: impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}
fn rows(db: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = db.prepare(sql).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<Vec<Value>>,
    tables: Vec<(String, Vec<Vec<Value>>)>,
}
fn snapshot(directory: &TempDir) -> Snapshot {
    // Quiescent owned TEMP only, between completed public Engine calls.
    let db = Connection::open_with_flags(
        directory.path().join("archive.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let schema = rows(
        &db,
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
    );
    let names: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables = names
        .into_iter()
        .map(|name| {
            let escaped = name.replace('"', "\"\"");
            let rows = rows(&db, &format!("SELECT * FROM \"{escaped}\" ORDER BY rowid"));
            (name, rows)
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

fn read(
    engine: &Engine,
    directory: &TempDir,
    source: &Source,
    genesis: Txid,
    cursor: Option<&NamesCursor>,
    limit: u32,
) -> Result<NamesPage, Error> {
    let before = snapshot(directory);
    let status = json(engine.status().unwrap());
    let calls = source.calls.load(Ordering::SeqCst);
    let result = engine.names_view(genesis, cursor, limit);
    assert_eq!(snapshot(directory), before);
    assert_eq!(json(engine.status().unwrap()), status);
    assert_eq!(
        source.calls.load(Ordering::SeqCst),
        calls,
        "Names view called a chain source"
    );
    result
}

fn collect(
    engine: &Engine,
    directory: &TempDir,
    source: &Source,
    fixture: &Fixture,
    limit: u32,
) -> (NamesPage, Vec<NamesEntry>, Vec<usize>) {
    let expected_status = json(engine.names_status(fixture.genesis.id()).unwrap().unwrap());
    let mut first: Option<NamesPage> = None;
    let mut cursor = None;
    let mut entries = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..6 {
        let page = read(
            engine,
            directory,
            source,
            fixture.genesis.id(),
            cursor.as_ref(),
            limit,
        )
        .unwrap();
        assert_eq!(
            page.chain_genesis,
            Chain::BitcoinRegtest.genesis().unwrap().0
        );
        assert_eq!(json(&page.status), expected_status);
        assert_eq!(page.rules, fixture.rules);
        assert!(page.entries.len() <= limit as usize);
        if let Some(first) = &first {
            assert_eq!(page.snapshot, first.snapshot);
        } else {
            first = Some(page.clone());
        }
        if let Some(next) = &page.next {
            assert_eq!(next.genesis, fixture.genesis.id());
            assert_eq!(next.snapshot, page.snapshot);
            assert_eq!(next.after, page.entries.last().unwrap().key());
        }
        sizes.push(page.entries.len());
        entries.extend(page.entries);
        cursor = page.next;
        if cursor.is_none() {
            return (first.unwrap(), entries, sizes);
        }
    }
    panic!("four-row traversal did not terminate within its bound");
}

fn assert_busy(result: Result<NamesPage, Error>) {
    assert!(
        matches!(result, Err(Error::Busy(_))),
        "expected stale-cursor Busy, got {result:?}"
    );
}
fn assert_stale(result: Result<NamesPage, Error>) {
    assert!(
        matches!(result, Err(Error::Stale)),
        "expected orphaned projection Stale, got {result:?}"
    );
}

#[test]
fn signed_names_then_pending_share_one_limit_and_exact_end() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (engine, source) = fixture.setup(&directory);
    let (empty, entries, sizes) = collect(&engine, &directory, &source, &fixture, 1);
    assert!(entries.is_empty());
    assert_eq!(sizes, vec![0]);
    assert!(empty.next.is_none());
    assert!(!empty.status.complete_to_tip); // End of local rows is not tip coverage.
    fixture.advance(&engine, 103);
    let (_, entries, sizes) = collect(&engine, &directory, &source, &fixture, 1);
    assert_eq!(entries, fixture.expected(false, &[]));
    assert_eq!(sizes, vec![1, 1, 1]);
    fixture.advance(&engine, 107);
    let expected = fixture.expected(true, &[0, 1]);
    for (limit, sizes) in [
        (1, vec![1, 1, 1, 1]),
        (2, vec![2, 2]),
        (3, vec![3, 1]),
        (4, vec![4]),
    ] {
        let (first, entries, actual_sizes) = collect(&engine, &directory, &source, &fixture, limit);
        assert_eq!(entries, expected);
        assert_eq!(actual_sizes, sizes);
        assert!(first.status.complete_to_tip);
        if limit == 2 {
            assert!(
                matches!(&first.next.as_ref().unwrap().after, NamesKey::Name(name) if name.as_str() == "zulu")
            );
        }
        if limit == 3 {
            assert!(matches!(
                &first.next.as_ref().unwrap().after,
                NamesKey::Pending(_)
            ));
        }
    }
}

#[test]
fn empty_and_state_changing_projection_invalidate_cursors_without_reorg() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (engine, source) = fixture.setup(&directory);
    fixture.advance(&engine, 103);
    let before_archive = json(engine.status().unwrap());
    let old = read(&engine, &directory, &source, fixture.genesis.id(), None, 1).unwrap();
    fixture.advance(&engine, 104); // Empty Names delta; only checkpoint/event moves.
    assert_eq!(json(engine.status().unwrap()), before_archive);
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        old.next.as_ref(),
        1,
    ));
    let (after_empty, entries, _) = collect(&engine, &directory, &source, &fixture, 1);
    assert_eq!(entries, fixture.expected(false, &[]));
    assert_eq!(after_empty.snapshot.instance, old.snapshot.instance);
    assert!(after_empty.snapshot.revision > old.snapshot.revision);
    assert_eq!(after_empty.status.generation, old.status.generation);
    fixture.advance(&engine, 105); // Same-generation pending approvals update.
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        after_empty.next.as_ref(),
        1,
    ));
    let (after_vote, entries, _) = collect(&engine, &directory, &source, &fixture, 1);
    assert_eq!(entries, fixture.expected(false, &[0]));
    fixture.advance(&engine, 107); // Completion creates atelier and keeps pending.
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        after_vote.next.as_ref(),
        1,
    ));
    let (completed, entries, _) = collect(&engine, &directory, &source, &fixture, 2);
    assert_eq!(entries, fixture.expected(true, &[0, 1]));
    assert_eq!(completed.status.generation, old.status.generation);
    assert_eq!(json(engine.status().unwrap()), before_archive);
}

#[test]
fn reorg_orphan_and_restart_refuse_old_views_and_preserve_reads() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (mut engine, source) = fixture.setup(&directory);
    fixture.advance(&engine, 107);
    let old = read(&engine, &directory, &source, fixture.genesis.id(), None, 1).unwrap();
    let fork = fixture.fork(107, 10_000);
    source.inner.replace_branch(&fork);
    engine.synchronize_headers().unwrap();
    scan_all(&engine);
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        old.next.as_ref(),
        1,
    ));
    assert_stale(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        None,
        1,
    ));
    let step = engine.names_step(fixture.genesis.id()).unwrap();
    assert_eq!(step.rolled_back, 1);
    assert_eq!(step.applied, Some(common::point(107, &fork[7])));
    let (reconciled, entries, _) = collect(&engine, &directory, &source, &fixture, 1);
    assert_eq!(entries, fixture.expected(false, &[0]));
    assert!(reconciled.status.generation > old.status.generation);
    let persisted = snapshot(&directory);
    drop(engine);
    engine = Engine::open(directory.path(), fixture.config(), None).unwrap();
    assert_eq!(snapshot(&directory), persisted);
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        reconciled.next.as_ref(),
        1,
    ));
    let (restarted, entries, _) = collect(&engine, &directory, &source, &fixture, 1);
    assert_eq!(entries, fixture.expected(false, &[0]));
    assert_ne!(restarted.snapshot.instance, reconciled.snapshot.instance);
    assert_eq!(restarted.snapshot.revision, reconciled.snapshot.revision);
    assert_eq!(json(&restarted.status), json(&reconciled.status));
    drop(engine);
    engine = Engine::open(directory.path(), fixture.config(), Some(source.clone())).unwrap();
    let before_orphan = read(&engine, &directory, &source, fixture.genesis.id(), None, 1).unwrap();
    let orphan = fixture.fork(101, 20_000);
    source.inner.replace_branch(&orphan);
    engine.synchronize_headers().unwrap();
    assert_stale(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        None,
        1,
    ));
    assert_busy(read(
        &engine,
        &directory,
        &source,
        fixture.genesis.id(),
        before_orphan.next.as_ref(),
        1,
    ));
}

#[test]
fn invalid_limits_and_genuine_cross_registry_cursor_do_not_write() {
    let fixture = Fixture::new();
    let directory = TempDir::new().unwrap();
    let (engine, source) = fixture.setup(&directory);
    fixture.advance(&engine, 107);
    let first = read(&engine, &directory, &source, fixture.genesis.id(), None, 1).unwrap();
    for limit in [0, 129, u32::MAX] {
        let result = read(
            &engine,
            &directory,
            &source,
            fixture.genesis.id(),
            None,
            limit,
        );
        assert!(
            matches!(result, Err(Error::Invalid(_))),
            "invalid limit {limit}: {result:?}"
        );
    }
    let result = read(
        &engine,
        &directory,
        &source,
        fixture.other_genesis.id(),
        first.next.as_ref(),
        1,
    );
    assert!(
        matches!(result, Err(Error::Invalid(_))),
        "cross-registry cursor: {result:?}"
    );
    let other = read(
        &engine,
        &directory,
        &source,
        fixture.other_genesis.id(),
        None,
        1,
    )
    .unwrap();
    assert_eq!(other.status.genesis, fixture.other_genesis.id());
    assert!(other.entries.is_empty());
    assert!(other.next.is_none());
}

#[test]
fn corrupt_owned_storage_is_refused_by_byte_bounds_without_read_mutation() {
    let fixture = Fixture::new();
    // The two TEXT keys use NUL to distinguish SQLite character length from
    // actual byte size. TEXT/BLOB value cases are corrupt local storage only.
    for (table, column, representation) in [
        ("names_states", "name", "key"),
        ("names_pending", "txid", "key"),
        ("names_registries", "rules", "text"),
        ("names_registries", "rules", "blob"),
        ("names_states", "state", "text"),
        ("names_states", "state", "blob"),
        ("names_pending", "state", "text"),
        ("names_pending", "state", "blob"),
    ] {
        let directory = TempDir::new().unwrap();
        let (engine, source) = fixture.setup(&directory);
        fixture.advance(&engine, 107);
        let (_, entries, _) = collect(&engine, &directory, &source, &fixture, 2);
        assert_eq!(entries, fixture.expected(true, &[0, 1])); // Genuine seed precondition.
        drop(engine); // No active archive owner/writer during test-only mutation.
        let db = Connection::open(directory.path().join("archive.sqlite3")).unwrap();
        let registry = fixture.genesis.id().to_string();
        let (predicate, key) = match table {
            "names_registries" => ("genesis=?2", registry.clone()),
            "names_states" => ("registry=?2 AND name=?3", fixture.op.name.to_string()),
            "names_pending" => ("registry=?2 AND txid=?3", fixture.claim.id().to_string()),
            _ => unreachable!(),
        };
        let value = match representation {
            "key" => Value::Text(format!("{key}\0{}", "x".repeat(512))),
            "text" => Value::Text(format!("\0{}", "x".repeat(MAX_NAMES_STATE_BYTES + 1))),
            "blob" => Value::Blob(vec![b'x'; MAX_NAMES_STATE_BYTES + 1]),
            _ => unreachable!(),
        };
        let sql = format!("UPDATE {table} SET {column}=?1 WHERE {predicate}");
        let changed = if table == "names_registries" {
            db.execute(&sql, params![value, registry]).unwrap()
        } else {
            db.execute(&sql, params![value, registry, key]).unwrap()
        };
        assert_eq!(changed, 1);
        let (characters, bytes): (i64, i64) = db.query_row(
            &format!("SELECT length({column}),length(CAST({column} AS BLOB)) FROM {table} WHERE {}=?1 AND {column}=?2", if table == "names_registries" { "genesis" } else { "registry" }),
            params![fixture.genesis.id().to_string(), value], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        let bound = if representation == "key" {
            64
        } else {
            MAX_NAMES_STATE_BYTES as i64
        };
        assert!(bytes > bound);
        if representation == "text" || representation == "key" {
            assert!(characters <= bound);
        }
        drop(db); // Writer closed before reopening the public Engine.
        let corrupted = snapshot(&directory);
        let reopened = Engine::open(directory.path(), fixture.config(), None).unwrap();
        assert_eq!(snapshot(&directory), corrupted);
        let result = read(
            &reopened,
            &directory,
            &source,
            fixture.genesis.id(),
            None,
            128,
        );
        match result {
            Err(Error::Invalid(reason)) => {
                let field = if representation == "key" {
                    "key"
                } else {
                    column
                };
                assert!(
                    reason.contains(&format!("stored {field}")) && reason.contains("bound"),
                    "{table}/{column}/{representation}: {reason}"
                );
            }
            other => panic!(
                "expected byte-bound refusal for {table}/{column}/{representation}: {other:?}"
            ),
        }
        assert_eq!(snapshot(&directory), corrupted);
    }
}
