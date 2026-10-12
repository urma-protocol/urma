//! Fair registered Names maintenance through public Engine and actual Service.
//! Genuine Taproot signatures and witness-integrity-valid blocks establish fixture
//! evidence; mock selection does not claim PoW, script, UTXO or full consensus.
//! The owned subprocess bounds abnormal cleanup, not hard cancellation of I/O.
//! Two registered fixtures exercise ordering/wrap, not a 128/129 page boundary.
#[allow(dead_code)]
mod common;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    block::Header,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use common::{FIRST_HEIGHT, MemorySource, SignedPair, config, point, vector, witness_block};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::payload::Payload;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, RecordPackage, Retention},
    names::{NamesStatus, NamesStep},
    retrieval::RecordSource,
    service::Service,
    source::ChainSource,
};
use urma_runtime::multipart::RecoveryLimits;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);

fn value<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn stage(control: &Path, text: &str) {
    fs::write(control.join("stage"), text).unwrap();
}

struct CountedSource {
    inner: MemorySource,
    calls: AtomicUsize,
}

impl CountedSource {
    fn new(blocks: &[Block]) -> Self {
        Self {
            inner: MemorySource::new(blocks),
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

// Count every source method, including genesis/tip, without changing common.
impl ChainSource for CountedSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.block(height)
    }
}

// Same public genesis corpus and genuine Taproot/BIP340 construction as the
// Names projection tests; no VerifiedRecord/scan mark/undo frame is fabricated.
fn signed_genesis(tag: u8) -> NamePair {
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
                txid: Txid::from_byte_array([tag; 32]),
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
    NamePair { commit, reveal }
}

struct NamePair {
    commit: Transaction,
    reveal: Transaction,
}
impl NamePair {
    fn id(&self) -> Txid {
        self.reveal.compute_txid()
    }
    fn transactions(&self) -> [Transaction; 2] {
        [self.commit.clone(), self.reveal.clone()]
    }
}
fn ordered_names() -> [NamePair; 2] {
    let mut pairs = [signed_genesis(41), signed_genesis(42)];
    // names_page orders the displayed SQL TXID strings, not block position or
    // internal consensus-byte ordering. Registration is deliberately reversed.
    pairs.sort_by_key(|pair| pair.id().to_string());
    assert!(pairs[0].id().to_string() < pairs[1].id().to_string());
    pairs
}

#[derive(Clone, Copy)]
enum Layout {
    Flat,
    Gap,
    Orphan { multipart: bool },
}
struct Fixture {
    temp: tempfile::TempDir,
    config: ArchiveConfig,
    blocks: Vec<Block>,
    source: Arc<CountedSource>,
    first: Txid,
    second: Txid,
    unregistered: Txid,
    root: Option<Txid>,
}
impl Fixture {
    fn new(retention: Retention, layout: Layout) -> Self {
        let [first, second] = ordered_names();
        let extra = signed_genesis(43);
        assert_ne!(extra.id(), first.id());
        assert_ne!(extra.id(), second.id());
        let mut transactions = second.transactions().to_vec();
        transactions.extend(extra.transactions());
        if matches!(layout, Layout::Flat | Layout::Gap) {
            transactions.extend(first.transactions());
        }
        let root = if matches!(layout, Layout::Orphan { multipart: true }) {
            let root = SignedPair::load("multipart/one-root");
            transactions.extend(root.transactions());
            Some(root.reveal.compute_txid())
        } else {
            None
        };
        let block0 = witness_block(&transactions, None, 9100);
        let transactions1 = if matches!(layout, Layout::Orphan { .. }) {
            first.transactions().to_vec()
        } else {
            vec![]
        };
        let block1 = witness_block(&transactions1, Some(&block0), 9101);
        let transactions2 = if matches!(layout, Layout::Gap) {
            // Genuine signed reveal, deliberately absent parent: scan mark has
            // unresolved=1. Neither registry can consume this shared block102.
            vec![SignedPair::load("proof-post").reveal]
        } else {
            vec![]
        };
        let block2 = witness_block(&transactions2, Some(&block1), 9102);
        let blocks = vec![block0, block1, block2];
        let config = config(&blocks[0], retention);
        let temp = tempfile::tempdir().unwrap();
        let source = Arc::new(CountedSource::new(&blocks));
        let engine = Engine::open(temp.path(), config.clone(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        for _ in &blocks {
            engine.scan_next().unwrap();
        }
        assert_eq!(engine.status().unwrap().scanned_blocks, 3);
        assert_eq!(
            engine.status().unwrap().unresolved_dependencies,
            u64::from(matches!(layout, Layout::Gap))
        );
        assert!(engine.record(extra.id()).unwrap().is_some());
        assert!(engine.names_status(extra.id()).unwrap().is_none());
        engine
            .register_names(second.id(), point(FIRST_HEIGHT, &blocks[0]))
            .unwrap();
        let first_height = usize::from(matches!(layout, Layout::Orphan { .. }));
        engine
            .register_names(
                first.id(),
                point(FIRST_HEIGHT + first_height as u64, &blocks[first_height]),
            )
            .unwrap();
        drop(engine); // Tests exercise persisted registrations through reopen.
        Self {
            temp,
            config,
            blocks,
            source,
            first: first.id(),
            second: second.id(),
            unregistered: extra.id(),
            root,
        }
    }
    fn open(&self) -> Engine {
        Engine::open(
            self.temp.path(),
            self.config.clone(),
            Some(self.source.clone()),
        )
        .unwrap()
    }
    fn orphan_first(&mut self) {
        let engine = self.open();
        let second = witness_block(&[], Some(&self.blocks[0]), 9201);
        let third = witness_block(&[], Some(&second), 9202);
        let replacement = vec![self.blocks[0].clone(), second, third];
        self.source.inner.replace_branch(&replacement);
        let generation = engine.status().unwrap().generation;
        engine.synchronize_headers().unwrap();
        engine.scan_next().unwrap();
        engine.scan_next().unwrap();
        assert!(engine.status().unwrap().generation > generation);
        assert_eq!(engine.status().unwrap().scanned_blocks, 3);
        assert!(matches!(engine.names_status(self.first), Err(Error::Stale)));
        assert_eq!(
            engine
                .names_status(self.second)
                .unwrap()
                .unwrap()
                .projected
                .height,
            FIRST_HEIGHT
        );
        assert!(engine.names_status(self.unregistered).unwrap().is_none());
        drop(engine);
        self.blocks = replacement;
    }
}
fn projection(engine: &Engine, id: Txid) -> NamesStatus {
    engine.names_status(id).unwrap().unwrap()
}
fn attempt(
    engine: &Engine,
    source: &CountedSource,
    cancelled: &AtomicBool,
) -> Result<Option<NamesStep>, Error> {
    let archive = value(engine.status().unwrap());
    let calls = source.calls();
    let result = engine.maintain_next_names(cancelled);
    assert_eq!(
        value(engine.status().unwrap()),
        archive,
        "Names maintenance changed coverage/evidence"
    );
    assert_eq!(
        source.calls(),
        calls,
        "Names maintenance performed source I/O"
    );
    result
}
fn assert_step(step: &NamesStep, genesis: Txid, applied: Option<ChainPoint>) {
    assert_eq!(step.status.genesis, genesis);
    assert_eq!(step.applied, applied);
    assert_eq!(step.rolled_back, 0);
    assert!(step.outcomes.is_empty());
}

#[test]
fn precancel_preserves_persisted_candidate_order_without_implicit_registration_in_both_retentions()
{
    for retention in [Retention::Pruned, Retention::Unpruned] {
        let fixture = Fixture::new(retention, Layout::Flat);
        let engine = fixture.open();
        let cancelled = AtomicBool::new(true);
        let initial_first = value(projection(&engine, fixture.first));
        let initial_second = value(projection(&engine, fixture.second));
        for _ in 0..2 {
            assert!(
                matches!(attempt(&engine, &fixture.source, &cancelled), Err(Error::Busy(message)) if message.contains("cancelled"))
            );
        }
        assert_eq!(value(projection(&engine, fixture.first)), initial_first);
        assert_eq!(value(projection(&engine, fixture.second)), initial_second);
        cancelled.store(false, Ordering::Release);
        let first = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &first,
            fixture.first,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1])),
        );
        assert_eq!(value(projection(&engine, fixture.second)), initial_second);
        // Cancellation after one attempt must not consume the next candidate.
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            attempt(&engine, &fixture.source, &cancelled),
            Err(Error::Busy(_))
        ));
        cancelled.store(false, Ordering::Release);
        let second = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &second,
            fixture.second,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1])),
        );
        assert!(engine.names_status(fixture.unregistered).unwrap().is_none());
        assert!(engine.record(fixture.unregistered).unwrap().is_some());
    }
}

#[test]
fn shared_gap_and_orphan_genesis_failures_advance_cursor_without_starving_later_registry() {
    for retention in [Retention::Pruned, Retention::Unpruned] {
        let fixture = Fixture::new(retention, Layout::Gap);
        let engine = fixture.open();
        let advanced = engine.names_step(fixture.first).unwrap();
        assert_step(
            &advanced,
            fixture.first,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1])),
        );
        assert_eq!(
            projection(&engine, fixture.first).projected.height,
            FIRST_HEIGHT + 1
        );
        assert_eq!(
            projection(&engine, fixture.second).projected.height,
            FIRST_HEIGHT
        );
        assert_eq!(
            engine.status().unwrap().indexed_through,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1]))
        );
        assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
        let cancelled = AtomicBool::new(false);
        let gap = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(&gap, fixture.first, None);
        assert_eq!(gap.status.projected.height, FIRST_HEIGHT + 1);
        assert!(!gap.status.complete_to_tip);
        let next = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &next,
            fixture.second,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1])),
        );
        // Both are now blocked by the same unresolved block102; no pretend
        // registry-specific scan completeness at one shared height.
        assert_eq!(
            projection(&engine, fixture.second).projected.height,
            FIRST_HEIGHT + 1
        );
        assert!(engine.names_status(fixture.unregistered).unwrap().is_none());
        drop(engine);

        let mut orphan = Fixture::new(retention, Layout::Orphan { multipart: false });
        // Sorted-first genesis at101, second at100: reorg preserves only latter.
        {
            let engine = orphan.open();
            assert_eq!(
                projection(&engine, orphan.first).genesis_block.height,
                FIRST_HEIGHT + 1
            );
            assert_eq!(
                projection(&engine, orphan.second).genesis_block.height,
                FIRST_HEIGHT
            );
        }
        orphan.orphan_first();
        let engine = orphan.open();
        let second_before = value(projection(&engine, orphan.second));
        assert!(matches!(
            attempt(&engine, &orphan.source, &cancelled),
            Err(Error::Stale)
        ));
        assert_eq!(value(projection(&engine, orphan.second)), second_before);
        let next = attempt(&engine, &orphan.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &next,
            orphan.second,
            Some(point(FIRST_HEIGHT + 1, &orphan.blocks[1])),
        );
        assert!(matches!(
            engine.names_status(orphan.first),
            Err(Error::Stale)
        ));
        assert!(engine.names_status(orphan.unregistered).unwrap().is_none());
    }
}

#[test]
fn completed_registry_is_skipped_and_each_call_applies_at_most_one_cached_block() {
    for retention in [Retention::Pruned, Retention::Unpruned] {
        let fixture = Fixture::new(retention, Layout::Flat);
        let engine = fixture.open();
        for index in 1..=2 {
            assert_step(
                &engine.names_step(fixture.first).unwrap(),
                fixture.first,
                Some(point(FIRST_HEIGHT + index as u64, &fixture.blocks[index])),
            );
        }
        let complete_first = projection(&engine, fixture.first);
        assert!(complete_first.complete_to_tip);
        assert_eq!(
            projection(&engine, fixture.second).projected.height,
            FIRST_HEIGHT
        );
        drop(engine);
        let engine = fixture.open();
        let cancelled = AtomicBool::new(false);
        let first = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &first,
            fixture.second,
            Some(point(FIRST_HEIGHT + 1, &fixture.blocks[1])),
        );
        assert_eq!(first.status.projected.height, FIRST_HEIGHT + 1);
        assert!(
            !first.status.complete_to_tip,
            "one call consumed both scanned remaining blocks"
        );
        assert_eq!(
            value(projection(&engine, fixture.first)),
            value(&complete_first)
        );
        // End-of-page wrap still skips the completed first registry.
        let second = attempt(&engine, &fixture.source, &cancelled)
            .unwrap()
            .unwrap();
        assert_step(
            &second,
            fixture.second,
            Some(point(FIRST_HEIGHT + 2, &fixture.blocks[2])),
        );
        assert!(second.status.complete_to_tip);
        let complete_second = value(second.status);
        for _ in 0..3 {
            assert!(
                attempt(&engine, &fixture.source, &cancelled)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                value(projection(&engine, fixture.first)),
                value(&complete_first)
            );
            assert_eq!(value(projection(&engine, fixture.second)), complete_second);
            assert!(engine.names_status(fixture.unregistered).unwrap().is_none());
        }
    }
}

fn request(method: &str, path: &str, headers: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n{headers}\r\n")
}
fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
}

// One absolute deadline for harness HTTP connect/write/read; no Client U2 API.
fn http(address: SocketAddr, request: &str) -> io::Result<(u16, Value)> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    let mut pending = request.as_bytes();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let count = stream.write(pending)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[count..];
    }
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == 8192 {
            return Err(io::Error::other("response header limit"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(io::Error::other)?;
    let code = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::other("missing status"))?
        .parse::<u16>()
        .map_err(io::Error::other)?;
    let headers: Vec<_> = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect();
    assert!(
        headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
                && value.trim() == "application/json")
    );
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() != 1 {
        return Err(io::Error::other("missing/duplicate response length"));
    }
    let length = lengths[0]
        .1
        .trim()
        .parse::<usize>()
        .map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("test response body limit"));
    }
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        stream.set_read_timeout(Some(remaining()?))?;
        let count = stream.read(&mut body[offset..])?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += count;
    }
    remaining()?;
    Ok((
        code,
        serde_json::from_slice(&body).map_err(io::Error::other)?,
    ))
}

const SYNC_REFUSAL: &str = "U3 controlled sync refusal";
const OBJECT_REFUSAL: &str = "U3 controlled object source refusal";
const GATE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug)]
enum Event {
    Sync(usize),
    Object {
        attempt: usize,
        requested: Txid,
        second: NamesStatus,
        first_stale: bool,
    },
}
struct Gate {
    events: mpsc::Sender<Event>,
    permits: Mutex<mpsc::Receiver<()>>,
}
impl Gate {
    fn pause(&self, event: Event) {
        // Already-started source callbacks cooperate with a bounded test gate.
        // Dropping the controller disconnects it on panic/shutdown; no I/O
        // preemption, archive-lock interruption or production hooks are claimed.
        let _ = self.events.send(event);
        let _ = self.permits.lock().unwrap().recv_timeout(GATE_TIMEOUT);
    }
}
struct RefusingSource {
    gate: Gate,
    tips: AtomicUsize,
    headers_or_bodies: AtomicUsize,
}
impl ChainSource for RefusingSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(urma_chain::observation::Chain::BitcoinRegtest
            .genesis()
            .unwrap()
            .0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        let round = self.tips.fetch_add(1, Ordering::Relaxed) + 1;
        self.gate.pause(Event::Sync(round));
        Err(Error::Invalid(SYNC_REFUSAL.into()))
    }
    fn header(&self, _: u64) -> Result<Header, Error> {
        self.headers_or_bodies.fetch_add(1, Ordering::Relaxed);
        Err(Error::Invalid("unexpected header acquisition".into()))
    }
    fn block(&self, _: u64) -> Result<Vec<u8>, Error> {
        self.headers_or_bodies.fetch_add(1, Ordering::Relaxed);
        Err(Error::Invalid("unexpected block acquisition".into()))
    }
}
struct ObservingPeer {
    engine: Arc<Engine>,
    first: Txid,
    second: Txid,
    gate: Gate,
    calls: AtomicUsize,
}
impl RecordSource for ObservingPeer {
    fn fetch(&self, requested: Txid) -> Result<Option<RecordPackage>, Error> {
        let attempt = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        let second = projection(&self.engine, self.second);
        let first_stale = matches!(self.engine.names_status(self.first), Err(Error::Stale));
        self.gate.pause(Event::Object {
            attempt,
            requested,
            second,
            first_stale,
        });
        Err(Error::Invalid(OBJECT_REFUSAL.into()))
    }
}
struct Permits {
    sync: mpsc::Sender<()>,
    object: mpsc::Sender<()>,
}
struct Session {
    address: SocketAddr,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
    permits: Option<Permits>,
}
impl Session {
    fn start(
        fixture: &Fixture,
        control: &Path,
        synchronize: bool,
    ) -> (
        Self,
        Arc<RefusingSource>,
        Arc<ObservingPeer>,
        mpsc::Receiver<Event>,
    ) {
        let (events, receive) = mpsc::channel();
        let (sync_permit, sync_wait) = mpsc::channel();
        let (object_permit, object_wait) = mpsc::channel();
        let source = Arc::new(RefusingSource {
            gate: Gate {
                events: events.clone(),
                permits: Mutex::new(sync_wait),
            },
            tips: AtomicUsize::new(0),
            headers_or_bodies: AtomicUsize::new(0),
        });
        let engine = Arc::new(
            Engine::open(
                fixture.temp.path(),
                fixture.config.clone(),
                Some(source.clone()),
            )
            .unwrap(),
        );
        let peer = Arc::new(ObservingPeer {
            engine: engine.clone(),
            first: fixture.first,
            second: fixture.second,
            gate: Gate {
                events,
                permits: Mutex::new(object_wait),
            },
            calls: AtomicUsize::new(0),
        });
        let scratch = control.join(if synchronize {
            "scratch-on"
        } else {
            "scratch-off"
        });
        fs::create_dir(&scratch).unwrap();
        let service = Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine.clone())
            .unwrap()
            .with_record_sources(vec![peer.clone()])
            .unwrap()
            .with_retention(
                scratch,
                RecoveryLimits {
                    attempts: 1,
                    timeout: Duration::from_secs(20),
                    ..RecoveryLimits::new(1, 3)
                },
            )
            .unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(synchronize));
        (
            Self {
                address,
                engine: Some(engine),
                worker: Some(worker),
                permits: Some(Permits {
                    sync: sync_permit,
                    object: object_permit,
                }),
            },
            source,
            peer,
            receive,
        )
    }
    fn engine(&self) -> &Engine {
        self.engine.as_ref().unwrap()
    }
    fn status(&self) -> Value {
        let (code, body) = http(self.address, &request("GET", "/v1/status", &auth())).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body["archive"], value(self.engine().status().unwrap()));
        assert_eq!(body["retention_configured"], true);
        assert_eq!(body["record_sources_configured"], 1);
        body
    }
    fn cleanup(&mut self) -> Result<(), String> {
        // Release/disconnect test-controlled callbacks before trying normal
        // authenticated shutdown and joining the actual Service worker.
        drop(self.permits.take());
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let shutdown = http(self.address, &request("POST", "/v1/shutdown", &auth()))
            .map_err(|e| e.to_string());
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service worker join exceeded cleanup bound".into());
        }
        worker
            .join()
            .map_err(|_| "Service thread panicked".to_owned())?
            .map_err(|e| e.to_string())?;
        match shutdown {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            result => Err(format!("authenticated shutdown failed: {result:?}")),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
        let weak = Arc::downgrade(self.engine.as_ref().unwrap());
        drop(self.engine.take());
        assert!(
            weak.upgrade().is_none(),
            "Service retained Engine after joined shutdown"
        );
        assert!(TcpStream::connect_timeout(&self.address, Duration::from_millis(200)).is_err());
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("bounded Names worker cleanup: {error}");
        }
    }
}
fn sync_event(events: &mpsc::Receiver<Event>, expected: usize) {
    match events
        .recv_timeout(GATE_TIMEOUT)
        .expect("sync callback event")
    {
        Event::Sync(round) => assert_eq!(round, expected),
        event => panic!("expected sync round {expected}, got {event:?}"),
    }
}
fn object_event(
    events: &mpsc::Receiver<Event>,
    expected: usize,
    leaf: Txid,
    second: Txid,
    height: u64,
) {
    match events
        .recv_timeout(GATE_TIMEOUT)
        .expect("object callback event")
    {
        Event::Object {
            attempt,
            requested,
            second: status,
            first_stale,
        } => {
            assert_eq!(attempt, expected);
            assert_eq!(
                requested, leaf,
                "callback must traverse the genuine root reference"
            );
            assert_eq!(status.genesis, second);
            assert_eq!(
                status.projected.height, height,
                "Names attempt was skipped or ran after object acquisition"
            );
            assert!(first_stale);
        }
        event => panic!("expected object attempt {expected}, got {event:?}"),
    }
}
fn assert_errors(body: &Value, names: Option<&str>, retention: Option<&str>) {
    assert!(
        body["last_sync_error"]
            .as_str()
            .unwrap()
            .contains(SYNC_REFUSAL),
        "{body}"
    );
    for (field, expected) in [
        ("last_names_error", names),
        ("last_retention_error", retention),
    ] {
        match expected {
            Some(text) => assert!(
                body[field].as_str().unwrap().contains(text),
                "{field}: {body}"
            ),
            None => assert!(body[field].is_null(), "{field}: {body}"),
        }
    }
    if let Some(error) = body["last_names_error"].as_str() {
        assert!(!error.contains(SYNC_REFUSAL));
        assert!(!error.contains(OBJECT_REFUSAL));
    }
}
fn worker(control: &Path) {
    let mut fixture = Fixture::new(Retention::Unpruned, Layout::Orphan { multipart: true });
    fixture.orphan_first();
    let root = fixture.root.unwrap();
    let leaf = SignedPair::load("multipart/one-leaf").reveal.compute_txid();
    {
        let engine = fixture.open();
        assert!(engine.record(root).unwrap().is_some());
        assert!(engine.record(leaf).unwrap().is_none());
        assert!(engine.object_status(root).unwrap().is_none());
    }
    stage(
        control,
        "run(false) control: registered cache, source and object handles configured",
    );
    let (session, source, peer, events) = Session::start(&fixture, control, false);
    let before = value(session.engine().status().unwrap());
    let names_before = value(projection(session.engine(), fixture.second));
    for _ in 0..3 {
        let body = session.status();
        for field in [
            "last_sync_error",
            "last_names_error",
            "last_retention_error",
        ] {
            assert!(body[field].is_null());
        }
        assert_eq!(
            value(projection(session.engine(), fixture.second)),
            names_before
        );
        assert!(session.engine().object_status(root).unwrap().is_none());
    }
    assert!(matches!(events.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(source.tips.load(Ordering::Relaxed), 0);
    assert_eq!(source.headers_or_bodies.load(Ordering::Relaxed), 0);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 0);
    drop(peer); // The observer owns an Engine handle; release it before lock check.
    session.finish();
    {
        let engine = fixture.open();
        assert_eq!(value(engine.status().unwrap()), before);
        assert_eq!(value(projection(&engine, fixture.second)), names_before);
    }

    stage(
        control,
        "run(true): sync failure then Names stale failure then object callback1",
    );
    let (session, source, peer, events) = Session::start(&fixture, control, true);
    sync_event(&events, 1);
    session.permits.as_ref().unwrap().sync.send(()).unwrap();
    object_event(&events, 1, leaf, fixture.second, FIRST_HEIGHT);
    let stale = Error::Stale.to_string();
    assert_errors(&session.status(), Some(&stale), None);
    session.permits.as_ref().unwrap().object.send(()).unwrap();

    // Round2 is held in source.tip before it returns. Round1's object error is
    // therefore fully published and cannot be overwritten by a later attempt.
    stage(
        control,
        "round2 sync gate: inspect three independent errors from round1",
    );
    sync_event(&events, 2);
    assert_errors(&session.status(), Some(&stale), Some(OBJECT_REFUSAL));
    assert_eq!(
        projection(session.engine(), fixture.second)
            .projected
            .height,
        FIRST_HEIGHT
    );
    assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
    session.permits.as_ref().unwrap().sync.send(()).unwrap();

    stage(
        control,
        "object callback2: cached Names progressed despite repeated sync error",
    );
    object_event(&events, 2, leaf, fixture.second, FIRST_HEIGHT + 1);
    assert_errors(&session.status(), None, Some(OBJECT_REFUSAL));
    let second = projection(session.engine(), fixture.second);
    assert_eq!(
        second.projected,
        point(FIRST_HEIGHT + 1, &fixture.blocks[1])
    );
    assert!(
        !second.complete_to_tip,
        "maintenance applied more than one Names block"
    );
    assert!(matches!(
        session.engine().names_status(fixture.first),
        Err(Error::Stale)
    ));
    assert!(
        session
            .engine()
            .names_status(fixture.unregistered)
            .unwrap()
            .is_none()
    );
    assert!(session.engine().object_status(root).unwrap().is_none());
    assert_eq!(value(session.engine().status().unwrap()), before);
    assert_eq!(source.tips.load(Ordering::Relaxed), 2);
    assert_eq!(source.headers_or_bodies.load(Ordering::Relaxed), 0);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 2);
    session.permits.as_ref().unwrap().object.send(()).unwrap();
    drop(peer);
    session.finish();
    // Public reopen proves normal cleanup released the archive, and cached Names
    // progress persists independently from the failed object acquisition.
    let engine = fixture.open();
    assert_eq!(value(engine.status().unwrap()), before);
    assert_eq!(value(projection(&engine, fixture.second)), value(second));
    assert!(engine.object_status(root).unwrap().is_none());
    assert!(engine.names_status(fixture.unregistered).unwrap().is_none());
}

#[test]
fn service_worker_retains_names_attempt_order_and_separate_errors_while_run_false_is_idle() {
    run("worker");
}

#[test]
#[ignore = "owned subprocess host for the Names-maintenance worker case"]
fn names_maintenance_host() {
    let control = PathBuf::from(std::env::var_os("U3_NAMES_MAINTENANCE_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("U3_NAMES_MAINTENANCE_CASE").unwrap();
    stage(&control, &format!("seeding actual Engine: {scenario}"));
    assert_eq!(scenario, "worker");
    worker(&control);
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({"scenario":scenario,"normal_service_joins_returned":true}))
            .unwrap(),
    )
    .unwrap();
}

struct Host {
    child: Option<Child>,
    directory: PathBuf,
}

impl Host {
    fn logs(&self) -> String {
        ["stage", "stdout", "stderr"]
            .map(|name| {
                let mut text = String::new();
                if let Ok(file) = File::open(self.directory.join(name)) {
                    let _ = file.take(64 * 1024).read_to_string(&mut text);
                }
                text
            })
            .join("\n")
    }
    fn finish(mut self, scenario: &str) {
        let deadline = Instant::now() + HOST_TIMEOUT;
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.child.take();
                assert!(exit.success(), "Names host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                assert_eq!(report["scenario"], scenario);
                assert_eq!(report["normal_service_joins_returned"], true);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Names host exceeded 45s; kill/reap is abnormal cleanup, not a normal Service join; {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => {
                    eprintln!("Names host cleanup/reap exceeded bound: {result:?}");
                    return;
                }
            }
        }
    }
}

fn run(scenario: &str) {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "names_maintenance_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_NAMES_MAINTENANCE_TEMP", directory.path())
        .env("U3_NAMES_MAINTENANCE_CASE", scenario)
        .env("TMPDIR", directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            File::create(directory.path().join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            File::create(directory.path().join("stderr")).unwrap(),
        ))
        .spawn()
        .unwrap();
    // Guard owns child before assertions, and TEMP outlives its cleanup.
    Host {
        child: Some(child),
        directory: directory.path().to_owned(),
    }
    .finish(scenario);
}
