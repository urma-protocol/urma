//! Actual authenticated Names routes through Service.run(false) and public Engine.
//! Genuine Taproot signatures and witness-integrity-valid blocks establish fixture
//! evidence; mock selection does not claim PoW, script, UTXO or full consensus.
//! The owned subprocess bounds abnormal cleanup, not hard cancellation of I/O.
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
use common::{
    FIRST_HEIGHT, MemorySource, config, point, profile, readonly_archive, vector, witness_block,
};
use rusqlite::types::Value as SqlValue;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{name::Name, payload::Payload, state::Resolution};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    names::{NamesResolution, NamesStatus, NamesStep},
    service::Service,
    source::ChainSource,
};

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

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<SqlValue>>>,
}

// Read-only inspection follows Service shutdown/join and Engine release.
fn snapshot(directory: &Path) -> Snapshot {
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
            let quoted = format!("\"{}\"", name.replace('"', "\"\""));
            let mut statement = db
                .prepare(&format!("SELECT * FROM {quoted} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, SqlValue>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
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

struct Seed {
    directory: PathBuf,
    config: ArchiveConfig,
    genesis: Txid,
    non_names: Txid,
    blocks: Vec<Block>,
    source: Arc<CountedSource>,
}

impl Seed {
    fn new(control: &Path, scanned: usize) -> Self {
        let (commit, reveal) = signed_genesis();
        let genesis = reveal.compute_txid();
        let profile = profile();
        let non_names = profile.reveal.compute_txid();
        let first = witness_block(
            &[vec![commit, reveal], profile.transactions().to_vec()].concat(),
            None,
            8101,
        );
        let second = witness_block(&[], Some(&first), 8102);
        let third = witness_block(&[], Some(&second), 8103);
        let blocks = vec![first, second, third];
        let source = Arc::new(CountedSource::new(&blocks));
        let directory = control.join("archive");
        let config = config(&blocks[0], Retention::Unpruned);
        let engine = Engine::open(&directory, config.clone(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        for _ in 0..scanned {
            engine.scan_next().unwrap();
        }
        assert_eq!(engine.status().unwrap().scanned_blocks, scanned as u64);
        assert!(engine.names_status(genesis).unwrap().is_none());
        drop(engine);
        Self {
            directory,
            config,
            genesis,
            non_names,
            blocks,
            source,
        }
    }
    fn base(&self) -> String {
        format!("/v1/names/{}", self.genesis)
    }
    fn register(&self) -> String {
        self.register_id(self.genesis)
    }
    fn register_id(&self, id: Txid) -> String {
        format!(
            "/v1/names/{id}/register?height={}&hash={}",
            FIRST_HEIGHT,
            self.blocks[0].block_hash()
        )
    }
    fn step(&self) -> String {
        format!("{}/step", self.base())
    }
    fn resolve(&self) -> String {
        format!("{}/resolve/absent", self.base())
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

struct Session {
    address: SocketAddr,
    engine: Option<Arc<Engine>>,
    source: Arc<CountedSource>,
    control: PathBuf,
    worker: Option<JoinHandle<Result<(), Error>>>,
}

impl Session {
    fn start(seed: &Seed, control: &Path) -> Self {
        let engine = Arc::new(
            Engine::open(
                &seed.directory,
                seed.config.clone(),
                Some(seed.source.clone()),
            )
            .unwrap(),
        );
        let service =
            Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine.clone()).unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(false));
        Self {
            address,
            engine: Some(engine),
            source: seed.source.clone(),
            control: control.to_owned(),
            worker: Some(worker),
        }
    }
    fn engine(&self) -> &Engine {
        self.engine.as_ref().unwrap()
    }
    fn call(&self, method: &str, path: &str, headers: &str, expected: u16) -> Value {
        stage(
            &self.control,
            &format!("{method} {path}: expect {expected}"),
        );
        let before = serde_json::to_value(self.engine().status().unwrap()).unwrap();
        let source_calls = self.source.calls();
        let (code, body) = http(self.address, &request(method, path, headers)).unwrap();
        assert_eq!(code, expected, "{method} {path}: {body}");
        if expected != 200 {
            assert!(body["error"].is_string());
        }
        assert_eq!(
            serde_json::to_value(self.engine().status().unwrap()).unwrap(),
            before,
            "Names route changed archive coverage/evidence"
        );
        assert_eq!(
            self.source.calls(),
            source_calls,
            "Names route called the chain source"
        );
        body
    }
    fn cleanup(&mut self) -> Result<(), String> {
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
            return Err("Service shutdown/join exceeded harness cleanup bound".into());
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
        assert!(
            TcpStream::connect_timeout(&self.address, Duration::from_millis(200)).is_err(),
            "Service listener remains open"
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("bounded Service cleanup: {error}");
        }
        // Rust cannot kill a timed-out worker thread. The owning host subprocess
        // is supervised below; abnormal termination is not a normal Service join.
    }
}

fn status(session: &Session, seed: &Seed) -> NamesStatus {
    let body = session.call("GET", &seed.base(), &auth(), 200);
    let status: NamesStatus = serde_json::from_value(body.clone()).unwrap();
    // Shared public DTO, without a separate client implementation or wire shape.
    let client: urma_node_client::names::NamesStatus =
        serde_json::from_value(body.clone()).unwrap();
    assert_eq!(value(&client), body);
    assert_eq!(value(&status), body);
    assert_eq!(
        body,
        value(
            session
                .engine()
                .names_status(seed.genesis)
                .unwrap()
                .unwrap()
        )
    );
    status
}
fn resolution(session: &Session, seed: &Seed) -> NamesResolution {
    let body = session.call("GET", &seed.resolve(), &auth(), 200);
    let resolution: NamesResolution = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(value(&resolution), body);
    assert_eq!(
        body,
        value(
            session
                .engine()
                .names_resolve(seed.genesis, &Name::parse("absent").unwrap())
                .unwrap()
        )
    );
    assert_eq!(resolution.resolution, Resolution::Unbound);
    resolution
}
fn register(session: &Session, seed: &Seed) -> NamesStatus {
    let body = session.call(
        "POST",
        &seed.register(),
        &(auth() + "Content-Length: 0\r\n"),
        200,
    );
    let registered: NamesStatus = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(value(&registered), body);
    assert_eq!(
        body,
        value(
            session
                .engine()
                .names_status(seed.genesis)
                .unwrap()
                .unwrap()
        )
    );
    assert_eq!(registered.genesis, seed.genesis);
    assert_eq!(
        registered.genesis_block,
        point(FIRST_HEIGHT, &seed.blocks[0])
    );
    registered
}
fn step(
    session: &Session,
    seed: &Seed,
    applied: Option<ChainPoint>,
    rolled_back: u64,
) -> NamesStep {
    let body = session.call("POST", &seed.step(), &auth(), 200);
    let step: NamesStep = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(value(&step), body);
    assert_eq!(step.applied, applied);
    assert_eq!(step.rolled_back, rolled_back);
    assert!(step.outcomes.is_empty());
    assert_eq!(value(&step.status), value(status(session, seed)));
    step
}
fn unregistered(session: &Session, seed: &Seed) {
    session.call("GET", &seed.base(), &auth(), 404);
    session.call("GET", &seed.resolve(), &auth(), 422);
    session.call("POST", &seed.step(), &auth(), 422);
    assert!(
        session
            .engine()
            .names_status(seed.genesis)
            .unwrap()
            .is_none()
    );
}

fn refusals(control: &Path) {
    let seed = Seed::new(control, 3);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let routes = [
        ("GET", seed.base()),
        ("GET", seed.resolve()),
        ("POST", seed.register()),
        ("POST", seed.step()),
    ];
    for (method, path) in &routes {
        session.call(method, path, "", 401);
        session.call(method, path, "Authorization: Bearer wrong\r\n", 401);
        session.call(method, path, &(auth() + "Content-Length: 1\r\n"), 400);
    }
    // Authentication precedes Names parsing, even for a malformed matched path.
    for (method, path) in [
        ("GET", "/v1/names/not-a-txid/resolve/UPPER"),
        ("POST", "/v1/names/not-a-txid/register?height=bad"),
    ] {
        session.call(method, path, "", 401);
        session.call(method, path, &auth(), 400);
    }
    for id in [
        "".to_owned(),
        "00".repeat(31),
        "00".repeat(33),
        "gg".repeat(32),
        format!("%30{}", "0".repeat(63)),
    ] {
        for (method, suffix) in [
            ("GET", ""),
            ("GET", "/resolve/absent"),
            ("POST", "/step"),
            ("POST", "/register?height=100&hash=00"),
        ] {
            session.call(method, &format!("/v1/names/{id}{suffix}"), &auth(), 400);
        }
    }
    for name in [
        "".to_owned(),
        "Upper".into(),
        "-name".into(),
        "name-".into(),
        "ab--name".into(),
        "a_b".into(),
        "a/b".into(),
        "%61bsent".into(),
        "a".repeat(64),
    ] {
        session.call(
            "GET",
            &format!("{}/resolve/{name}", seed.base()),
            &auth(),
            400,
        );
    }
    let hash = seed.blocks[0].block_hash().to_string();
    let queries = [
        "".to_owned(),
        "height".into(),
        format!("height=100"),
        format!("hash={hash}"),
        format!("height=100&hash={hash}&height=100"),
        format!("height=100&hash={hash}&hash={hash}"),
        format!("height=100&hash={hash}&other=1"),
        format!("Height=100&hash={hash}"),
        format!("height=100&hash={hash}&"),
        format!("height=&hash={hash}"),
        format!("height=-1&hash={hash}"),
        format!("height=+100&hash={hash}"),
        format!("height=100.0&hash={hash}"),
        format!("height=%31&hash={hash}"),
        format!("height=9223372036854775808&hash={hash}"),
        format!("height=18446744073709551616&hash={hash}"),
        "height=100&hash=".into(),
        "height=100&hash=00".into(),
        format!("height=100&hash={}", "gg".repeat(32)),
    ];
    for query in queries {
        session.call(
            "POST",
            &format!("{}/register?{query}", seed.base()),
            &auth(),
            400,
        );
    }
    // Frozen path/method predicate: no implicit query defaults or method alias.
    for (method, path) in [
        ("POST", format!("{}/register", seed.base())),
        ("GET", seed.register()),
        ("GET", seed.step()),
        ("POST", seed.base()),
        ("POST", seed.resolve()),
        ("PUT", seed.step()),
        ("GET", format!("{}/other", seed.base())),
        ("POST", format!("{}/step?extra=1", seed.base())),
    ] {
        session.call(method, &path, &auth(), 404);
    }
    unregistered(&session, &seed);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "auth/syntax/path/refused reads mutated archive"
    );
}

fn registration(control: &Path) {
    let seed = Seed::new(control, 0);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    unregistered(&session, &seed);
    session.call("POST", &seed.register(), &auth(), 409);
    assert!(
        session
            .engine()
            .names_status(seed.genesis)
            .unwrap()
            .is_none()
    );
    assert_eq!(session.engine().status().unwrap().scanned_blocks, 0);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "registration fetched/scanned or partially registered"
    );

    // Scan only genesis explicitly; the HTTP service never provides coverage.
    let session = Session::start(&seed, control);
    session.engine().scan_next().unwrap();
    assert!(session.engine().record(seed.genesis).unwrap().is_some());
    assert!(session.engine().record(seed.non_names).unwrap().is_some());
    session.finish();
    let scanned = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    unregistered(&session, &seed);
    session.call("POST", &seed.register_id(seed.non_names), &auth(), 422);
    let absent = Txid::from_byte_array([77; 32]);
    session.call("POST", &seed.register_id(absent), &auth(), 422);
    let wrong_placement = format!(
        "{}/register?height={}&hash={}",
        seed.base(),
        FIRST_HEIGHT,
        seed.blocks[1].block_hash()
    );
    session.call("POST", &wrong_placement, &auth(), 409);
    assert!(
        session
            .engine()
            .names_status(seed.genesis)
            .unwrap()
            .is_none()
    );
    assert!(
        session
            .engine()
            .names_status(seed.non_names)
            .unwrap()
            .is_none()
    );
    assert!(session.engine().names_status(absent).unwrap().is_none());
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        scanned,
        "eligibility refusal partially registered a registry"
    );

    let session = Session::start(&seed, control);
    let registered = register(&session, &seed);
    assert_eq!(registered.projected, registered.genesis_block);
    assert!(!registered.complete_to_tip);
    // Selected headers alone are not scanned Names evidence: step is a no-op.
    let idle = step(&session, &seed, None, 0);
    assert_eq!(value(&idle.status), value(&registered));
    assert_eq!(session.engine().status().unwrap().scanned_blocks, 1);
    assert_eq!(
        session.engine().status().unwrap().indexed_through,
        Some(registered.genesis_block)
    );
    resolution(&session, &seed);
    session.finish();
    let registered_snapshot = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let alternate_query = format!(
        "{}/register?hash={}&height=000100",
        seed.base(),
        seed.blocks[0].block_hash()
    );
    let repeated = session.call("POST", &alternate_query, &auth(), 200);
    assert_eq!(repeated, value(registered));
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        registered_snapshot,
        "same-registration retry appended state/events"
    );
}

fn one_step(control: &Path) {
    let seed = Seed::new(control, 3);
    let session = Session::start(&seed, control);
    let initial = register(&session, &seed);
    assert_eq!(initial.projected.height, FIRST_HEIGHT);
    assert_eq!(
        initial.selected_tip,
        Some(point(FIRST_HEIGHT + 2, &seed.blocks[2]))
    );
    assert!(!initial.complete_to_tip);
    assert_eq!(value(status(&session, &seed)), value(&initial));
    assert_eq!(value(resolution(&session, &seed).status), value(&initial));
    session.finish();
    let before_reads = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    status(&session, &seed);
    resolution(&session, &seed);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before_reads,
        "GET advanced the registered projection"
    );

    let session = Session::start(&seed, control);
    let first = step(
        &session,
        &seed,
        Some(point(FIRST_HEIGHT + 1, &seed.blocks[1])),
        0,
    );
    assert_eq!(first.status.projected.height, FIRST_HEIGHT + 1);
    assert!(
        !first.status.complete_to_tip,
        "one HTTP step consumed both outstanding blocks"
    );
    assert_eq!(
        value(resolution(&session, &seed).status),
        value(&first.status)
    );
    let second = step(
        &session,
        &seed,
        Some(point(FIRST_HEIGHT + 2, &seed.blocks[2])),
        0,
    );
    assert!(second.status.complete_to_tip);
    assert_eq!(
        value(resolution(&session, &seed).status),
        value(&second.status)
    );
    assert_eq!(session.engine().status().unwrap().scanned_blocks, 3);
    session.finish();
    let at_tip = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let idle = step(&session, &seed, None, 0);
    assert_eq!(value(idle.status), value(second.status));
    resolution(&session, &seed);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        at_tip,
        "at-tip step/read wrote projection state"
    );
}

fn restart_reorg(control: &Path) {
    let seed = Seed::new(control, 3);
    let session = Session::start(&seed, control);
    register(&session, &seed);
    let old = step(
        &session,
        &seed,
        Some(point(FIRST_HEIGHT + 1, &seed.blocks[1])),
        0,
    );
    let old_resolution = value(resolution(&session, &seed));
    session.finish();
    let persisted = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    assert_eq!(value(status(&session, &seed)), value(&old.status));
    assert_eq!(value(resolution(&session, &seed)), old_resolution);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        persisted,
        "restart reads mutated persisted projection"
    );

    // Preserve selected genesis. Orphan only the projected checkpoint so that
    // explicit Names step can reconcile its retained undo, then apply one block.
    let second = witness_block(&[], Some(&seed.blocks[0]), 8202);
    let third = witness_block(&[], Some(&second), 8203);
    let branch = vec![seed.blocks[0].clone(), second, third];
    seed.source.inner.replace_branch(&branch);
    let session = Session::start(&seed, control);
    session.engine().synchronize_headers().unwrap();
    assert!(session.engine().status().unwrap().generation > old.status.generation);
    assert_eq!(session.engine().status().unwrap().scanned_blocks, 1);
    session.finish();
    let stale = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    assert!(matches!(
        session.engine().names_status(seed.genesis),
        Err(Error::Stale)
    ));
    session.call("GET", &seed.base(), &auth(), 409);
    session.call("GET", &seed.resolve(), &auth(), 409);
    // Idempotent registration must not disguise an orphaned projection as fresh.
    session.call("POST", &seed.register(), &auth(), 409);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        stale,
        "stale HTTP reads/register repaired state implicitly"
    );

    let session = Session::start(&seed, control);
    session.engine().scan_next().unwrap();
    session.engine().scan_next().unwrap();
    let recovered = step(
        &session,
        &seed,
        Some(point(FIRST_HEIGHT + 1, &branch[1])),
        1,
    );
    assert_eq!(recovered.status.genesis_block, old.status.genesis_block);
    assert_eq!(
        recovered.status.projected,
        point(FIRST_HEIGHT + 1, &branch[1])
    );
    assert_eq!(
        recovered.status.selected_tip,
        Some(point(FIRST_HEIGHT + 2, &branch[2]))
    );
    assert!(recovered.status.generation > old.status.generation);
    assert!(!recovered.status.complete_to_tip);
    assert_eq!(
        value(resolution(&session, &seed).status),
        value(&recovered.status)
    );
    let complete = step(
        &session,
        &seed,
        Some(point(FIRST_HEIGHT + 2, &branch[2])),
        0,
    );
    assert!(complete.status.complete_to_tip);
    session.finish();
    let repaired = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    assert_eq!(value(status(&session, &seed)), value(complete.status));
    resolution(&session, &seed);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        repaired,
        "repaired restart reads mutated state"
    );
}

#[test]
#[ignore = "owned subprocess host for the Names-service cases"]
fn names_service_host() {
    let control = PathBuf::from(std::env::var_os("U3_NAMES_SERVICE_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("U3_NAMES_SERVICE_CASE").unwrap();
    stage(&control, &format!("seeding actual Engine: {scenario}"));
    match scenario.as_str() {
        "refusals" => refusals(&control),
        "registration" => registration(&control),
        "step" => one_step(&control),
        "restart-reorg" => restart_reorg(&control),
        _ => panic!("unknown owned scenario"),
    }
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
            "names_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_NAMES_SERVICE_TEMP", directory.path())
        .env("U3_NAMES_SERVICE_CASE", scenario)
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

#[test]
fn names_http_auth_syntax_and_frozen_route_predicates_preserve_archive() {
    run("refusals");
}
#[test]
fn names_http_registration_requires_explicit_fully_scanned_signed_genesis() {
    run("registration");
}
#[test]
fn names_http_shared_dtos_reads_and_one_step_preserve_scan_coverage() {
    run("step");
}
#[test]
fn names_http_restart_and_reorg_refuse_stale_checkpoint_until_explicit_step() {
    run("restart-reorg");
}
