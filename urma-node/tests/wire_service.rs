//! Actual Service.run(false) Wire pages over owned loopback/TEMP archives.
//! Public signatures and witness inclusion are real; branch selection is an
//! explicit fixture, not a PoW, script, UTXO or regtest consensus claim.
//! Process supervision bounds abnormal cleanup, not hard cancellation of I/O.
#[allow(dead_code)]
mod common;

use bitcoin::{Block, BlockHash, block::Header, consensus::serialize};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive, witness_block,
};
use rusqlite::types::Value as SqlValue;
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
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, ChainPoint, RecordPackage, Retention},
    projection::{WireCursor, WirePage},
    service::Service,
    source::ChainSource,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);

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
    fn bodies(&self) -> usize {
        self.inner.body_calls.load(Ordering::Relaxed)
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

fn package(block: &Block, height: u64, position: u32, pair: &SignedPair) -> RecordPackage {
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(height, block),
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

struct Seed {
    directory: PathBuf,
    config: ArchiveConfig,
    profile: SignedPair,
    post: SignedPair,
    blocks: Vec<Block>,
    source: Arc<CountedSource>,
}

impl Seed {
    fn new(control: &Path, split: bool, admit_post: bool) -> Self {
        let profile = profile();
        let post = SignedPair::load("proof-post");
        let blocks = if split {
            let root = witness_block(&profile.transactions(), None, 7301);
            let tail = witness_block(&post.transactions(), Some(&root), 7302);
            vec![root, tail]
        } else {
            vec![witness_block(
                &[profile.transactions(), post.transactions()].concat(),
                None,
                7301,
            )]
        };
        let source = Arc::new(CountedSource::new(&blocks));
        let directory = control.join("archive");
        let config = config(&blocks[0], Retention::Pruned);
        let engine = Engine::open(&directory, config.clone(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        engine
            .admit_record(package(&blocks[0], FIRST_HEIGHT, 2, &profile))
            .unwrap();
        let seed = Self {
            directory,
            config,
            profile,
            post,
            blocks,
            source,
        };
        if admit_post {
            engine.admit_record(seed.post_package()).unwrap();
        }
        assert_eq!(engine.status().unwrap().scanned_blocks, 0);
        assert!(engine.status().unwrap().indexed_through.is_none());
        assert_eq!(seed.source.bodies(), 0);
        drop(engine);
        seed
    }
    fn post_package(&self) -> RecordPackage {
        let split = self.blocks.len() == 2;
        package(
            &self.blocks[usize::from(split)],
            FIRST_HEIGHT + u64::from(split),
            if split { 2 } else { 4 },
            &self.post,
        )
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
            "Wire route changed archive status"
        );
        assert_eq!(
            self.source.calls(),
            source_calls,
            "Wire route called the chain source"
        );
        body
    }
    fn page(&self, path: &str) -> WirePage {
        let body = self.call("GET", path, &auth(), 200);
        let page: WirePage = serde_json::from_value(body).unwrap();
        assert_eq!(
            serde_json::to_value(&page.archive).unwrap(),
            serde_json::to_value(self.engine().status().unwrap()).unwrap()
        );
        page
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

fn exact(
    page: &WirePage,
    index: usize,
    pair: &SignedPair,
    block: &Block,
    height: u64,
    position: u32,
) {
    let record = &page.records[index];
    assert_eq!(record.block_hash, block.block_hash());
    assert_eq!(record.wtxid, pair.reveal.compute_wtxid());
    assert_eq!(
        serde_json::to_value(&record.entry).unwrap(),
        json!({
            "height":height, "position":position, "txid":pair.reveal.compute_txid().to_string(),
            "author":pair.verified.author().to_string(), "record":hex::encode(pair.verified.record_bytes()),
            "return_script":hex::encode(pair.reveal.output[0].script_pubkey.as_bytes()),
        })
    );
    assert_eq!(
        hex::decode(&record.entry.record).unwrap(),
        pair.verified.record_bytes()
    );
}

fn cursor_hex(cursor: &WireCursor) -> String {
    let encoded = hex::encode(serde_json::to_vec(cursor).unwrap());
    assert_eq!(
        serde_json::from_slice::<WireCursor>(&hex::decode(&encoded).unwrap()).unwrap(),
        *cursor
    );
    encoded
}
fn continuation(cursor: &WireCursor) -> String {
    format!("/v1/wire?limit=1&cursor={}", cursor_hex(cursor))
}
fn endpoint_cursor(page: &WirePage) -> WireCursor {
    // A terminal page has no `next`; public cursor fields can still represent
    // its endpoint. Late admission/restart must invalidate that old snapshot.
    let entry = &page.records.last().unwrap().entry;
    WireCursor {
        snapshot: page.snapshot.clone(),
        height: entry.height,
        position: entry.position,
    }
}

fn pages(control: &Path) {
    let seed = Seed::new(control, false, true);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let body = session.call("GET", "/v1/wire?limit=1", &auth(), 200);
    let first: WirePage = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(first.records.len(), 1);
    exact(&first, 0, &seed.profile, &seed.blocks[0], FIRST_HEIGHT, 2);
    let encoded = hex::encode(serde_json::to_vec(&body["next"]).unwrap());
    let decoded: WireCursor = serde_json::from_slice(&hex::decode(&encoded).unwrap()).unwrap();
    assert_eq!(Some(&decoded), first.next.as_ref());
    let second = session.page(&format!("/v1/wire?limit=1&cursor={encoded}"));
    assert_eq!(first.snapshot, second.snapshot);
    assert_eq!(second.records.len(), 1);
    exact(&second, 0, &seed.post, &seed.blocks[0], FIRST_HEIGHT, 4);
    assert!(second.next.is_none());
    for page in [&first, &second] {
        assert_eq!(
            page.archive.selected_tip,
            Some(point(FIRST_HEIGHT, &seed.blocks[0]))
        );
        assert_eq!(page.archive.scanned_blocks, 0);
        assert!(page.archive.indexed_through.is_none());
        assert_eq!(page.archive.stored_transactions, 4);
    }
    assert_eq!(session.engine().status().unwrap().scanned_blocks, 0);
    assert_eq!(seed.source.bodies(), 0);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "Wire GET mutated the entire DB"
    );
}

fn late_admission(control: &Path) {
    let seed = Seed::new(control, false, false);
    let session = Session::start(&seed, control);
    let first = session.page("/v1/wire?limit=1");
    assert_eq!(first.records.len(), 1);
    assert!(first.next.is_none());
    let cursor = endpoint_cursor(&first);
    let generation = session.engine().status().unwrap().generation;
    session.engine().admit_record(seed.post_package()).unwrap();
    assert_eq!(session.engine().status().unwrap().generation, generation);
    session.call("GET", &continuation(&cursor), &auth(), 409);
    let fresh = session.page("/v1/wire?limit=128");
    assert_eq!(fresh.records.len(), 2);
    assert_ne!(fresh.snapshot.revision, first.snapshot.revision);
    assert_eq!(fresh.snapshot.instance, first.snapshot.instance);
    exact(&fresh, 0, &seed.profile, &seed.blocks[0], FIRST_HEIGHT, 2);
    exact(&fresh, 1, &seed.post, &seed.blocks[0], FIRST_HEIGHT, 4);
    assert_eq!(fresh.archive.scanned_blocks, 0);
    assert!(fresh.archive.indexed_through.is_none());
    assert_eq!(seed.source.bodies(), 0);
    session.finish();
    // Control archive performs the same admissions without HTTP: every schema
    // and table row must match, including revision/events and raw transactions.
    let expected = Seed::new(&control.join("expected"), false, true);
    assert_eq!(snapshot(&seed.directory), snapshot(&expected.directory));
}

fn lifecycle(control: &Path) {
    let seed = Seed::new(control, true, true);
    let session = Session::start(&seed, control);
    let first = session.page("/v1/wire?limit=1");
    let before_scan = first.next.as_ref().unwrap();
    session.engine().scan_next().unwrap();
    session.call("GET", &continuation(before_scan), &auth(), 409);
    let scanned = session.page("/v1/wire?limit=1");
    assert_eq!(scanned.archive.scanned_blocks, 1);
    assert_eq!(
        scanned.archive.indexed_through,
        Some(point(FIRST_HEIGHT, &seed.blocks[0]))
    );
    let before_reorg = scanned.next.as_ref().unwrap();
    exact(&scanned, 0, &seed.profile, &seed.blocks[0], FIRST_HEIGHT, 2);
    let scanned_tail = session.page(&continuation(before_reorg));
    assert_eq!(scanned_tail.snapshot, scanned.snapshot);
    assert_eq!(scanned_tail.records.len(), 1);
    assert!(scanned_tail.next.is_none());
    exact(
        &scanned_tail,
        0,
        &seed.post,
        &seed.blocks[1],
        FIRST_HEIGHT + 1,
        2,
    );
    let replacement = witness_block(&[], Some(&seed.blocks[0]), 7303);
    seed.source
        .inner
        .replace_branch(&[seed.blocks[0].clone(), replacement.clone()]);
    session.engine().synchronize_headers().unwrap();
    session.call("GET", &continuation(before_reorg), &auth(), 409);
    let selected = session.page("/v1/wire?limit=128");
    assert_eq!(selected.records.len(), 1);
    assert!(selected.next.is_none());
    assert_eq!(selected.archive.generation, first.archive.generation + 1);
    assert_eq!(
        selected.archive.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    assert_eq!(selected.archive.stored_transactions, 4); // Orphan raw evidence remains.
    exact(
        &selected,
        0,
        &seed.profile,
        &seed.blocks[0],
        FIRST_HEIGHT,
        2,
    );
    assert!(
        session
            .engine()
            .record(seed.post.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    let before_restart = endpoint_cursor(&selected);
    session.finish();
    let before = snapshot(&seed.directory);
    assert_eq!(before.tables["records"].len(), 2);
    assert_eq!(before.tables["transactions"].len(), 4);
    let session = Session::start(&seed, control);
    session.call("GET", &continuation(&before_restart), &auth(), 409);
    let restarted = session.page("/v1/wire?limit=128");
    assert_eq!(
        serde_json::to_value(&restarted.records).unwrap(),
        serde_json::to_value(&selected.records).unwrap()
    );
    assert_eq!(restarted.snapshot.revision, selected.snapshot.revision);
    assert_ne!(restarted.snapshot.instance, selected.snapshot.instance);
    assert_eq!(
        serde_json::to_value(&restarted.archive).unwrap(),
        serde_json::to_value(&selected.archive).unwrap()
    );
    assert_eq!(seed.source.bodies(), 1);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "restart/read-only Wire GET changed DB"
    );
}

fn refusals(control: &Path) {
    let seed = Seed::new(control, false, true);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let path = "/v1/wire?limit=1";
    session.call("GET", path, "", 401);
    session.call("GET", path, "Authorization: Bearer wrong\r\n", 401);
    session.call("GET", "/v1/wire?limit=0", "", 401);
    for extra in [
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "authorization: Bearer duplicate\r\n",
    ] {
        session.call("GET", path, &(auth() + extra), 400);
    }
    let first = session.page(path);
    let valid_cursor = cursor_hex(first.next.as_ref().unwrap());
    let mut invalid = vec![
        "".to_owned(),
        "limit".into(),
        "limit=".into(),
        "limit=0".into(),
        "limit=129".into(),
        "limit=-1".into(),
        "limit=+1".into(),
        "limit=1.0".into(),
        "limit=4294967296".into(),
        "limit=1&limit=1".into(),
        "limit=1&unknown=1".into(),
        "limit=1&".into(),
        "Limit=1".into(),
        "cursor=00".into(),
        "limit=1&cursor=".into(),
        "limit=1&cursor=0".into(),
        "limit=1&cursor=gg".into(),
        "limit=1&cursor=7b".into(),
        "limit=1&cursor=%7B".into(),
        format!("limit=1&cursor={}", hex::encode(b"{}")),
        format!("limit=1&cursor={valid_cursor}&cursor={valid_cursor}"),
        format!("limit=1&cursor={}", "00".repeat(513)),
    ];
    for mutate in 0..4 {
        let mut cursor = serde_json::to_value(first.next.as_ref().unwrap()).unwrap();
        match mutate {
            0 => cursor["extra"] = true.into(),
            1 => cursor["snapshot"]["instance"] = "short".into(),
            2 => cursor["snapshot"]["instance"] = "g".repeat(32).into(),
            3 => cursor["height"] = (i64::MAX as u64 + 1).into(),
            _ => unreachable!(),
        }
        invalid.push(format!(
            "limit=1&cursor={}",
            hex::encode(serde_json::to_vec(&cursor).unwrap())
        ));
    }
    for query in invalid {
        session.call("GET", &format!("/v1/wire?{query}"), &auth(), 400);
    }
    // Frozen predicate: GET with the literal /v1/wire? prefix, no default limit
    // or alternate-method/path alias silently routed into this view.
    session.call("GET", "/v1/wire", &auth(), 404);
    session.call("GET", "/v1/wire-other?limit=1", &auth(), 404);
    session.call("POST", path, &auth(), 404);
    let fresh = session.page("/v1/wire?limit=128");
    assert_eq!(fresh.records.len(), 2);
    assert_eq!(fresh.snapshot, first.snapshot);
    assert_eq!(fresh.archive.scanned_blocks, 0);
    assert!(fresh.archive.indexed_through.is_none());
    assert_eq!(seed.source.bodies(), 0);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "query/auth/body refusals changed DB"
    );
}

#[test]
#[ignore = "owned subprocess host for the Wire-service cases"]
fn wire_service_host() {
    let control = PathBuf::from(std::env::var_os("U3_WIRE_SERVICE_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("U3_WIRE_SERVICE_CASE").unwrap();
    stage(&control, &format!("seeding actual Engine: {scenario}"));
    match scenario.as_str() {
        "pages" => pages(&control),
        "late-admission" => late_admission(&control),
        "lifecycle" => lifecycle(&control),
        "refusals" => refusals(&control),
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
                assert!(exit.success(), "Wire host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                assert_eq!(report["scenario"], scenario);
                assert_eq!(report["normal_service_joins_returned"], true);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Wire host exceeded 45s; kill/reap is abnormal cleanup, not a normal Service join; {}",
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
                    eprintln!("Wire host cleanup/reap exceeded bound: {result:?}");
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
            "wire_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_WIRE_SERVICE_TEMP", directory.path())
        .env("U3_WIRE_SERVICE_CASE", scenario)
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
fn wire_http_pages_preserve_exact_signed_entries_without_scan_source_calls_or_db_writes() {
    run("pages");
}
#[test]
fn wire_http_late_admission_invalidates_cursor_without_generation_change() {
    run("late-admission");
}
#[test]
fn wire_http_scan_reorg_restart_invalidate_cursors_and_keep_only_selected_entries() {
    run("lifecycle");
}
#[test]
fn wire_http_auth_body_query_and_predicate_refusals_preserve_the_archive() {
    run("refusals");
}
