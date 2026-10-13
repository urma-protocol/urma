//! Linux Service scheduling for automatic raw commit-parent acquisition.
//! Genuine public signed vectors in mock-selected witness-authenticated blocks;
//! the commit source is an owned in-memory recorder or a loopback RPC stub.
//! No live nodes, no PoW or consensus claim.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Block, BlockHash, Txid, block::Header};
use common::{MemorySource, SignedPair, config, profile, witness_block};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::{ChainPoint, Retention, ServiceStatus},
    service::{Service, ShutdownHandle},
    source::{ChainSource, CommitSource, CommitSources, LocalRpcCommitSource},
};
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const LABEL: &str = "owned in-memory recording parent source";
const FAILURE: &str = "scripted parent source failure";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_TIMEOUT: Duration = Duration::from_secs(15);
// One worker round sleeps 20 x 100 ms; waiting longer covers a whole round.
const ROUND: Duration = Duration::from_millis(2500);

type Requests = Arc<Mutex<Vec<Txid>>>;
// Answers the first `failures` fetches with an owned error, then exact bytes.
#[derive(Clone)]
struct Recording {
    chain: Chain,
    raw: Vec<u8>,
    failures: usize,
    requests: Requests,
}
impl Recording {
    fn new(chain: Chain, raw: &[u8], failures: usize) -> Self {
        Self {
            chain,
            raw: raw.to_vec(),
            failures,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn requests(&self) -> Vec<Txid> {
        self.requests.lock().unwrap().clone()
    }
}
impl CommitSource for Recording {
    fn chain(&self) -> Chain {
        self.chain
    }
    fn fetch(&self, txid: Txid, _cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(txid);
        if requests.len() <= self.failures {
            return Err(Error::Busy(FAILURE.into()));
        }
        Ok(Some(self.raw.clone()))
    }
}

fn request(method: &str, path: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
    )
}

// Absolute bounds apply to this test client's I/O, not to Engine operations.
fn http(address: SocketAddr, request: &str) -> io::Result<(u16, Value)> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    stream.set_write_timeout(Some(remaining()?))?;
    stream.write_all(request.as_bytes())?;
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
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| io::Error::other("missing response length"))?
        .1
        .trim()
        .parse::<usize>()
        .map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("test response body limit"));
    }
    let mut body = vec![0; length];
    stream.set_read_timeout(Some(remaining()?))?;
    stream.read_exact(&mut body)?;
    Ok((
        code,
        serde_json::from_slice(&body).map_err(io::Error::other)?,
    ))
}

fn status(address: SocketAddr) -> Value {
    let (code, status) = http(address, &request("GET", "/v1/status")).unwrap();
    assert_eq!(code, 200, "{status}");
    status
}

// Indexing a missing JSON key also yields null; the contract fields must exist.
fn single(source: &Recording) -> CommitSources {
    let mut sources = CommitSources::new(source.chain());
    sources.push(LABEL.into(), Box::new(source.clone()));
    sources
}

fn field<'a>(status: &'a Value, key: &str) -> &'a Value {
    status
        .get(key)
        .unwrap_or_else(|| panic!("status lacks {key}: {status}"))
}

fn poll(address: SocketAddr, what: &str, accept: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        let current = status(address);
        if accept(&current) {
            return current;
        }
        assert!(Instant::now() < deadline, "{what} not observed: {current}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn scanned(status: &Value) -> u64 {
    status["archive"]["scanned_blocks"].as_u64().unwrap()
}

fn unresolved(status: &Value) -> u64 {
    status["archive"]["unresolved_dependencies"]
        .as_u64()
        .unwrap()
}

fn dependency_error(status: &Value) -> Option<String> {
    field(status, "last_dependency_error")
        .as_str()
        .map(str::to_owned)
}

struct Running {
    address: SocketAddr,
    handle: ShutdownHandle,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}
impl Running {
    fn start(engine: Engine, source: Option<&Recording>, synchronize: bool) -> Self {
        Self::with_sources(engine, source.map(single), synchronize)
    }
    fn with_sources(engine: Engine, sources: Option<CommitSources>, synchronize: bool) -> Self {
        let engine = Arc::new(engine);
        let mut service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap();
        if let Some(sources) = sources {
            service = service.with_commit_sources(sources).unwrap();
        }
        let address = service.address().unwrap();
        let handle = service.shutdown_handle();
        let worker = thread::spawn(move || service.run(synchronize));
        Self {
            address,
            handle,
            engine: Some(engine),
            worker: Some(worker),
        }
    }
    // Authenticated shutdown, bounded normal join, then sole Engine ownership.
    fn finish(mut self) -> Engine {
        let (code, body) = http(self.address, &request("POST", "/v1/shutdown")).unwrap();
        assert_eq!((code, body), (200, json!({"stopping":true})));
        self.join().unwrap();
        let engine = self.engine.take().unwrap();
        Arc::into_inner(engine).expect("Service retained Engine after joined run")
    }
    fn join(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + JOIN_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service normal join exceeded harness bound".to_owned());
        }
        worker
            .join()
            .map_err(|_| "Service panicked".to_owned())?
            .map_err(|e| e.to_string())
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.handle.request();
        if let Err(error) = self.join() {
            eprintln!("service cleanup: {error}");
        }
    }
}

// First block carries a reveal whose commit parent is in no block; `empty`
// further blocks follow it so later rounds still have scanning to do.
fn fixture(directory: &Path, pair: &SignedPair, empty: u32) -> (Engine, Arc<MemorySource>) {
    let mut blocks: Vec<Block> = vec![witness_block(std::slice::from_ref(&pair.reveal), None, 31)];
    for nonce in 0..empty {
        blocks.push(witness_block(&[], blocks.last(), 32 + nonce));
    }
    let chain = Arc::new(MemorySource::new(&blocks));
    let engine = Engine::open(
        directory,
        config(&blocks[0], Retention::Unpruned),
        Some(chain.clone()),
    )
    .unwrap();
    (engine, chain)
}

fn assert_resolved_record(engine: &Engine, pair: &SignedPair) {
    let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
    assert_eq!(record.package.commit, pair.raw_commit);
    assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
}

#[test]
fn synchronizing_round_fetches_exactly_the_missing_parent_and_reports_label() {
    let pair = profile();
    let directory = tempfile::tempdir().unwrap();
    let (engine, _chain) = fixture(directory.path(), &pair, 0);
    let source = Recording::new(Chain::BitcoinRegtest, &pair.raw_commit, 0);
    let running = Running::start(engine, Some(&source), true);
    let done = poll(running.address, "scan plus resolved parent", |s| {
        scanned(s) == 1 && unresolved(s) == 0
    });
    assert_eq!(field(&done, "commit_sources")[0]["label"], json!(LABEL));
    assert_eq!(dependency_error(&done), None);
    assert!(field(&done, "last_sync_error").is_null(), "{done}");
    assert!(
        !done["archive"]["indexed_through"].is_null(),
        "resolved parent did not advance the contiguous prefix: {done}"
    );
    // Later rounds have nothing pending and must not refetch.
    thread::sleep(ROUND);
    let later = status(running.address);
    assert_eq!(unresolved(&later), 0);
    assert_eq!(dependency_error(&later), None);
    let engine = running.finish();
    assert_eq!(source.requests(), vec![pair.commit.compute_txid()]);
    assert_resolved_record(&engine, &pair);
}

#[test]
fn failing_source_error_is_reported_while_scanning_progresses_then_cleared() {
    let pair = profile();
    let directory = tempfile::tempdir().unwrap();
    let (engine, _chain) = fixture(directory.path(), &pair, 2);
    let source = Recording::new(Chain::BitcoinRegtest, &pair.raw_commit, 2);
    let running = Running::start(engine, Some(&source), true);
    for blocks in [1, 2] {
        let failed = poll(running.address, "stored dependency error", |s| {
            scanned(s) == blocks && dependency_error(s).is_some()
        });
        assert!(
            dependency_error(&failed).unwrap().contains(FAILURE),
            "{failed}"
        );
        assert_eq!(unresolved(&failed), 1);
        assert!(field(&failed, "last_sync_error").is_null(), "{failed}");
        assert_eq!(field(&failed, "commit_sources")[0]["label"], json!(LABEL));
    }
    let done = poll(running.address, "cleared error and resolved parent", |s| {
        unresolved(s) == 0 && dependency_error(s).is_none()
    });
    assert_eq!(scanned(&done), 3, "dependency resolved before third scan");
    assert!(field(&done, "last_sync_error").is_null(), "{done}");
    let engine = running.finish();
    let missing = pair.commit.compute_txid();
    assert_eq!(source.requests(), vec![missing, missing, missing]);
    assert_resolved_record(&engine, &pair);
}

#[test]
fn offline_run_never_calls_configured_source_but_reports_its_label() {
    let pair = profile();
    let directory = tempfile::tempdir().unwrap();
    let (engine, chain) = fixture(directory.path(), &pair, 0);
    engine.synchronize_headers().unwrap();
    assert_eq!(engine.scan_next().unwrap().unresolved_dependencies, 1);
    let chain_calls = (
        chain.body_calls.load(Ordering::Relaxed),
        chain.header_calls.load(Ordering::Relaxed),
    );
    let source = Recording::new(Chain::BitcoinRegtest, &pair.raw_commit, 0);
    let running = Running::start(engine, Some(&source), false);
    let first = status(running.address);
    thread::sleep(ROUND);
    let second = status(running.address);
    for current in [&first, &second] {
        assert_eq!(field(current, "commit_sources")[0]["label"], json!(LABEL));
        assert_eq!(dependency_error(current), None);
        assert_eq!(unresolved(current), 1);
        assert_eq!(scanned(current), 1);
    }
    assert_eq!(first["archive"], second["archive"]);
    let engine = running.finish();
    assert!(source.requests().is_empty(), "run(false) fetched a parent");
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
    assert_eq!(
        (
            chain.body_calls.load(Ordering::Relaxed),
            chain.header_calls.load(Ordering::Relaxed),
        ),
        chain_calls,
        "run(false) touched the chain source"
    );
}

// A chain source that reports connected peers, as the Litecoin source does.
struct Peered(Arc<MemorySource>);
impl ChainSource for Peered {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.0.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.0.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.0.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.0.block(height)
    }
    fn chain_peers(&self) -> Result<u64, Error> {
        Ok(3)
    }
}

#[test]
fn status_reports_chain_peers_from_the_source_and_zero_offline() {
    let block = witness_block(&[], None, 41);
    let memory = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    let peered: Arc<dyn ChainSource> = Arc::new(Peered(memory.clone()));
    let plain: Arc<dyn ChainSource> = memory;
    for (source, expected) in [(None, 0), (Some(plain), 0), (Some(peered), 3)] {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&block, Retention::Unpruned);
        let engine = Engine::open(directory.path(), config, source).unwrap();
        let running = Running::start(engine, None, false);
        let mut current = status(running.address);
        assert_eq!(
            field(&current, "chain_peers"),
            &json!(expected),
            "{current}"
        );
        let typed: ServiceStatus = serde_json::from_value(current.clone()).unwrap();
        assert_eq!(typed.chain_peers, expected);
        current.as_object_mut().unwrap().remove("chain_peers");
        let older: ServiceStatus = serde_json::from_value(current).unwrap();
        assert_eq!(older.chain_peers, 0);
        running.finish();
    }
}

const COOKIE: &str = "__cookie__:5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5";
const MISSING_COOKIE: &str = "commit source: cookie file missing: litecoind not running?";

// Loopback stand-in for a cookie-authenticated litecoind with txindex.
struct Rpc {
    address: SocketAddr,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Rpc {
    fn start(parent: Txid, raw: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (calls, stop) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicBool::new(false)),
        );
        let (log, halted) = (calls.clone(), stop.clone());
        let thread = thread::spawn(move || {
            while !halted.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => answer(stream, &log, parent, &raw).unwrap(),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("rpc stub accept: {error}"),
                }
            }
        });
        Self {
            address,
            calls,
            stop,
            thread: Some(thread),
        }
    }
    fn url(&self) -> String {
        format!("http://{}/", self.address)
    }
    fn count(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|m| *m == method)
            .count()
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn answer(
    mut stream: TcpStream,
    calls: &Mutex<Vec<String>>,
    parent: Txid,
    raw: &[u8],
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).map_err(io::Error::other)?;
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .ok_or_else(|| io::Error::other("missing content length"))?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let request: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
    let method = request["method"].as_str().unwrap_or_default().to_owned();
    calls.lock().unwrap().push(method.clone());
    let genesis = Chain::BitcoinRegtest.genesis().unwrap().0.to_string();
    let (result, error) = match method.as_str() {
        "getblockhash" => (json!(genesis), Value::Null),
        "getindexinfo" => (
            json!({"txindex": {"synced": true, "best_block_height": 1}}),
            Value::Null,
        ),
        "getblockcount" => (json!(1), Value::Null),
        "getrawtransaction" if request["params"] == json!([parent, false]) => {
            (json!(hex::encode(raw)), Value::Null)
        }
        _ => (
            Value::Null,
            json!({"code": -5, "message": "No such mempool or blockchain transaction."}),
        ),
    };
    let reply =
        serde_json::to_vec(&json!({"result": result, "error": error, "id": request["id"]}))?;
    let status = if error.is_null() {
        "200 OK"
    } else {
        "500 Internal Server Error"
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.len()
    )?;
    stream.write_all(&reply)?;
    stream.flush()
}

fn local_error(sources: &CommitSources) -> Option<String> {
    sources.status().unwrap()[0].last_error.clone()
}

#[test]
fn local_rpc_comes_and_goes_with_its_cookie_and_falls_through_while_away() {
    let pair = profile();
    let parent = pair.commit.compute_txid();
    let rpc = Rpc::start(parent, pair.raw_commit.clone());
    let directory = tempfile::tempdir().unwrap();
    let cookie = directory.path().join("rpc.cookie");
    let local = LocalRpcCommitSource::new(Chain::BitcoinRegtest, rpc.url(), cookie.clone());
    let backup = Recording::new(Chain::BitcoinRegtest, &pair.raw_commit, 0);
    let mut sources = CommitSources::new(Chain::BitcoinRegtest);
    sources.push(
        "local-rpc".into(),
        Box::new(local.with_probe_interval(Duration::ZERO)),
    );
    sources.push(LABEL.into(), Box::new(backup.clone()));
    let running = AtomicBool::new(false);
    // litecoind down: probe and lookup report the cookie; the backup serves.
    assert_eq!(local_error(&sources).as_deref(), Some(MISSING_COOKIE));
    assert_eq!(
        sources.fetch(parent, &running).unwrap(),
        Some(pair.raw_commit.clone())
    );
    assert_eq!(backup.requests(), vec![parent]);
    // litecoind up: the next probe clears the error and lookups use it.
    fs::write(&cookie, COOKIE).unwrap();
    assert_eq!(local_error(&sources), None);
    assert_eq!(
        sources.fetch(parent, &running).unwrap(),
        Some(pair.raw_commit.clone())
    );
    assert_eq!(backup.requests().len(), 1, "local-rpc served the parent");
    assert_eq!(rpc.count("getrawtransaction"), 1);
    // litecoind down again: the error returns and lookups fall through.
    fs::remove_file(&cookie).unwrap();
    assert_eq!(local_error(&sources).as_deref(), Some(MISSING_COOKIE));
    assert_eq!(
        sources.fetch(parent, &running).unwrap(),
        Some(pair.raw_commit.clone())
    );
    assert_eq!(backup.requests().len(), 2);
    // One verification for the one cookie that existed; probes are cheap.
    assert_eq!(rpc.count("getindexinfo"), 1);
    assert!(rpc.count("getblockcount") >= 1);
}

#[test]
fn service_status_flips_local_rpc_within_one_probe() {
    let pair = profile();
    let rpc = Rpc::start(pair.commit.compute_txid(), pair.raw_commit.clone());
    let directory = tempfile::tempdir().unwrap();
    let (engine, _chain) = fixture(&directory.path().join("archive"), &pair, 0);
    let cookie = directory.path().join("rpc.cookie");
    let local = LocalRpcCommitSource::new(Chain::BitcoinRegtest, rpc.url(), cookie.clone())
        .with_probe_interval(Duration::from_millis(100));
    let mut sources = CommitSources::new(Chain::BitcoinRegtest);
    sources.push("local-rpc".into(), Box::new(local));
    let running = Running::with_sources(engine, Some(sources), false);
    let entry = |s: &Value| field(s, "commit_sources")[0].clone();
    let first = status(running.address);
    assert_eq!(entry(&first)["label"], json!("local-rpc"), "{first}");
    assert_eq!(
        entry(&first)["last_error"],
        json!(MISSING_COOKIE),
        "{first}"
    );
    fs::write(&cookie, COOKIE).unwrap();
    poll(running.address, "local-rpc ok", |s| {
        entry(s)["last_error"].is_null()
    });
    fs::remove_file(&cookie).unwrap();
    poll(running.address, "local-rpc error again", |s| {
        entry(s)["last_error"] == json!(MISSING_COOKIE)
    });
    running.finish();
}

#[test]
fn wrong_chain_commit_source_is_refused_at_configuration_without_fetching() {
    let pair = profile();
    let directory = tempfile::tempdir().unwrap();
    let (engine, _chain) = fixture(directory.path(), &pair, 0);
    let engine = Arc::new(engine);
    let wrong = Recording::new(Chain::LitecoinTestnet, &pair.raw_commit, 0);
    let service = Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.into(),
        Arc::clone(&engine),
    )
    .unwrap();
    assert!(matches!(
        service.with_commit_sources(single(&wrong)),
        Err(Error::Invalid(_))
    ));
    assert!(wrong.requests().is_empty(), "refused source was fetched");
    let right = Recording::new(Chain::BitcoinRegtest, &pair.raw_commit, 0);
    let service = Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.into(),
        Arc::clone(&engine),
    )
    .unwrap();
    assert!(service.with_commit_sources(single(&right)).is_ok());
    assert!(
        right.requests().is_empty(),
        "configuration fetched a parent"
    );
    assert!(
        Arc::into_inner(engine).is_some(),
        "refused Service kept Engine"
    );
}
