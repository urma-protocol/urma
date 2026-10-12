//! Linux Service scheduling for automatic raw commit-parent acquisition.
//! Genuine public signed vectors in mock-selected witness-authenticated blocks;
//! the commit source is an owned in-memory recorder. No sockets beyond the
//! loopback control surface, no live nodes, no PoW or consensus claim.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Block, Txid};
use common::{MemorySource, SignedPair, config, profile, witness_block};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::{Arc, Mutex, atomic::Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::Retention,
    service::{Service, ShutdownHandle},
    source::{CommitSource, CommitSources},
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
    fn fetch(&self, txid: Txid) -> Result<Option<Vec<u8>>, Error> {
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
        let engine = Arc::new(engine);
        let mut service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap();
        if let Some(source) = source {
            service = service.with_commit_sources(single(source)).unwrap();
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
