//! Linux ordered commit-parent source chains, directly and through a running
//! Service. Genuine public signed vectors in mock-selected witness-authenticated
//! blocks; every chained entry is an owned in-memory recorder. The public
//! source is only constructed, never fetched: no provider is ever contacted.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Block, Txid};
use common::{
    MemorySource, SignedPair, config, profile, readonly_archive, stored_bytes, witness_block,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::{CommitSourceStatus, Retention},
    service::{Service, ShutdownHandle},
    source::{CommitSource, CommitSources, PublicCommitSource},
};
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_TIMEOUT: Duration = Duration::from_secs(15);
const CANCELLED: &str = "dependency acquisition cancelled";
const MISMATCH: &str = "commit parent bytes do not match the requested TXID";

// Socket accounting reads process-wide descriptors, so this binary's cases
// never overlap. A failed case must not poison the others.
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

type Log = Arc<Mutex<Vec<(String, Txid)>>>;
#[derive(Clone, Copy)]
enum Reply {
    Serve,
    Absent,
    Fail,
    // Valid bytes of an unrelated transaction, never the requested parent.
    Wrong,
    // Raise the shared cancellation flag, then report absence.
    Cancel,
}
// Fails its first `failures` fetches, then answers `then`. Every call is
// appended to a log shared by all entries of one chain, preserving order.
struct Entry {
    label: String,
    chain: Chain,
    raws: BTreeMap<Txid, Vec<u8>>,
    failures: usize,
    then: Reply,
    calls: Mutex<usize>,
    log: Log,
}
impl CommitSource for Entry {
    fn chain(&self) -> Chain {
        self.chain
    }
    fn fetch(&self, txid: Txid, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        self.log.lock().unwrap().push((self.label.clone(), txid));
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        let reply = if *calls <= self.failures {
            Reply::Fail
        } else {
            self.then
        };
        match reply {
            Reply::Serve => Ok(self.raws.get(&txid).cloned()),
            Reply::Absent => Ok(None),
            Reply::Fail => Err(Error::Busy(failure(&self.label))),
            Reply::Wrong => Ok(Some(stranger())),
            Reply::Cancel => {
                cancelled.store(true, Ordering::Release);
                Ok(None)
            }
        }
    }
}

// A genuine signed commit that no fixture block in this file spends.
fn stranger() -> Vec<u8> {
    SignedPair::load("multipart/one-leaf").raw_commit
}

fn failure(label: &str) -> String {
    format!("{label} scripted parent failure")
}

fn shown(label: &str) -> String {
    Error::Busy(failure(label)).to_string()
}

fn raws(pairs: &[SignedPair]) -> BTreeMap<Txid, Vec<u8>> {
    pairs
        .iter()
        .map(|pair| (pair.commit.compute_txid(), pair.raw_commit.clone()))
        .collect()
}

fn entry(chain: Chain, pairs: &[SignedPair], spec: (&str, usize, Reply), log: &Log) -> Entry {
    let (label, failures, then) = spec;
    Entry {
        label: label.to_owned(),
        chain,
        raws: raws(pairs),
        failures,
        then,
        calls: Mutex::new(0),
        log: Arc::clone(log),
    }
}

fn chained(
    chain: Chain,
    pairs: &[SignedPair],
    entries: &[(&str, usize, Reply)],
) -> (CommitSources, Log) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let mut sources = CommitSources::new(chain);
    for spec in entries {
        sources.push(
            spec.0.to_owned(),
            Box::new(entry(chain, pairs, *spec, &log)),
        );
    }
    (sources, log)
}

fn logged(log: &Log) -> Vec<(String, Txid)> {
    log.lock().unwrap().clone()
}

// Every round asks each entry once, in order, for the same missing parent.
fn assert_rounds(log: &[(String, Txid)], labels: &[&str], parent: Txid) {
    for (index, (label, txid)) in log.iter().enumerate() {
        assert_eq!(*txid, parent, "only the missing parent is requested");
        assert_eq!(label, labels[index % labels.len()], "order broke: {log:?}");
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

fn unresolved(status: &Value) -> u64 {
    status["archive"]["unresolved_dependencies"]
        .as_u64()
        .unwrap()
}

// Indexing a missing JSON key also yields null; the contract fields must exist.
fn dependency_error(status: &Value) -> Option<String> {
    status
        .get("last_dependency_error")
        .unwrap_or_else(|| panic!("status lacks last_dependency_error: {status}"))
        .as_str()
        .map(str::to_owned)
}

fn entries(status: &Value) -> Vec<(String, Option<String>)> {
    status
        .get("commit_sources")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("status lacks commit_sources array: {status}"))
        .iter()
        .map(|entry| {
            let error = entry
                .get("last_error")
                .unwrap_or_else(|| panic!("entry lacks last_error: {entry}"));
            (
                entry["label"].as_str().unwrap().to_owned(),
                error.as_str().map(str::to_owned),
            )
        })
        .collect()
}

fn expect(rows: &[(&str, Option<String>)]) -> Vec<(String, Option<String>)> {
    rows.iter()
        .map(|(label, error)| ((*label).to_owned(), error.clone()))
        .collect()
}

// Every recorded error carries its recording time; a cleared one carries none.
fn labelled(rows: Vec<CommitSourceStatus>) -> Vec<(String, Option<String>)> {
    rows.into_iter()
        .map(|row| {
            assert_eq!(row.last_error.is_some(), row.last_error_at.is_some());
            (row.label, row.last_error)
        })
        .collect()
}

struct Running {
    address: SocketAddr,
    handle: ShutdownHandle,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}
impl Running {
    fn start(engine: Engine, sources: CommitSources) -> Self {
        let engine = Arc::new(engine);
        let service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap()
        .with_commit_sources(sources)
        .unwrap();
        let address = service.address().unwrap();
        let handle = service.shutdown_handle();
        let worker = thread::spawn(move || service.run(true));
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

// One block whose reveals all spend commit parents absent from every block.
fn fixture(directory: &Path, pairs: &[SignedPair]) -> Engine {
    let reveals: Vec<_> = pairs.iter().map(|pair| pair.reveal.clone()).collect();
    let block: Block = witness_block(&reveals, None, 41);
    let chain = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
    Engine::open(directory, config(&block, Retention::Unpruned), Some(chain)).unwrap()
}

fn sorted_pairs() -> Vec<SignedPair> {
    let mut pairs = vec![profile(), SignedPair::load("proof-post")];
    pairs.sort_by_key(|pair| pair.commit.compute_txid().to_string());
    pairs
}

fn assert_record(engine: &Engine, pair: &SignedPair) {
    let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
    assert_eq!(record.package.commit, pair.raw_commit);
}

#[test]
fn service_chain_short_circuits_on_first_serving_entry_and_clears_recovered_error() {
    let _serial = serial();
    let pairs = sorted_pairs();
    let (first, second) = (
        pairs[0].commit.compute_txid(),
        pairs[1].commit.compute_txid(),
    );
    let directory = tempfile::tempdir().unwrap();
    let engine = fixture(directory.path(), &pairs);
    let (sources, log) = chained(
        Chain::BitcoinRegtest,
        &pairs,
        &[
            ("A", 1, Reply::Serve),
            ("B", 0, Reply::Serve),
            ("C", 0, Reply::Serve),
        ],
    );
    let running = Running::start(engine, sources);
    let half = poll(running.address, "first parent via B", |s| {
        unresolved(s) == 1
    });
    assert_eq!(
        entries(&half),
        expect(&[("A", Some(shown("A"))), ("B", None), ("C", None)])
    );
    assert_eq!(dependency_error(&half), None, "B served; overall is Ok");
    let done = poll(running.address, "second parent via A", |s| {
        s["archive"]["scanned_blocks"] == json!(1) && unresolved(s) == 0
    });
    assert_eq!(
        entries(&done),
        expect(&[("A", None), ("B", None), ("C", None)]),
        "A's later success clears its stored error"
    );
    assert_eq!(dependency_error(&done), None);
    let engine = running.finish();
    assert_eq!(
        logged(&log),
        vec![
            ("A".to_owned(), first),
            ("B".to_owned(), first),
            ("A".to_owned(), second),
        ],
        "B answered round one so C was never asked; A answered round two alone"
    );
    for pair in &pairs {
        assert_record(&engine, pair);
    }
}

#[test]
fn service_chain_of_absent_entries_asks_each_once_per_round_and_stays_unresolved() {
    let _serial = serial();
    let pair = profile();
    let parent = pair.commit.compute_txid();
    let directory = tempfile::tempdir().unwrap();
    let engine = fixture(directory.path(), std::slice::from_ref(&pair));
    let (sources, log) = chained(
        Chain::BitcoinRegtest,
        std::slice::from_ref(&pair),
        &[("A", 0, Reply::Absent), ("B", 0, Reply::Absent)],
    );
    let running = Running::start(engine, sources);
    // Two complete rounds: each round asks A then B for the same parent.
    let later = poll(running.address, "two absent rounds", |_| {
        logged(&log).len() >= 4
    });
    assert_eq!(unresolved(&later), 1, "absence must not resolve anything");
    assert_eq!(entries(&later), expect(&[("A", None), ("B", None)]));
    assert_eq!(dependency_error(&later), None, "all-absent is Ok(None)");
    let engine = running.finish();
    assert_rounds(&logged(&log), &["A", "B"], parent);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    assert!(engine.record(pair.reveal.compute_txid()).unwrap().is_none());
}

#[test]
fn service_chain_of_failing_entries_reports_every_error_and_shuts_down_cleanly() {
    let _serial = serial();
    let pair = profile();
    let parent = pair.commit.compute_txid();
    let directory = tempfile::tempdir().unwrap();
    let engine = fixture(directory.path(), std::slice::from_ref(&pair));
    let (sources, log) = chained(
        Chain::BitcoinRegtest,
        std::slice::from_ref(&pair),
        &[
            ("A", usize::MAX, Reply::Serve),
            ("B", usize::MAX, Reply::Serve),
        ],
    );
    let running = Running::start(engine, sources);
    let failed = poll(running.address, "overall dependency error", |s| {
        dependency_error(s).is_some()
    });
    assert_eq!(
        entries(&failed),
        expect(&[("A", Some(shown("A"))), ("B", Some(shown("B")))])
    );
    let overall = dependency_error(&failed).unwrap();
    assert!(
        overall.contains(&failure("B")),
        "overall error must carry the last entry's text: {overall}"
    );
    assert_eq!(unresolved(&failed), 1);
    assert!(failed["last_sync_error"].is_null(), "{failed}");
    let engine = running.finish();
    assert_rounds(&logged(&log), &["A", "B"], parent);
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
}

#[test]
fn service_chain_records_wrong_transaction_bytes_and_resolves_through_next_entry() {
    let _serial = serial();
    let pair = profile();
    let parent = pair.commit.compute_txid();
    let directory = tempfile::tempdir().unwrap();
    let engine = fixture(directory.path(), std::slice::from_ref(&pair));
    let (sources, log) = chained(
        Chain::BitcoinRegtest,
        std::slice::from_ref(&pair),
        &[("A", 0, Reply::Wrong), ("B", 0, Reply::Serve)],
    );
    let running = Running::start(engine, sources);
    let done = poll(running.address, "parent via B after A's wrong bytes", |s| {
        s["archive"]["scanned_blocks"] == json!(1) && unresolved(s) == 0
    });
    let rows = entries(&done);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, "A");
    assert_eq!(rows[0].1.as_deref(), Some(MISMATCH), "{done}");
    assert_eq!(rows[1], ("B".to_owned(), None));
    assert_eq!(dependency_error(&done), None, "B served; overall is Ok");
    let engine = running.finish();
    assert_eq!(
        logged(&log),
        vec![("A".to_owned(), parent), ("B".to_owned(), parent)]
    );
    assert_record(&engine, &pair);
    drop(engine);
    let stored = stored_bytes(&readonly_archive(directory.path()));
    assert!(
        stored.values().all(|raw| *raw != stranger()),
        "unverified wrong bytes reached the archive"
    );
    assert_eq!(
        stored[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
}

fn sockets() -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|fd| {
            fs::read_link(fd.path())
                .is_ok_and(|target| target.to_string_lossy().starts_with("socket:"))
        })
        .count()
}

fn bind(engine: &Arc<Engine>) -> Service {
    Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.into(),
        Arc::clone(engine),
    )
    .unwrap()
}

// Direct combinator semantics: order, continue-on-absence/error, overall Err
// only when every entry errored, and per-entry error clearing.
fn direct_chain_semantics(pair: &SignedPair) {
    let idle = AtomicBool::new(false);
    let parent = pair.commit.compute_txid();
    let pairs = std::slice::from_ref(pair);
    let (absent, log) = chained(
        Chain::BitcoinRegtest,
        pairs,
        &[("A", usize::MAX, Reply::Serve), ("B", 0, Reply::Absent)],
    );
    assert_eq!(
        absent.chain().genesis().unwrap().0,
        Chain::BitcoinRegtest.genesis().unwrap().0
    );
    assert!(absent.fetch(parent, &idle).unwrap().is_none());
    assert_eq!(
        labelled(absent.status().unwrap()),
        expect(&[("A", Some(shown("A"))), ("B", None)])
    );
    assert_eq!(logged(&log).len(), 2);
    let (failing, _) = chained(
        Chain::BitcoinRegtest,
        pairs,
        &[
            ("A", usize::MAX, Reply::Serve),
            ("B", usize::MAX, Reply::Serve),
        ],
    );
    let overall = failing.fetch(parent, &idle).unwrap_err().to_string();
    assert!(overall.contains(&failure("B")), "{overall}");
    let (recovering, log) = chained(
        Chain::BitcoinRegtest,
        pairs,
        &[("A", 1, Reply::Serve), ("B", 0, Reply::Serve)],
    );
    assert_eq!(
        recovering.fetch(parent, &idle).unwrap(),
        Some(pair.raw_commit.clone())
    );
    assert_eq!(
        labelled(recovering.status().unwrap()),
        expect(&[("A", Some(shown("A"))), ("B", None)])
    );
    assert_eq!(
        recovering.fetch(parent, &idle).unwrap(),
        Some(pair.raw_commit.clone())
    );
    assert_eq!(
        labelled(recovering.status().unwrap()),
        expect(&[("A", None), ("B", None)])
    );
    let order: Vec<String> = logged(&log).into_iter().map(|(label, _)| label).collect();
    assert_eq!(order, ["A", "B", "A"], "B is skipped once A serves");
}

// Cancellation is checked before every entry and never recorded as an entry
// error; a mismatching Some is that entry's error and the chain moves on.
fn direct_cancel_and_verification(pair: &SignedPair) {
    let parent = pair.commit.compute_txid();
    let pairs = std::slice::from_ref(pair);
    let (precancelled, log) = chained(Chain::BitcoinRegtest, pairs, &[("A", 0, Reply::Serve)]);
    assert!(matches!(
        precancelled.fetch(parent, &AtomicBool::new(true)),
        Err(Error::Busy(message)) if message == CANCELLED
    ));
    assert!(
        logged(&log).is_empty(),
        "pre-cancelled chain asked an entry"
    );
    assert_eq!(
        labelled(precancelled.status().unwrap()),
        expect(&[("A", None)])
    );
    let (midway, log) = chained(
        Chain::BitcoinRegtest,
        pairs,
        &[("A", 0, Reply::Cancel), ("B", 0, Reply::Serve)],
    );
    let flag = AtomicBool::new(false);
    assert!(
        matches!(midway.fetch(parent, &flag), Err(Error::Busy(message)) if message == CANCELLED)
    );
    assert_eq!(
        logged(&log),
        vec![("A".to_owned(), parent)],
        "B asked after cancel"
    );
    assert_eq!(
        labelled(midway.status().unwrap()),
        expect(&[("A", None), ("B", None)])
    );
    let (verified, log) = chained(
        Chain::BitcoinRegtest,
        pairs,
        &[("A", 0, Reply::Wrong), ("B", 0, Reply::Serve)],
    );
    let served = verified.fetch(parent, &AtomicBool::new(false)).unwrap();
    assert_eq!(served, Some(pair.raw_commit.clone()));
    assert_eq!(logged(&log).len(), 2);
    let rows = labelled(verified.status().unwrap());
    assert_eq!(rows[0].1.as_deref(), Some(MISMATCH));
    assert_eq!(rows[1], ("B".to_owned(), None));
}

// A Service without a chain reports an empty array, not null or absence.
fn unconfigured_status(engine: &Arc<Engine>) {
    let service = bind(engine);
    let address = service.address().unwrap();
    let worker = thread::spawn(move || service.run(false));
    let current = status(address);
    assert_eq!(entries(&current), expect(&[]));
    assert_eq!(dependency_error(&current), None);
    let (code, _) = http(address, &request("POST", "/v1/shutdown")).unwrap();
    assert_eq!(code, 200);
    let deadline = Instant::now() + JOIN_TIMEOUT;
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "unconfigured Service join bound");
        thread::sleep(Duration::from_millis(5));
    }
    worker.join().unwrap().unwrap();
}

#[test]
fn configuration_refuses_empty_and_wrong_chain_sets_and_public_source_is_inert() {
    let _serial = serial();
    let pair = profile();
    direct_chain_semantics(&pair);
    direct_cancel_and_verification(&pair);
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(fixture(directory.path(), std::slice::from_ref(&pair)));
    unconfigured_status(&engine);
    assert!(matches!(
        bind(&engine).with_commit_sources(CommitSources::new(Chain::BitcoinRegtest)),
        Err(Error::Invalid(_))
    ));
    let (wrong, log) = chained(
        Chain::LitecoinTestnet,
        std::slice::from_ref(&pair),
        &[("A", 0, Reply::Serve)],
    );
    assert!(matches!(
        bind(&engine).with_commit_sources(wrong),
        Err(Error::Invalid(_))
    ));
    assert!(logged(&log).is_empty(), "refused set was fetched");
    // A matching set chain does not excuse one foreign entry.
    let pairs = std::slice::from_ref(&pair);
    let (mut mixed, log) = chained(Chain::BitcoinRegtest, pairs, &[("A", 0, Reply::Serve)]);
    let foreign = entry(Chain::LitecoinTestnet, pairs, ("B", 0, Reply::Serve), &log);
    mixed.push("B".to_owned(), Box::new(foreign));
    assert!(matches!(
        bind(&engine).with_commit_sources(mixed),
        Err(Error::Invalid(_))
    ));
    assert!(logged(&log).is_empty(), "mixed-chain set was fetched");
    public_source_is_inert();
    assert!(
        Arc::into_inner(engine).is_some(),
        "refused Service kept Engine"
    );
}

// Construction and chaining only: fetch would reach real public providers.
fn public_source_is_inert() {
    let cache = tempfile::tempdir().unwrap();
    let missing = cache.path().join("not-created");
    let baseline = sockets();
    let public = PublicCommitSource::new(Chain::LitecoinTestnet, cache.path().to_path_buf());
    let absent = PublicCommitSource::new(Chain::LitecoinTestnet, missing.clone());
    assert_eq!(
        public.chain().genesis().unwrap().0,
        Chain::LitecoinTestnet.genesis().unwrap().0
    );
    let mut set = CommitSources::new(Chain::LitecoinTestnet);
    set.push("public".to_owned(), Box::new(public));
    set.push("public-missing".to_owned(), Box::new(absent));
    assert_eq!(
        labelled(set.status().unwrap()),
        expect(&[("public", None), ("public-missing", None)])
    );
    assert_eq!(
        sockets(),
        baseline,
        "public source opened a socket before fetch"
    );
    assert_eq!(
        fs::read_dir(cache.path()).unwrap().count(),
        0,
        "cache touched"
    );
    assert!(
        !missing.exists(),
        "construction created its cache directory"
    );
    drop(set);
    assert_eq!(
        fs::read_dir(cache.path()).unwrap().count(),
        0,
        "drop wrote cache"
    );
}
