#[allow(dead_code)]
mod common;

use bitcoin::{Block, BlockHash, Transaction, Txid, block::Header};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, readonly_archive, witness_block,
};
use rusqlite::{Connection, types::Value as SqlValue};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchivedRecord, ChainPoint, ObjectStatus, Retention},
    service::Service,
    source::ChainSource,
};
use urma_runtime::multipart::RecoveryLimits;

const TOKEN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OFFLINE: &str = "node is offline; no chain source configured";
const REFUSED: &str = "U4 fixture permanently refuses block 101";
const START_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(6);
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Graph {
    pairs: Vec<SignedPair>,
}

impl Graph {
    fn load() -> Self {
        Self {
            pairs: ["one-root", "one-leaf", "one-part-0"]
                .into_iter()
                .map(|name| SignedPair::load(&format!("multipart/{name}")))
                .collect(),
        }
    }

    fn root(&self) -> Txid {
        self.pairs[0].reveal.compute_txid()
    }

    fn block(&self) -> Block {
        let transactions: Vec<Transaction> = self
            .pairs
            .iter()
            .flat_map(SignedPair::transactions)
            .collect();
        witness_block(&transactions, None, 8100)
    }

    fn payload_bytes(&self) -> u64 {
        let MultipartRecord::Data(part) = self.pairs[2].verified.decode().unwrap() else {
            panic!("public data fixture")
        };
        part.payload.len() as u64
    }

    fn limits(&self) -> RecoveryLimits {
        RecoveryLimits {
            timeout: Duration::from_secs(2),
            ..RecoveryLimits::new(self.payload_bytes(), self.pairs.len() as u32)
        }
    }
}

// SQL is inspection only, on an owned TEMP archive after its Engine/host exits.
// Object completion may add an object event, but must not change scan evidence.
fn evidence(directory: &Path) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
    let db = readonly_archive(directory);
    let mut snapshot = BTreeMap::new();
    for table in [
        "config",
        "state",
        "headers",
        "selected",
        "scans",
        "locators",
        "transactions",
        "records",
        "dependencies",
        "pins",
        "events",
    ] {
        let predicate = if table == "events" {
            " WHERE kind != 'object'"
        } else {
            ""
        };
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table}{predicate} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get::<_, SqlValue>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        snapshot.insert(table.to_owned(), rows);
    }
    snapshot
}

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

struct Seed {
    temp: tempfile::TempDir,
    archive: PathBuf,
    config: ArchiveConfig,
    status: Value,
    evidence: BTreeMap<String, Vec<Vec<SqlValue>>>,
    graph: Graph,
}

impl Seed {
    fn new(selected_101: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("archive");
        let graph = Graph::load();
        let first = graph.block();
        let config = config(&first, Retention::Unpruned);
        let blocks = if selected_101 {
            vec![first.clone(), witness_block(&[], Some(&first), 8101)]
        } else {
            vec![first.clone()]
        };
        let engine = Engine::open(
            &archive,
            config.clone(),
            Some(Arc::new(MemorySource::new(&blocks))),
        )
        .unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.indexed_through, Some(point(FIRST_HEIGHT, &first)));
        assert_eq!(
            status.selected_tip,
            Some(point(
                if selected_101 { 101 } else { 100 },
                blocks.last().unwrap()
            ))
        );
        assert_eq!(status.unresolved_dependencies, 0);
        assert_eq!(status.stored_transactions, 6);
        assert!(engine.object_status(graph.root()).unwrap().is_none());
        for pair in &graph.pairs {
            assert_eq!(
                engine
                    .record(pair.reveal.compute_txid())
                    .unwrap()
                    .unwrap()
                    .package
                    .reveal
                    .transaction,
                pair.raw_reveal
            );
        }
        let status = serde_json::to_value(status).unwrap();
        drop(engine);
        let evidence = evidence(&archive);
        {
            let db = readonly_archive(&archive);
            assert_eq!(count(&db, "objects"), 0);
            assert_eq!(count(&db, "object_members"), 0);
            assert_eq!(count(&db, "pins"), 0);
        }
        fs::write(
            temp.path().join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        Self {
            temp,
            archive,
            config,
            status,
            evidence,
            graph,
        }
    }

    fn assert_persisted(&self, completed: bool) {
        // Host termination has released the archive lock before these reads.
        let engine = Engine::open(&self.archive, self.config.clone(), None).unwrap();
        assert_eq!(
            serde_json::to_value(engine.status().unwrap()).unwrap(),
            self.status
        );
        let object = engine.object_status(self.graph.root()).unwrap();
        if completed {
            assert_complete(object.unwrap(), self);
        } else {
            assert!(object.is_none());
        }
        drop(engine);
        assert_eq!(evidence(&self.archive), self.evidence);
        let db = readonly_archive(&self.archive);
        assert_eq!(count(&db, "objects"), i64::from(completed));
        assert_eq!(count(&db, "object_members"), if completed { 3 } else { 0 });
        assert_eq!(count(&db, "pins"), 0);
        let events: i64 = db
            .query_row(
                "SELECT count(*) FROM events WHERE kind='object'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(events, i64::from(completed));
    }
}

fn assert_complete(object: ObjectStatus, seed: &Seed) {
    assert_eq!(object.root, seed.graph.root());
    assert_eq!(
        object.verified_generation,
        seed.status["generation"].as_u64().unwrap()
    );
    assert_eq!(object.payload_bytes, seed.graph.payload_bytes());
    assert_eq!(object.members_total, 3);
    assert_eq!(object.members_local, 3);
    assert_eq!(object.members_selected, 3);
    assert!(!object.pinned);
    assert!(object.locally_complete());
    assert!(object.selected_complete());
}

// This is a host for the library Service thread, not a standalone node daemon.
// A Rust thread cannot be forcibly killed: the parent owns the whole test host,
// with bounded kill/reap on every abnormal path (including assertion panic).
struct Host {
    child: Option<Child>,
    directory: PathBuf,
    address: SocketAddr,
    reaped: Arc<AtomicBool>,
}

impl Host {
    fn spawn(seed: &Seed, scenario: &str) -> Self {
        let directory = seed.temp.path().to_owned();
        let stdout = File::create(directory.join("stdout.log")).unwrap();
        let stderr = File::create(directory.join("stderr.log")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "maintenance_worker_host",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("U4_MAINTENANCE_TEMP", &directory)
            .env("U4_MAINTENANCE_SCENARIO", scenario)
            .env("TMPDIR", &directory)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        let mut host = Self {
            child: Some(child),
            directory,
            address: "127.0.0.1:0".parse().unwrap(),
            reaped: Arc::new(AtomicBool::new(false)),
        };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Ok(address) = fs::read_to_string(host.directory.join("address")) {
                if let Ok(address) = address.parse() {
                    host.address = address;
                    break;
                }
            }
            if let Some(exit) = host.child.as_mut().unwrap().try_wait().unwrap() {
                host.reaped.store(true, Ordering::Release);
                panic!("host exited before bind: {exit}; {}", host.logs());
            }
            assert!(
                Instant::now() < deadline,
                "host bind timed out; {}",
                host.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
        host
    }

    fn logs(&self) -> String {
        ["stdout.log", "stderr.log"]
            .map(|name| {
                let mut output = String::new();
                if let Ok(file) = File::open(self.directory.join(name)) {
                    let _ = file.take(64 * 1024).read_to_string(&mut output);
                }
                output
            })
            .join("\n")
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        authenticated: bool,
        deadline: Instant,
    ) -> (u16, Value) {
        let deadline = deadline.min(Instant::now() + HTTP_TIMEOUT);
        let remaining = || {
            let duration = deadline.saturating_duration_since(Instant::now());
            assert!(!duration.is_zero(), "HTTP deadline; {}", self.logs());
            duration
        };
        let mut stream = TcpStream::connect_timeout(&self.address, remaining()).unwrap();
        stream.set_write_timeout(Some(remaining())).unwrap();
        let authorization = if authenticated {
            format!("Authorization: Bearer {TOKEN}\r\n")
        } else {
            String::new()
        };
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 8192, "HTTP header limit");
            stream.set_read_timeout(Some(remaining())).unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let header = std::str::from_utf8(&header).unwrap();
        let status = header
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let length: usize = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .unwrap()
            .1
            .trim()
            .parse()
            .unwrap();
        assert!(length <= 1024 * 1024, "HTTP body limit");
        let mut body = vec![0; length];
        let mut offset = 0;
        while offset < length {
            stream.set_read_timeout(Some(remaining())).unwrap();
            let read = stream.read(&mut body[offset..]).unwrap();
            assert!(read > 0, "truncated HTTP body");
            offset += read;
        }
        let _ = remaining();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn status(&self, seed: &Seed, deadline: Instant) -> Value {
        let (code, status) = self.request("GET", "/v1/status", true, deadline);
        assert_eq!(code, 200);
        assert_eq!(status["archive"], seed.status);
        assert_eq!(status["retention_configured"], true);
        status
    }

    fn finish(mut self) -> Value {
        let (code, response) =
            self.request("POST", "/v1/shutdown", true, Instant::now() + HTTP_TIMEOUT);
        assert_eq!(code, 200);
        assert_eq!(response["stopping"], true);
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.reaped.store(true, Ordering::Release);
                self.child.take();
                assert!(exit.success(), "host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("joined.json")).unwrap())
                        .unwrap();
                assert_eq!(report["joined"], true);
                return report;
            }
            assert!(
                Instant::now() < deadline,
                "host shutdown/join deadline; {}",
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
                Ok(Some(_)) => {
                    self.reaped.store(true, Ordering::Release);
                    return;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => {
                    // Do not cause a second panic while unwinding the test.
                    eprintln!("maintenance host cleanup failed within deadline: {result:?}");
                    return;
                }
            }
        }
    }
}

struct RefusingSource {
    headers: MemorySource,
    refusals: Arc<AtomicUsize>,
}

impl ChainSource for RefusingSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.headers.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.headers.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.headers.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        assert_eq!(
            height,
            FIRST_HEIGHT + 1,
            "worker must not rescan cached block100"
        );
        self.refusals.fetch_add(1, Ordering::Relaxed);
        Err(Error::Invalid(REFUSED.into()))
    }
}

#[test]
#[ignore = "owned subprocess host; invoked only by maintenance_service tests"]
fn maintenance_worker_host() {
    let directory =
        PathBuf::from(std::env::var_os("U4_MAINTENANCE_TEMP").expect("owned TEMP host"));
    let scenario = std::env::var("U4_MAINTENANCE_SCENARIO").unwrap();
    assert!(matches!(
        scenario.as_str(),
        "offline" | "refused" | "disabled"
    ));
    let graph = Graph::load();
    let config: ArchiveConfig =
        serde_json::from_slice(&fs::read(directory.join("config.json")).unwrap()).unwrap();
    let refusals = Arc::new(AtomicUsize::new(0));
    let source: Option<Arc<dyn ChainSource>> = if scenario == "refused" {
        let first = graph.block();
        let second = witness_block(&[], Some(&first), 8101);
        Some(Arc::new(RefusingSource {
            headers: MemorySource::new(&[first, second]),
            refusals: Arc::clone(&refusals),
        }))
    } else {
        None
    };
    let engine = Arc::new(Engine::open(&directory.join("archive"), config, source).unwrap());
    let scratch = directory.join("scratch");
    fs::create_dir(&scratch).unwrap();
    let service = Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.to_owned(),
        Arc::clone(&engine),
    )
    .unwrap()
    .with_retention(scratch, graph.limits())
    .unwrap();
    let address = service.address().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let result = service.run(scenario != "disabled");
        let _ = sender.send(result);
    });
    fs::write(directory.join("address"), address.to_string()).unwrap();
    // Normal shutdown must return AND join the actual Service/worker thread.
    // On a stuck worker, the parent's deadline kills this entire test host.
    receiver
        .recv_timeout(Duration::from_secs(20))
        .expect("Service shutdown deadline")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !handle.is_finished() {
        assert!(Instant::now() < deadline, "Service thread join deadline");
        thread::sleep(Duration::from_millis(10));
    }
    handle.join().unwrap();
    drop(engine);
    fs::write(
        directory.join("joined.json"),
        serde_json::to_vec(&json!({"joined":true,"refusals":refusals.load(Ordering::Relaxed)}))
            .unwrap(),
    )
    .unwrap();
}

fn assert_record_read(host: &Host, seed: &Seed, deadline: Instant) {
    let path = format!("/v1/records/{}", seed.graph.root());
    assert_eq!(host.request("GET", &path, false, deadline).0, 401);
    let (code, record) = host.request("GET", &path, true, deadline);
    assert_eq!(code, 200);
    let record: ArchivedRecord = serde_json::from_value(record).unwrap();
    assert_eq!(record.receipt.txid, seed.graph.root());
    assert_eq!(record.receipt.block, seed.config.application_start);
    assert_eq!(
        record.package.reveal.transaction,
        seed.graph.pairs[0].raw_reveal
    );
    assert_eq!(record.package.commit, seed.graph.pairs[0].raw_commit);
}

fn await_completion(host: &Host, seed: &Seed, expected_error: &str) {
    let deadline = Instant::now() + OBSERVE_TIMEOUT;
    assert_eq!(host.request("GET", "/v1/status", false, deadline).0, 401);
    let object_path = format!("/v1/objects/{}", seed.graph.root());
    assert_eq!(host.request("GET", &object_path, false, deadline).0, 401);
    loop {
        let status = host.status(seed, deadline);
        let (code, object) = host.request("GET", &object_path, true, deadline);
        if code == 200
            && status["last_sync_error"]
                .as_str()
                .is_some_and(|error| error.contains(expected_error))
        {
            assert!(status["last_retention_error"].is_null(), "{status}");
            assert_complete(serde_json::from_value(object).unwrap(), seed);
            assert_record_read(host, seed, deadline);
            break;
        }
        assert!(code == 200 || code == 404, "{object}");
        assert!(
            Instant::now() < deadline,
            "completion timeout; {status}; {}",
            host.logs()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn offline_sync_error_does_not_suppress_cached_object_retention() {
    let seed = Seed::new(false);
    let offline = Engine::open(&seed.archive, seed.config.clone(), None).unwrap();
    let error = offline.synchronize_headers().unwrap_err();
    assert!(matches!(&error, Error::Invalid(message) if message == OFFLINE));
    assert!(offline.object_status(seed.graph.root()).unwrap().is_none());
    assert_eq!(
        serde_json::to_value(offline.status().unwrap()).unwrap(),
        seed.status
    );
    drop(offline);
    let host = Host::spawn(&seed, "offline");
    await_completion(&host, &seed, OFFLINE);
    let report = host.finish();
    assert_eq!(report["refusals"], 0);
    seed.assert_persisted(true);
}

#[test]
fn persistent_scan_error_preserves_coverage_and_still_retains_prior_root() {
    let seed = Seed::new(true);
    let host = Host::spawn(&seed, "refused");
    await_completion(&host, &seed, REFUSED);
    // Observe a second worker opportunity, not just the initial error. The
    // refusal count returned AFTER shutdown proves block101 failed repeatedly.
    let deadline = Instant::now() + Duration::from_millis(2300);
    while Instant::now() < deadline {
        let status = host.status(&seed, Instant::now() + HTTP_TIMEOUT);
        assert!(
            status["last_sync_error"]
                .as_str()
                .unwrap()
                .contains(REFUSED)
        );
        assert!(status["last_retention_error"].is_null());
        thread::sleep(Duration::from_millis(50));
    }
    let report = host.finish();
    assert!(report["refusals"].as_u64().unwrap() >= 2, "{report}");
    seed.assert_persisted(true);
}

#[test]
fn run_false_serves_authentic_cache_without_starting_retention() {
    let seed = Seed::new(false);
    let host = Host::spawn(&seed, "disabled");
    let deadline = Instant::now() + Duration::from_millis(2300);
    let object_path = format!("/v1/objects/{}", seed.graph.root());
    assert_eq!(host.request("GET", "/v1/status", false, deadline).0, 401);
    assert_record_read(&host, &seed, deadline);
    while Instant::now() < deadline {
        let status = host.status(&seed, Instant::now() + HTTP_TIMEOUT);
        assert!(status["last_sync_error"].is_null());
        assert!(status["last_retention_error"].is_null());
        assert_eq!(
            host.request("GET", &object_path, true, Instant::now() + HTTP_TIMEOUT)
                .0,
            404
        );
        thread::sleep(Duration::from_millis(50));
    }
    let report = host.finish();
    assert_eq!(report["refusals"], 0);
    seed.assert_persisted(false);
}

#[test]
fn panic_reaps_service_host_and_releases_archive_lock_within_deadline() {
    let seed = Seed::new(false);
    let host = Host::spawn(&seed, "offline");
    await_completion(&host, &seed, OFFLINE);
    let reaped = Arc::clone(&host.reaped);
    let began = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned_host = host;
        panic!("intentional maintenance test panic");
    }));
    assert!(result.is_err());
    assert!(
        reaped.load(Ordering::Acquire),
        "host must be reaped during unwind"
    );
    assert!(began.elapsed() < CLEANUP_TIMEOUT + Duration::from_secs(1));
    seed.assert_persisted(true);
}
