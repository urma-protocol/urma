//! Linux Service scheduling for the soft, logical multipart cache target.
//! Genuine public signed vectors in mock-selected witness-authenticated blocks;
//! no PoW, UTXO/full consensus, disk quota or crash/power-loss claim.
//! Receipts describe one historical successful step, not current total usage.
//! Owned process supervision bounds the harness, not entered SQL or Engine I/O.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Txid, consensus::serialize};
use common::{MemorySource, SignedPair, config, readonly_archive, stored_bytes, witness_block};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::inclusion::TransactionProof;
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, RecordPackage, Retention},
    retrieval::recover,
    service::Service,
};
use urma_runtime::multipart::RecoveryLimits;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_TIMEOUT: Duration = Duration::from_secs(8);
fn stage(control: &Path, text: &str) {
    fs::write(control.join("stage"), text).unwrap();
}
#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<SqlValue>>>,
}

// Every call follows Engine release. After running a Service, authenticated
// shutdown and a finished-thread join precede inspection as well. Inspection
// is read-only, never a production DB mutation/test hook.
fn snapshot(directory: &Path) -> Snapshot {
    let db = readonly_archive(directory);
    let schema: Vec<(String, String, String, Option<String>)> = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
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
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap(),
        schema,
        tables,
    }
}

fn request(method: &str, path: &str, headers: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n{headers}\r\n")
}

fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
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
    let mut bytes = request.as_bytes();
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let count = stream.write(bytes)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[count..];
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

// A process group belongs exclusively to this test host.
// SIGKILL is abnormal host cleanup, never evidence of a graceful Service join.
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
struct OwnedChild {
    child: Option<Child>,
    group: bool,
}
impl OwnedChild {
    fn terminate(&mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if self.group {
            let pid = i32::try_from(child.id()).map_err(|e| e.to_string())?;
            // SAFETY: process_group(0) was set when spawning this owned child;
            // no process outside this test was admitted to that group.
            unsafe {
                kill(-pid, 9);
            }
        } else {
            let _ = child.kill();
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                other => return Err(format!("owned child reap exceeded bound: {other:?}")),
            }
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(e) = self.terminate() {
            eprintln!("{e}");
        }
    }
}
fn bounded_text(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(file) = File::open(path) {
        file.take(1024 * 1024).read_to_string(&mut text).unwrap();
    }
    text
}

fn coverage(status: &Value) -> Value {
    let mut status = status.clone();
    status
        .as_object_mut()
        .unwrap()
        .remove("stored_transactions");
    status
}
struct Seed {
    directory: PathBuf,
    config: ArchiveConfig,
    pairs: Vec<SignedPair>,
    payload_bytes: u64,
    status: Value,
    before: Snapshot,
    source: Arc<MemorySource>,
    source_calls: (usize, usize),
}
impl Seed {
    fn new(control: &Path, retention: Retention) -> Self {
        let directory = control.join("archive");
        let pairs: Vec<_> = ["one-root", "one-leaf", "one-part-0"]
            .into_iter()
            .map(|name| SignedPair::load(&format!("multipart/{name}")))
            .collect();
        let transactions: Vec<_> = pairs.iter().flat_map(SignedPair::transactions).collect();
        let block = witness_block(&transactions, None, 10001);
        let config = config(&block, retention);
        let source = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
        let engine = Engine::open(&directory, config.clone(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        let scanned = engine.scan_next().unwrap();
        assert_eq!(scanned.scanned_blocks, 1);
        assert_eq!(scanned.indexed_through, Some(config.application_start));
        assert_eq!(scanned.unresolved_dependencies, 0);
        // Pruned fullscan deliberately omits these children. Selective public
        // admission authenticates exact fixture bytes without inventing scans.
        for pair in &pairs[1..] {
            let position = block
                .txdata
                .iter()
                .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
                .unwrap();
            engine
                .admit_record(RecordPackage {
                    version: API_VERSION,
                    chain_genesis: config.chain.genesis().unwrap().0,
                    block: config.application_start,
                    reveal: TransactionProof::from_block(
                        &block,
                        position as u32,
                        pair.raw_reveal.clone(),
                        serialize(&block.txdata[0]),
                    )
                    .unwrap(),
                    commit: pair.raw_commit.clone(),
                })
                .unwrap();
        }
        let MultipartRecord::Data(data) = pairs[2].verified.decode().unwrap() else {
            panic!("genuine public data fixture");
        };
        let scratch = control.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let mut recovered = recover(
            &engine,
            pairs[0].reveal.compute_txid(),
            &[],
            RecoveryLimits {
                timeout: Duration::from_secs(2),
                ..RecoveryLimits::new(data.payload.len() as u64, 3)
            },
            &scratch,
        )
        .unwrap();
        let mut payload = Vec::new();
        recovered.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, data.payload);
        drop(recovered);
        let status = serde_json::to_value(engine.status().unwrap()).unwrap();
        assert_eq!(
            coverage(&status),
            coverage(&serde_json::to_value(scanned).unwrap())
        );
        assert_eq!(status["stored_transactions"], 6);
        let object = engine
            .object_status(pairs[0].reveal.compute_txid())
            .unwrap()
            .unwrap();
        assert!(object.locally_complete());
        assert!(!object.pinned);
        drop(engine);
        let before = snapshot(&directory);
        assert_eq!(before.tables["records"].len(), 3);
        assert_eq!(before.tables["transactions"].len(), 6);
        assert_eq!(before.tables["object_members"].len(), 3);
        assert!(before.tables["pins"].is_empty());
        let source_calls = (
            source.body_calls.load(Ordering::SeqCst),
            source.header_calls.load(Ordering::SeqCst),
        );
        Self {
            directory,
            config,
            pairs,
            payload_bytes: payload.len() as u64,
            status,
            before,
            source,
            source_calls,
        }
    }
    fn root(&self) -> Txid {
        self.pairs[0].reveal.compute_txid()
    }
    fn no_source_calls(&self) {
        assert_eq!(
            (
                self.source.body_calls.load(Ordering::SeqCst),
                self.source.header_calls.load(Ordering::SeqCst)
            ),
            self.source_calls
        );
    }
    fn inspect_reopened(&self, children: bool) {
        let engine = Engine::open(&self.directory, self.config.clone(), None).unwrap();
        let status = serde_json::to_value(engine.status().unwrap()).unwrap();
        assert_eq!(coverage(&status), coverage(&self.status));
        assert_eq!(status["stored_transactions"], if children { 6 } else { 2 });
        for (index, pair) in self.pairs.iter().enumerate() {
            let record = engine.record(pair.reveal.compute_txid()).unwrap();
            if children || index == 0 {
                let record = record.unwrap();
                assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
                assert_eq!(record.package.commit, pair.raw_commit);
                assert_eq!(record.receipt.block, self.config.application_start);
                assert_eq!(record.receipt.wtxid, pair.reveal.compute_wtxid());
            } else {
                assert!(record.is_none());
            }
        }
        let object = engine.object_status(self.root()).unwrap().unwrap();
        assert_eq!(object.root, self.root());
        assert_eq!(
            object.verified_generation,
            self.status["generation"].as_u64().unwrap()
        );
        assert_eq!(object.payload_bytes, self.payload_bytes);
        assert_eq!(object.members_total, 3);
        assert_eq!(object.members_selected, 3);
        assert_eq!(object.members_local, if children { 3 } else { 1 });
        assert_eq!(object.locally_complete(), children);
        assert!(!object.pinned);
        drop(engine);
        let db = readonly_archive(&self.directory);
        let expected: BTreeMap<_, _> = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(index, _)| children || *index == 0)
            .flat_map(|(_, pair)| {
                [
                    (
                        pair.reveal.compute_wtxid().to_string(),
                        pair.raw_reveal.clone(),
                    ),
                    (
                        pair.commit.compute_wtxid().to_string(),
                        pair.raw_commit.clone(),
                    ),
                ]
            })
            .collect();
        assert_eq!(stored_bytes(&db), expected);
        self.no_source_calls();
    }
}

struct Session {
    address: SocketAddr,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}
impl Session {
    fn start(seed: &Seed, synchronize: bool) -> Self {
        // No source or remote record candidates exist in the actual Service.
        let engine = Arc::new(Engine::open(&seed.directory, seed.config.clone(), None).unwrap());
        let service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap()
        .with_cache_limit(0)
        .unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(synchronize));
        Self {
            address,
            engine: Some(engine),
            worker: Some(worker),
        }
    }
    fn status(&self) -> Value {
        let (code, body) = http(self.address, &request("GET", "/v1/status", &auth())).unwrap();
        assert_eq!(code, 200);
        // Individual status reads can race a maintenance commit; compare
        // immutable coverage separately, not two non-atomic raw row counts.
        assert_eq!(body["cache_limit_bytes"], 0);
        assert_eq!(body["record_sources_configured"], 0);
        assert_eq!(body["retention_configured"], false);
        assert!(body["last_retention_error"].is_null());
        assert!(body["last_names_error"].is_null());
        body
    }
    fn poll(&self, ready: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + POLL_TIMEOUT;
        loop {
            let status = self.status();
            if ready(&status) {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "Service maintenance did not reach expected state: {status}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn cleanup(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let reply = http(self.address, &request("POST", "/v1/shutdown", &auth()));
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service normal join exceeded harness bound".into());
        }
        worker
            .join()
            .map_err(|_| "Service panicked".to_owned())?
            .map_err(|error| error.to_string())?;
        match reply {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            other => Err(format!(
                "authenticated shutdown not acknowledged: {other:?}"
            )),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
        let weak = Arc::downgrade(self.engine.as_ref().unwrap());
        drop(self.engine.take());
        assert!(
            weak.upgrade().is_none(),
            "Service kept Engine after normal joined shutdown"
        );
        assert!(
            matches!(TcpStream::connect_timeout(&self.address, HTTP_TIMEOUT),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused),
            "listener remains after shutdown"
        );
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("Service cleanup: {e}");
        }
        // Rust cannot force-kill a stuck SQL thread. The Linux host supervisor
        // handles abnormal cleanup, which never establishes normal join success.
    }
}

fn assert_sync_failed(status: &Value, seed: &Seed) {
    assert!(
        status["last_sync_error"]
            .as_str()
            .unwrap()
            .contains("offline")
    );
    assert!(status["last_cache_error"].is_null());
    assert_eq!(coverage(&status["archive"]), coverage(&seed.status));
    seed.no_source_calls();
}
fn worker_free(control: &Path) {
    stage(
        control,
        "G1: genuine pruned cache, run(false) with zero operational target",
    );
    let seed = Seed::new(control, Retention::Pruned);
    let session = Session::start(&seed, false);
    // Observe beyond one current worker cadence; no maintenance or failed
    // sync attempt is permitted merely by configuring the cache target.
    let until = Instant::now() + Duration::from_millis(2250);
    loop {
        let status = session.status();
        assert_eq!(status["archive"], seed.status);
        assert!(status["last_sync_error"].is_null());
        assert!(status["last_cache_error"].is_null());
        assert!(status["last_cache_maintenance"].is_null());
        if Instant::now() >= until {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    session.finish();
    assert_eq!(snapshot(&seed.directory), seed.before);
    seed.inspect_reopened(true);
}
fn offline_drain(control: &Path) {
    stage(
        control,
        "G2: offline sync fails, independent cache stage drains unpinned pruned children",
    );
    let seed = Seed::new(control, Retention::Pruned);
    let session = Session::start(&seed, true);
    let status = session.poll(|status| {
        status["last_sync_error"].is_string()
            && status["last_cache_maintenance"].is_object()
            && status["last_cache_maintenance"]["remaining_bytes"] == 0
            && status["archive"]["stored_transactions"] == 2
    });
    assert_sync_failed(&status, &seed);
    let receipt = &status["last_cache_maintenance"];
    assert_eq!(receipt["enabled"], true);
    assert_eq!(receipt["limit_bytes"], 0);
    assert_eq!(receipt["remaining_bytes"], 0);
    assert_eq!(receipt["over_budget"], false);
    // Status retains the last successful step, not cumulative deletion totals.
    // A subsequent successful no-op can already have replaced the drain step.
    if receipt["before_bytes"].as_u64().unwrap() > 0 {
        assert_eq!(receipt["removed_records"], 2);
        assert_eq!(receipt["removed_transactions"], 4);
    } else {
        assert_eq!(receipt["removed_records"], 0);
        assert_eq!(receipt["removed_transactions"], 0);
    }
    assert!(
        session
            .engine
            .as_ref()
            .unwrap()
            .record(seed.root())
            .unwrap()
            .is_some()
    );
    for child in &seed.pairs[1..] {
        assert!(
            session
                .engine
                .as_ref()
                .unwrap()
                .record(child.reveal.compute_txid())
                .unwrap()
                .is_none()
        );
    }
    session.finish();
    let after = snapshot(&seed.directory);
    assert_eq!(after.version, seed.before.version);
    assert_eq!(after.schema, seed.before.schema);
    for (table, rows) in &seed.before.tables {
        if !["records", "transactions", "events", "sqlite_sequence"].contains(&table.as_str()) {
            assert_eq!(
                &after.tables[table], rows,
                "preserved evidence table {table}"
            );
        }
    }
    let events = |snapshot: &Snapshot| {
        snapshot.tables["events"]
            .iter()
            .filter(|row| row[2] != SqlValue::Text("cache".to_owned()))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(events(&after), events(&seed.before));
    assert_eq!(
        after.tables["events"].len(),
        seed.before.tables["events"].len() + 1
    );
    assert_eq!(
        after.tables["events"].last().unwrap()[2],
        SqlValue::Text("cache".to_owned())
    );
    assert_eq!(after.tables["records"].len(), 1);
    assert_eq!(after.tables["transactions"].len(), 2);
    seed.inspect_reopened(false);
    // A newly bound run(false) has no historical in-memory Service receipt;
    // persisted archive evidence is checked above rather than fabricating one.
    let restarted = Session::start(&seed, false);
    let status = restarted.status();
    assert_eq!(coverage(&status["archive"]), coverage(&seed.status));
    assert_eq!(status["archive"]["stored_transactions"], 2);
    assert!(status["last_sync_error"].is_null());
    assert!(status["last_cache_error"].is_null());
    assert!(status["last_cache_maintenance"].is_null());
    restarted.finish();
    assert_eq!(snapshot(&seed.directory), after);
    seed.no_source_calls();
}
fn unpruned_disabled(control: &Path) {
    stage(
        control,
        "G3: Unpruned offline worker reports disabled enforcement, never evicts",
    );
    let seed = Seed::new(control, Retention::Unpruned);
    let session = Session::start(&seed, true);
    let status = session.poll(|status| {
        status["last_sync_error"].is_string() && status["last_cache_maintenance"].is_object()
    });
    assert_sync_failed(&status, &seed);
    assert_eq!(status["archive"], seed.status);
    assert_eq!(
        status["last_cache_maintenance"],
        json!({
            "enabled":false,"limit_bytes":0,"before_bytes":0,"remaining_bytes":0,
            "removed_records":0,"removed_transactions":0,"over_budget":false
        })
    );
    // Disabled zero-valued fields do not imply an empty cache/database.
    for pair in &seed.pairs {
        let record = session
            .engine
            .as_ref()
            .unwrap()
            .record(pair.reveal.compute_txid())
            .unwrap()
            .unwrap();
        assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
        assert_eq!(record.package.commit, pair.raw_commit);
    }
    session.finish();
    assert_eq!(snapshot(&seed.directory), seed.before);
    seed.inspect_reopened(true);
}

#[test]
#[ignore = "owned bounded Linux subprocess host, not a standalone Service case"]
fn cache_service_host() {
    let control = PathBuf::from(std::env::var_os("U4_CACHE_SERVICE_TEMP").expect("owned TEMP"));
    let case = std::env::var("U4_CACHE_SERVICE_CASE").unwrap();
    match case.as_str() {
        "worker-free" => worker_free(&control),
        "offline-drain" => offline_drain(&control),
        "unpruned" => unpruned_disabled(&control),
        _ => panic!("unknown owned case"),
    }
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({
            "case":case,"normal_service_joins_returned":true
        }))
        .unwrap(),
    )
    .unwrap();
}
fn run_host(case: &str) {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "cache_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("TMPDIR", directory.path())
        .env("U4_CACHE_SERVICE_TEMP", directory.path())
        .env("U4_CACHE_SERVICE_CASE", case)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(directory.path().join("stdout")).unwrap())
        .stderr(File::create(directory.path().join("stderr")).unwrap())
        .spawn()
        .unwrap();
    let mut owned = OwnedChild {
        child: Some(child),
        group: true,
    };
    let deadline = Instant::now() + HOST_TIMEOUT;
    let logs = || {
        ["stage", "stdout", "stderr"]
            .map(|name| bounded_text(&directory.path().join(name)))
            .join("\n")
    };
    loop {
        if let Some(exit) = owned.child.as_mut().unwrap().try_wait().unwrap() {
            assert!(
                exit.success(),
                "cache Service host {case}: {exit}; {}",
                logs()
            );
            owned.child.take();
            let report: Value =
                serde_json::from_slice(&fs::read(directory.path().join("result.json")).unwrap())
                    .unwrap();
            assert_eq!(
                report,
                json!({"case":case,"normal_service_joins_returned":true})
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "cache Service host {case} exceeded45s; process kill/reap is abnormal cleanup, not a Service join; {}",
            logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn configured_zero_cache_run_false_stays_worker_free() {
    run_host("worker-free");
}
#[test]
fn offline_sync_failure_does_not_suppress_cache_drain_or_preserved_history() {
    run_host("offline-drain");
}
#[test]
fn unpruned_worker_reports_disabled_cache_without_eviction() {
    run_host("unpruned");
}
