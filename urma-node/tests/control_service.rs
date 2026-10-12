//! Actual authenticated Service controls over owned loopback and TEMP archives.
//! Signed public multipart vectors and public recovery establish completion.
//! Process supervision bounds the harness; it is not a generic API deadline,
//! forced cancellation, daemon deployment, or crash/power-loss durability test.

#[allow(dead_code)]
mod common;

use bitcoin::{Txid, hashes::Hash};
use common::{MemorySource, SignedPair, config, readonly_archive, stored_bytes, witness_block};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, PinReceipt, PruneReceipt, Retention},
    retrieval::recover,
    service::Service,
};
use urma_runtime::multipart::RecoveryLimits;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);

fn stage(directory: &Path, text: &str) {
    fs::write(directory.join("stage"), text).unwrap();
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<SqlValue>>>,
}

// Every call follows authenticated shutdown, a finished-thread join and Engine
// release. Inspection is read-only, never a production DB mutation/test hook.
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

fn assert_history(before: &Snapshot, after: &Snapshot) {
    assert_eq!(after.version, before.version);
    assert_eq!(after.schema, before.schema);
    for table in [
        "config",
        "state",
        "headers",
        "selected",
        "scans",
        "locators",
        "dependencies",
        "objects",
        "object_members",
    ] {
        assert_eq!(after.tables[table], before.tables[table], "history {table}");
    }
    let history = |snapshot: &Snapshot| {
        snapshot.tables["events"]
            .iter()
            .filter(|row| {
                row[2] != SqlValue::Text("pin".into()) && row[2] != SqlValue::Text("prune".into())
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(history(after), history(before));
}

fn events(snapshot: &Snapshot, kind: &str) -> usize {
    snapshot.tables["events"]
        .iter()
        .filter(|row| row[2] == SqlValue::Text(kind.into()))
        .count()
}

fn coverage(engine: &Engine) -> Value {
    let mut status = serde_json::to_value(engine.status().unwrap()).unwrap();
    status
        .as_object_mut()
        .unwrap()
        .remove("stored_transactions");
    status
}

struct Seed {
    directory: PathBuf,
    control: PathBuf,
    config: ArchiveConfig,
    pairs: Vec<SignedPair>,
    coverage: Value,
    payload: Vec<u8>,
}

impl Seed {
    fn new(control: &Path, retention: Retention, complete: bool) -> Self {
        let directory = control.join("archive");
        let pairs: Vec<_> = ["one-root", "one-leaf", "one-part-0"]
            .into_iter()
            .map(|name| SignedPair::load(&format!("multipart/{name}")))
            .collect();
        let transactions: Vec<_> = pairs.iter().flat_map(SignedPair::transactions).collect();
        let block = witness_block(&transactions, None, 9200);
        let config = config(&block, retention);
        let engine = Engine::open(
            &directory,
            config.clone(),
            Some(Arc::new(MemorySource::new(&[block]))),
        )
        .unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.indexed_through, Some(config.application_start));
        assert_eq!(status.unresolved_dependencies, 0);
        assert!(
            engine
                .object_status(pairs[0].reveal.compute_txid())
                .unwrap()
                .is_none()
        );
        let MultipartRecord::Data(data) = pairs[2].verified.decode().unwrap() else {
            panic!("real public data fixture");
        };
        let payload = data.payload;
        if complete {
            let scratch = control.join("scratch");
            fs::create_dir(&scratch).unwrap();
            let limits = RecoveryLimits {
                timeout: Duration::from_secs(2),
                ..RecoveryLimits::new(payload.len() as u64, pairs.len() as u32)
            };
            let mut recovered = recover(
                &engine,
                pairs[0].reveal.compute_txid(),
                &[],
                limits,
                &scratch,
            )
            .unwrap();
            let mut actual = Vec::new();
            recovered.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, payload);
            assert_eq!(recovered.root(), pairs[0].reveal.compute_txid());
            assert!(
                engine
                    .object_status(recovered.root())
                    .unwrap()
                    .unwrap()
                    .locally_complete()
            );
        }
        let coverage = coverage(&engine);
        drop(engine);
        Self {
            directory,
            control: control.to_owned(),
            config,
            pairs,
            coverage,
            payload,
        }
    }

    fn root(&self) -> Txid {
        self.pairs[0].reveal.compute_txid()
    }
    fn pin(&self) -> String {
        format!("/v1/objects/{}/pin", self.root())
    }
    fn unpin(&self) -> String {
        format!("/v1/objects/{}/unpin", self.root())
    }

    fn inspect_complete(&self, pinned: bool, children: bool) {
        let engine = Engine::open(&self.directory, self.config.clone(), None).unwrap();
        assert_eq!(coverage(&engine), self.coverage);
        assert_eq!(
            engine.status().unwrap().stored_transactions,
            if children { 6 } else { 2 }
        );
        for (index, pair) in self.pairs.iter().enumerate() {
            let record = engine.record(pair.reveal.compute_txid()).unwrap();
            if index == 0 || children {
                let record = record.unwrap();
                assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
                assert_eq!(record.package.commit, pair.raw_commit);
                assert_eq!(record.receipt.wtxid, pair.reveal.compute_wtxid());
                assert_eq!(record.receipt.block, self.config.application_start);
            } else {
                assert!(record.is_none());
            }
        }
        let object = engine.object_status(self.root()).unwrap().unwrap();
        assert_eq!(object.root, self.root());
        assert_eq!(object.pinned, pinned);
        assert_eq!(
            object.verified_generation,
            self.coverage["generation"].as_u64().unwrap()
        );
        assert_eq!(object.payload_bytes, self.payload.len() as u64);
        assert_eq!(object.members_total, 3);
        assert_eq!(object.members_selected, 3);
        assert_eq!(object.members_local, if children { 3 } else { 1 });
        assert_eq!(object.locally_complete(), children);
        drop(engine);
        let db = readonly_archive(&self.directory);
        let expected: BTreeMap<String, Vec<u8>> = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(index, _)| *index == 0 || children)
            .flat_map(|(_, pair)| {
                [
                    (
                        pair.commit.compute_wtxid().to_string(),
                        pair.raw_commit.clone(),
                    ),
                    (
                        pair.reveal.compute_wtxid().to_string(),
                        pair.raw_reveal.clone(),
                    ),
                ]
            })
            .collect();
        assert_eq!(stored_bytes(&db), expected);
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

struct Session {
    address: SocketAddr,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}

impl Session {
    fn start(seed: &Seed) -> Self {
        let engine = Arc::new(Engine::open(&seed.directory, seed.config.clone(), None).unwrap());
        let service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(false));
        Self {
            address,
            engine: Some(engine),
            worker: Some(worker),
        }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let shutdown = http(self.address, &request("POST", "/v1/shutdown", &auth()))
            .map_err(|error| error.to_string());
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service shutdown/join exceeded harness cleanup bound".into());
        }
        worker
            .join()
            .map_err(|_| "Service thread panicked".to_owned())?
            .map_err(|error| error.to_string())?;
        match shutdown {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            result => Err(format!("authenticated normal shutdown failed: {result:?}")),
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
        // A timed-out worker cannot be killed in Rust. The owning subprocess
        // supervisor handles the abnormal path; it never counts as a normal join.
    }
}

fn call(seed: &Seed, method: &str, path: &str, headers: &str, expected: u16) -> Value {
    stage(
        &seed.control,
        &format!("{method} {path}: expect {expected}"),
    );
    let session = Session::start(seed);
    let (code, body) = http(session.address, &request(method, path, headers)).unwrap();
    assert_eq!(code, expected, "{method} {path}: {body}");
    if expected != 200 {
        assert!(body["error"].is_string(), "{body}");
    }
    let (status_code, status) =
        http(session.address, &request("GET", "/v1/status", &auth())).unwrap();
    assert_eq!(status_code, 200);
    assert_eq!(
        status["archive"],
        serde_json::to_value(session.engine.as_ref().unwrap().status().unwrap()).unwrap()
    );
    assert!(status["last_sync_error"].is_null());
    assert!(status["last_retention_error"].is_null());
    session.finish();
    body
}

fn refused(seed: &Seed, method: &str, path: &str, headers: &str, code: u16) {
    let before = snapshot(&seed.directory);
    call(seed, method, path, headers, code);
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "refusal mutated DB: {method} {path} {code}"
    );
}

fn pin_receipt(seed: &Seed, root: Txid, pin: bool) {
    let path = format!("/v1/objects/{root}/{}", if pin { "pin" } else { "unpin" });
    // Explicit Content-Length: 0 is accepted, as is no Content-Length elsewhere.
    let body = call(
        seed,
        "POST",
        &path,
        &(auth() + "Content-Length: 0\r\n"),
        200,
    );
    assert_eq!(body, json!({"root":root,"pinned":pin}));
    let receipt: PinReceipt = serde_json::from_value(body).unwrap();
    assert_eq!(receipt.root, root);
    assert_eq!(receipt.pinned, pin);
}

fn prune_receipt(seed: &Seed, removed: u64) {
    let body = call(seed, "POST", "/v1/cache/prune", &auth(), 200);
    assert_eq!(body, json!({"records_removed":removed}));
    let receipt: PruneReceipt = serde_json::from_value(body).unwrap();
    assert_eq!(receipt.records_removed, removed);
}

fn refusals(control: &Path) {
    let seed = Seed::new(control, Retention::Pruned, true);
    let before = snapshot(&seed.directory);
    for path in [seed.pin(), seed.unpin(), "/v1/cache/prune".to_owned()] {
        refused(&seed, "POST", &path, "", 401);
        refused(&seed, "POST", &path, "Authorization: Bearer wrong\r\n", 401);
        // Existing GET object parsing remains compatible: the mutation suffix
        // is an invalid TXID (400); GET cache/prune is an unknown route (404).
        let get_code = if path == "/v1/cache/prune" { 404 } else { 400 };
        refused(&seed, "GET", &path, &auth(), get_code);
        for extra in [
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\n",
            "authorization: Bearer duplicate\r\n",
        ] {
            refused(&seed, "POST", &path, &(auth() + extra), 400);
        }
    }
    for id in ["bad".to_owned(), "g".repeat(64), "1".repeat(63)] {
        for operation in ["pin", "unpin"] {
            let path = format!("/v1/objects/{id}/{operation}");
            refused(&seed, "POST", &path, &auth(), 400);
            refused(&seed, "POST", &path, "", 401);
        }
    }
    seed.inspect_complete(false, true);
    assert_eq!(snapshot(&seed.directory), before);
}

fn eligibility(control: &Path) {
    let seed = Seed::new(control, Retention::Pruned, false);
    let unknown = Txid::from_byte_array([0; 32]);
    assert_ne!(unknown, seed.root());
    let before = snapshot(&seed.directory);
    refused(
        &seed,
        "POST",
        &format!("/v1/objects/{unknown}/pin"),
        &auth(),
        422,
    );
    refused(&seed, "POST", &seed.pin(), &auth(), 422);
    for root in [unknown, seed.root(), unknown, seed.root()] {
        pin_receipt(&seed, root, false);
    }
    assert_eq!(snapshot(&seed.directory), before);
    let engine = Engine::open(&seed.directory, seed.config.clone(), None).unwrap();
    assert_eq!(coverage(&engine), seed.coverage);
    assert!(engine.record(seed.root()).unwrap().is_some());
    assert!(engine.object_status(seed.root()).unwrap().is_none());
}

fn lifecycle(control: &Path) {
    let seed = Seed::new(control, Retention::Pruned, true);
    let before = snapshot(&seed.directory);
    pin_receipt(&seed, seed.root(), true);
    seed.inspect_complete(true, true); // New Engine after shutdown: pin persisted.
    let pinned = snapshot(&seed.directory);
    assert_history(&before, &pinned);
    assert_eq!(
        pinned.tables["pins"],
        vec![vec![SqlValue::Text(seed.root().to_string())]]
    );
    assert_eq!(events(&pinned, "pin"), events(&before, "pin") + 1);
    pin_receipt(&seed, seed.root(), true);
    prune_receipt(&seed, 0);
    assert_eq!(snapshot(&seed.directory), pinned);
    seed.inspect_complete(true, true);
    pin_receipt(&seed, seed.root(), false);
    let unpinned = snapshot(&seed.directory);
    assert_history(&before, &unpinned);
    assert!(unpinned.tables["pins"].is_empty());
    assert_eq!(events(&unpinned, "pin"), events(&before, "pin") + 2);
    pin_receipt(&seed, seed.root(), false);
    assert_eq!(snapshot(&seed.directory), unpinned);
    prune_receipt(&seed, 2); // Leaf + data records, not four raw transactions.
    seed.inspect_complete(false, false);
    let pruned = snapshot(&seed.directory);
    assert_history(&before, &pruned);
    assert_eq!(pruned.tables["records"].len(), 1);
    assert_eq!(pruned.tables["transactions"].len(), 2);
    assert_eq!(events(&pruned, "prune"), events(&before, "prune") + 1);
    refused(&seed, "POST", &seed.pin(), &auth(), 422);
    prune_receipt(&seed, 0);
    pin_receipt(&seed, seed.root(), false);
    assert_eq!(snapshot(&seed.directory), pruned);
    seed.inspect_complete(false, false); // Restart retains historical completion.
}

fn unpruned(control: &Path) {
    let seed = Seed::new(control, Retention::Unpruned, true);
    let before = snapshot(&seed.directory);
    prune_receipt(&seed, 0);
    prune_receipt(&seed, 0);
    seed.inspect_complete(false, true);
    assert_eq!(snapshot(&seed.directory), before);
}

#[test]
#[ignore = "owned subprocess host for the control-service cases"]
fn control_service_host() {
    let control = PathBuf::from(std::env::var_os("U4_CONTROL_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("U4_CONTROL_CASE").unwrap();
    stage(&control, &format!("seeding actual Engine: {scenario}"));
    match scenario.as_str() {
        "refusals" => refusals(&control),
        "eligibility" => eligibility(&control),
        "lifecycle" => lifecycle(&control),
        "unpruned" => unpruned(&control),
        _ => panic!("unknown owned test scenario"),
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
                assert!(
                    exit.success(),
                    "control host failed: {exit}; {}",
                    self.logs()
                );
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                assert_eq!(report["scenario"], scenario);
                assert_eq!(report["normal_service_joins_returned"], true);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "control host exceeded 45s; kill/reap is abnormal cleanup, not a normal Service join; {}",
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
                    eprintln!("control host cleanup/reap exceeded bound: {result:?}");
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
            "control_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U4_CONTROL_TEMP", directory.path())
        .env("U4_CONTROL_CASE", scenario)
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
    // Guard owns the process before any assertions. TEMP drops after its guard.
    Host {
        child: Some(child),
        directory: directory.path().to_owned(),
    }
    .finish(scenario);
}

#[test]
fn authenticated_control_refusals_preserve_the_entire_archive() {
    run("refusals");
}

#[test]
fn control_pin_requires_completion_and_unpin_is_idempotent() {
    run("eligibility");
}

#[test]
fn control_pin_prune_unpin_prune_preserves_raw_history_and_coverage_after_restart() {
    run("lifecycle");
}

#[test]
fn control_prune_unpruned_archive_is_an_exact_noop() {
    run("unpruned");
}
