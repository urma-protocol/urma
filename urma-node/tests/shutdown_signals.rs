//! Linux cooperative standalone signals and embedded shutdown requests.
//! Successful cases require normal exit/join; process-group kill/reap is only
//! abnormal harness containment, never a successful shutdown oracle.
//! Real regtest genesis is a local fixture, not a product application anchor.
//! No entered I/O/SQL interruption or hard graceful-stop deadline is claimed.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Block, BlockHash, Network, block::Header, consensus::serialize};
use common::readonly_archive;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::{
        fs::PermissionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    service::{Service, ShutdownHandle},
    source::ChainSource,
};
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);
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

// Every call follows Engine release. After a standalone/embedded Service,
// normal process exit or a finished-thread join precedes inspection as well.
// Inspection is read-only, never a production DB mutation/test hook.
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

// Count all source entrypoints. Constructor validation legitimately calls
// genesis; precancel checks the delta from the baseline after that validation.
struct CountedGenesis {
    block: Block,
    calls: [AtomicUsize; 4],
}
impl CountedGenesis {
    fn new() -> Self {
        Self {
            block: bitcoin::blockdata::constants::genesis_block(Network::Regtest),
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }
    fn counts(&self) -> [usize; 4] {
        std::array::from_fn(|i| self.calls[i].load(Ordering::SeqCst))
    }
}
impl ChainSource for CountedGenesis {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls[0].fetch_add(1, Ordering::SeqCst);
        Ok(self.block.block_hash())
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls[1].fetch_add(1, Ordering::SeqCst);
        Ok(ChainPoint {
            height: 0,
            hash: self.block.block_hash(),
        })
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls[2].fetch_add(1, Ordering::SeqCst);
        assert_eq!(height, 0);
        Ok(self.block.header)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls[3].fetch_add(1, Ordering::SeqCst);
        assert_eq!(height, 0);
        Ok(serialize(&self.block))
    }
}
struct Fixture {
    control: PathBuf,
    directory: PathBuf,
    config_path: PathBuf,
    token_path: PathBuf,
    config: ArchiveConfig,
    status: Value,
    before: Snapshot,
    sequence: usize,
}
impl Fixture {
    fn new(control: &Path) -> Self {
        let source = Arc::new(CountedGenesis::new());
        let config = ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: ChainPoint {
                height: 0,
                hash: source.block.block_hash(),
            },
            retention: Retention::Pruned,
        };
        let directory = control.join("archive");
        let config_path = control.join("config.json");
        let token_path = control.join("service.token");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        fs::write(&token_path, TOKEN).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        let engine = Engine::open(&directory, config.clone(), Some(source)).unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.indexed_through, Some(config.application_start));
        assert_eq!(status.unresolved_dependencies, 0);
        let status = serde_json::to_value(status).unwrap();
        drop(engine);
        let before = snapshot(&directory);
        Self {
            control: control.to_owned(),
            directory,
            config_path,
            token_path,
            config,
            status,
            before,
            sequence: 0,
        }
    }
    fn spawn(&mut self, args: &[&str]) -> Binary {
        self.sequence += 1;
        let stdout = self.control.join(format!("child-{}.stdout", self.sequence));
        let stderr = self.control.join(format!("child-{}.stderr", self.sequence));
        // Inherit the owned host's process group, so a host-level panic/timeout
        // contains its binary descendants too. Drop also owns this exact child.
        let child = Command::new(env!("CARGO_BIN_EXE_urma-node"))
            .env_clear()
            .env("TMPDIR", &self.control)
            .current_dir(&self.control)
            .arg("--data")
            .arg(&self.directory)
            .arg("--config")
            .arg(&self.config_path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        Binary {
            owned: OwnedChild {
                child: Some(child),
                group: false,
            },
            stdout,
            stderr,
        }
    }
    fn serve(&mut self, key: Option<&Path>) -> Binary {
        let token = self.token_path.clone();
        let mut args = vec![
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            token.to_str().unwrap(),
        ];
        if let Some(key) = key {
            args.extend([
                "--peer-key",
                key.to_str().unwrap(),
                "--urma-listen",
                "127.0.0.1:0",
            ]);
        }
        self.spawn(&args)
    }
    fn inspect_reopened(&self) {
        let engine = Engine::open(&self.directory, self.config.clone(), None).unwrap();
        assert_eq!(
            serde_json::to_value(engine.status().unwrap()).unwrap(),
            self.status
        );
        drop(engine);
        assert_eq!(snapshot(&self.directory), self.before);
        assert!(
            !self.directory.join("headers").exists(),
            "offline process created chain P2P cache"
        );
        assert!(
            !self.directory.join("peers.json").exists(),
            "no manual peers were configured"
        );
    }
}
struct Binary {
    owned: OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Binary {
    fn running(&mut self) {
        assert!(
            self.owned
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "owned binary exited before signal: {}",
            bounded_text(&self.stderr)
        );
    }
    fn ready(&mut self, expected: &Value) -> SocketAddr {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            self.running();
            let logs = bounded_text(&self.stderr);
            if let Some(address) = logs.lines().find_map(|line| {
                line.strip_prefix("URMA Node listening at ")?
                    .strip_suffix(" (authenticated loopback)")
            }) {
                let address: SocketAddr = address.parse().unwrap();
                assert!(address.ip().is_loopback());
                assert_ne!(address.port(), 0);
                let (code, status) = http(address, &request("GET", "/v1/status", &auth())).unwrap();
                assert_eq!(code, 200);
                assert_eq!(&status["archive"], expected);
                assert!(status["last_sync_error"].is_null());
                assert!(status["last_cache_maintenance"].is_null());
                assert_eq!(status["record_sources_configured"], 0);
                return address;
            }
            assert!(
                Instant::now() < deadline,
                "binary readiness timed out: {logs}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn overlay(&self) -> (PeerId, SocketAddr) {
        let logs = bounded_text(&self.stderr);
        let line = logs
            .lines()
            .find_map(|line| line.strip_prefix("URMA peer identity "))
            .expect("explicit overlay readiness");
        let (identity, listener) = line
            .split_once(" listener Some(")
            .expect("explicit bound listener");
        let identity: PeerId = identity.parse().unwrap();
        let listener: Multiaddr = listener.strip_suffix(')').unwrap().parse().unwrap();
        let mut protocols = listener.iter();
        let Some(Protocol::Ip4(ip)) = protocols.next() else {
            panic!("owned IPv4 listener")
        };
        assert!(ip.is_loopback());
        let Some(Protocol::Tcp(port)) = protocols.next() else {
            panic!("owned TCP listener")
        };
        assert_ne!(port, 0);
        assert_eq!(protocols.next(), Some(Protocol::P2p(identity)));
        assert!(protocols.next().is_none());
        (identity, SocketAddr::new(ip.into(), port))
    }
    fn signal(&mut self, signal: i32) {
        self.running();
        let pid = i32::try_from(self.owned.child.as_ref().unwrap().id()).unwrap();
        assert!(pid > 0);
        // SAFETY: this is the unreaped positive PID of our own Child. Never a
        // shell pattern, process group, PID zero or a discovered external PID.
        assert_eq!(
            unsafe { kill(pid, signal) },
            0,
            "owned signal failed: {}",
            io::Error::last_os_error()
        );
    }
    fn finish_zero(mut self) -> String {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.owned.child.as_mut().unwrap().try_wait().unwrap() {
                self.owned.child.take();
                assert_eq!(
                    status.code(),
                    Some(0),
                    "binary did not exit normally: {status}; {}",
                    bounded_text(&self.stderr)
                );
                assert_eq!(
                    status.signal(),
                    None,
                    "success cannot be signal termination"
                );
                assert!(bounded_text(&self.stdout).is_empty());
                return bounded_text(&self.stderr);
            }
            assert!(
                Instant::now() < deadline,
                "owned binary normal exit timed out: {}",
                bounded_text(&self.stderr)
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn listener_closed(address: SocketAddr) {
    assert!(
        matches!(TcpStream::connect_timeout(&address,HTTP_TIMEOUT),Err(e) if e.kind()==io::ErrorKind::ConnectionRefused),
        "owned listener remains after normal exit/join: {address}"
    );
}
fn standalone_signals(control: &Path) {
    let mut fixture = Fixture::new(control);
    for (label, signal) in [("SIGINT", 2), ("SIGTERM", 15), ("SIGHUP", 1)] {
        stage(
            control,
            &format!("G1 {label}: authenticate readiness, then signal only owned positive PID"),
        );
        let mut binary = fixture.serve(None);
        let address = binary.ready(&fixture.status);
        assert!(!bounded_text(&binary.stderr).contains("URMA peer identity "));
        binary.signal(signal);
        binary.finish_zero();
        listener_closed(address);
        fixture.inspect_reopened();
    }
}
fn standalone_overlay(control: &Path) {
    stage(
        control,
        "G2: explicit owned private overlay identity, no chain source or peer candidates",
    );
    let mut fixture = Fixture::new(control);
    let key = control.join("peer.key");
    fixture
        .spawn(&["create-peer-key", key.to_str().unwrap()])
        .finish_zero();
    let raw = fs::read(&key).unwrap();
    assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o077, 0);
    let expected = libp2p::identity::Keypair::from_protobuf_encoding(&raw)
        .unwrap()
        .public()
        .to_peer_id();
    for cycle in 0..2 {
        stage(
            control,
            &format!(
                "G2 lifecycle {cycle}: SIGTERM requires Service and overlay owner path to finish"
            ),
        );
        let mut binary = fixture.serve(Some(&key));
        let control_address = binary.ready(&fixture.status);
        let (identity, peer_address) = binary.overlay();
        assert_eq!(identity, expected);
        binary.signal(15);
        binary.finish_zero();
        listener_closed(control_address);
        listener_closed(peer_address);
        fixture.inspect_reopened();
        assert_eq!(
            fs::read(&key).unwrap(),
            raw,
            "transport key changed across normal shutdown/restart"
        );
    }
}
struct Embedded {
    address: SocketAddr,
    handle: ShutdownHandle,
    engine: Option<Arc<Engine>>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}
impl Embedded {
    fn start(engine: Engine, precancel: bool) -> Self {
        let engine = Arc::new(engine);
        let service = Service::bind(
            "127.0.0.1:0".parse().unwrap(),
            TOKEN.into(),
            Arc::clone(&engine),
        )
        .unwrap();
        let address = service.address().unwrap();
        let handle = service.shutdown_handle();
        if precancel {
            handle.request();
            handle.clone().request();
        }
        let worker = thread::spawn(move || service.run(true));
        Self {
            address,
            handle,
            engine: Some(engine),
            worker: Some(worker),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
        let weak = Arc::downgrade(self.engine.as_ref().unwrap());
        drop(self.engine.take());
        assert!(
            weak.upgrade().is_none(),
            "Service retained Engine after joined run"
        );
        listener_closed(self.address);
    }
    fn cleanup(&mut self) -> Result<(), String> {
        self.handle.clone().request();
        self.handle.request();
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("embedded Service normal join exceeded harness bound".to_owned());
        }
        worker
            .join()
            .map_err(|_| "embedded Service panicked".to_owned())?
            .map_err(|e| e.to_string())
    }
}
impl Drop for Embedded {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("embedded cleanup: {error}");
        }
    }
}
fn embedded_requests(control: &Path) {
    stage(
        control,
        "G3: embedded active offline worker, cloned repeated cooperative stop and mandatory join",
    );
    let fixture = Fixture::new(control);
    let engine = Engine::open(&fixture.directory, fixture.config.clone(), None).unwrap();
    let embedded = Embedded::start(engine, false);
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        let (code, status) =
            http(embedded.address, &request("GET", "/v1/status", &auth())).unwrap();
        assert_eq!(code, 200);
        assert_eq!(status["archive"], fixture.status);
        if let Some(error) = status["last_sync_error"].as_str() {
            assert!(error.contains("offline"));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "offline worker attempt was not observed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let cloned = embedded.handle.clone();
    cloned.request();
    embedded.handle.request();
    cloned.request();
    embedded.finish();
    fixture.inspect_reopened();
    stage(
        control,
        "G3 precancel: source baseline follows Engine constructor genesis validation",
    );
    let source = Arc::new(CountedGenesis::new());
    let engine = Engine::open(
        &fixture.directory,
        fixture.config.clone(),
        Some(source.clone()),
    )
    .unwrap();
    let baseline = source.counts();
    assert_eq!(
        baseline,
        [1, 0, 0, 0],
        "constructor validation is included in baseline"
    );
    let precancelled = Embedded::start(engine, true);
    precancelled.finish();
    assert_eq!(
        source.counts(),
        baseline,
        "precancel run called a source after constructor baseline"
    );
    fixture.inspect_reopened();
}
#[test]
#[ignore = "owned bounded Linux subprocess host, not a standalone shutdown case"]
fn shutdown_signals_host() {
    let control = PathBuf::from(std::env::var_os("U4_SHUTDOWN_TEMP").expect("owned TEMP"));
    let case = std::env::var("U4_SHUTDOWN_CASE").unwrap();
    match case.as_str() {
        "signals" => standalone_signals(&control),
        "overlay" => standalone_overlay(&control),
        "embedded" => embedded_requests(&control),
        _ => panic!("unknown owned case"),
    }
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({"case":case,"normal_exit_or_join":true})).unwrap(),
    )
    .unwrap();
}
fn run_host(case: &str) {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "shutdown_signals_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("TMPDIR", directory.path())
        .env("U4_SHUTDOWN_TEMP", directory.path())
        .env("U4_SHUTDOWN_CASE", case)
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
            assert!(exit.success(), "shutdown host {case}: {exit}; {}", logs());
            owned.child.take();
            let report: Value =
                serde_json::from_slice(&fs::read(directory.path().join("result.json")).unwrap())
                    .unwrap();
            assert_eq!(report, json!({"case":case,"normal_exit_or_join":true}));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "shutdown host {case} exceeded45s; kill/reap is abnormal containment; {}",
            logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn standalone_sigint_sigterm_sighup_exit_normally_and_preserve_archive() {
    run_host("signals");
}
#[test]
fn standalone_sigterm_joins_explicit_offline_overlay_and_preserves_identity() {
    run_host("overlay");
}
#[test]
fn embedded_shutdown_handle_joins_worker_and_precancel_makes_no_source_delta() {
    run_host("embedded");
}
