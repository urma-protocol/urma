use bitcoin::{Block, BlockHash, Network, block::Header, consensus::serialize};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    source::ChainSource,
};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);
const HTTP_TIMEOUT: Duration = Duration::from_secs(6);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Completed {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

// Every spawned child is immediately owned by this guard. No pipe reader or
// unbounded Child::wait is used, including while unwinding from an assertion.
struct OwnedChild {
    child: Option<Child>,
    stdout: PathBuf,
    stderr: PathBuf,
    reaped: Arc<AtomicBool>,
}

impl OwnedChild {
    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap()
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "child exited unexpectedly: {}",
            self.stderr()
        );
    }

    fn listening_address(&mut self) -> SocketAddr {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            self.assert_running();
            let stderr = self.stderr();
            if let Some(address) = stderr.lines().find_map(|line| {
                line.strip_prefix("URMA Node listening at ")?
                    .strip_suffix(" (authenticated loopback)")
            }) {
                let address: SocketAddr = address.parse().unwrap();
                assert!(address.ip().is_loopback());
                assert_ne!(address.port(), 0);
                return address;
            }
            assert!(Instant::now() < deadline, "startup timed out: {stderr}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self) -> Completed {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.child.take();
                self.reaped.store(true, Ordering::Release);
                return Completed {
                    status,
                    stdout: fs::read_to_string(&self.stdout).unwrap(),
                    stderr: self.stderr(),
                };
            }
            assert!(
                Instant::now() < deadline,
                "child exit timed out: {}",
                self.stderr()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
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
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                result => {
                    // Do not cause a second panic during unwinding. This is
                    // also observed by the explicit panic-cleanup regression.
                    eprintln!("child {} cleanup did not reap: {result:?}", child.id());
                    return;
                }
            }
        }
    }
}

struct Fixture {
    root: tempfile::TempDir,
    data: PathBuf,
    config_path: PathBuf,
    token_path: PathBuf,
    config: ArchiveConfig,
    sequence: Cell<u32>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("archive");
        let config_path = root.path().join("config.json");
        let token_path = root.path().join("service.token");
        let config = ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: ChainPoint {
                height: 0,
                hash: bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash(),
            },
            retention: Retention::Pruned,
        };
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        Self {
            root,
            data,
            config_path,
            token_path,
            config,
            sequence: Cell::new(0),
        }
    }

    fn spawn(&self, args: &[&str]) -> OwnedChild {
        let sequence = self.sequence.get();
        self.sequence.set(sequence + 1);
        let stdout = self.root.path().join(format!("child-{sequence}.stdout"));
        let stderr = self.root.path().join(format!("child-{sequence}.stderr"));
        let child = Command::new(env!("CARGO_BIN_EXE_urma-node"))
            .env_clear()
            .env("TMPDIR", self.root.path())
            .env("TEMP", self.root.path())
            .env("TMP", self.root.path())
            .current_dir(self.root.path())
            .arg("--data")
            .arg(&self.data)
            .arg("--config")
            .arg(&self.config_path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        OwnedChild {
            child: Some(child),
            stdout,
            stderr,
            reaped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn create_token(&self) -> String {
        let result = self
            .spawn(&["create-token", self.token_path.to_str().unwrap()])
            .finish();
        assert!(result.status.success(), "{}", result.stderr);
        let token = fs::read_to_string(&self.token_path).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        token
    }

    fn serve_at(&self, address: &str) -> OwnedChild {
        self.spawn(&[
            "serve",
            "--listen",
            address,
            "--token-file",
            self.token_path.to_str().unwrap(),
        ])
    }

    fn serve(&self) -> (OwnedChild, SocketAddr) {
        let mut child = self.serve_at("127.0.0.1:0");
        let address = child.listening_address();
        (child, address)
    }

    fn seed_scanned_genesis(&self) -> Value {
        let source = GenesisSource(bitcoin::blockdata::constants::genesis_block(
            Network::Regtest,
        ));
        let engine = Engine::open(&self.data, self.config.clone(), Some(Arc::new(source))).unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.indexed_through, Some(self.config.application_start));
        serde_json::to_value(status).unwrap()
    }
}

// The only chain source used by a fixture is this in-memory regtest genesis.
// The real service processes run offline and never instantiate a P2P source.
struct GenesisSource(Block);

impl ChainSource for GenesisSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(self.0.block_hash())
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        Ok(ChainPoint {
            height: 0,
            hash: self.0.block_hash(),
        })
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        assert_eq!(height, 0);
        Ok(self.0.header)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        assert_eq!(height, 0);
        Ok(serialize(&self.0))
    }
}

struct Response {
    code: u16,
    body: Value,
}

fn connect(address: SocketAddr) -> TcpStream {
    assert!(address.ip().is_loopback());
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn response(stream: &mut TcpStream, deadline: Instant) -> Response {
    let mut header = Vec::new();
    loop {
        assert!(header.len() < 8192, "response header exceeds test bound");
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("HTTP deadline");
        stream.set_read_timeout(Some(remaining)).unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8(header).unwrap();
    let mut lines = header.split("\r\n");
    let code = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert!(header.contains("Content-Type: application/json\r\n"));
    assert!(header.contains("Cache-Control: no-store\r\n"));
    assert!(header.contains("Connection: close\r\n"));
    let length: usize = lines
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(length <= 65536, "response body exceeds test bound");
    let mut body = vec![0; length];
    let mut received = 0;
    while received < length {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("HTTP deadline");
        stream.set_read_timeout(Some(remaining)).unwrap();
        let count = stream.read(&mut body[received..]).unwrap();
        assert_ne!(count, 0, "truncated response body");
        received += count;
    }
    Response {
        code,
        body: serde_json::from_slice(&body).unwrap(),
    }
}

fn exchange(address: SocketAddr, request: &[u8]) -> Response {
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let mut stream = connect(address);
    stream.write_all(request).unwrap();
    response(&mut stream, deadline)
}

fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (name, value) in headers {
        bytes.push_str(&format!("{name}: {value}\r\n"));
    }
    bytes.push_str("\r\n");
    bytes.into_bytes()
}

fn status(address: SocketAddr, token: &str) -> Value {
    let response = exchange(
        address,
        &request(
            "GET",
            "/v1/status",
            &[("Authorization", &format!("Bearer {token}"))],
        ),
    );
    assert_eq!(response.code, 200, "{}", response.body);
    response.body
}

fn shutdown(child: OwnedChild, address: SocketAddr, token: &str) {
    let response = exchange(
        address,
        &request(
            "POST",
            "/v1/shutdown",
            &[("Authorization", &format!("Bearer {token}"))],
        ),
    );
    assert_eq!(response.code, 200);
    assert_eq!(response.body, json!({"stopping": true}));
    let result = child.finish();
    assert!(result.status.success(), "{}", result.stderr);
}

#[cfg(unix)]
#[test]
fn create_token_is_private_and_never_overwrites_existing_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let token = fixture.create_token();
    assert_eq!(
        fs::metadata(&fixture.token_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let result = fixture
        .spawn(&["create-token", fixture.token_path.to_str().unwrap()])
        .finish();
    assert!(!result.status.success());
    assert_eq!(fs::read_to_string(&fixture.token_path).unwrap(), token);
    assert!(
        !fixture.data.exists(),
        "token creation must not open an archive"
    );
}

#[test]
fn offline_status_requires_auth_and_rejects_duplicate_auth_and_request_bodies() {
    let fixture = Fixture::new();
    let token = fixture.create_token();
    let (child, address) = fixture.serve();
    let authorized = format!("Bearer {token}");
    let mut wrong_token = token.clone().into_bytes();
    wrong_token[0] = if wrong_token[0] == b'0' { b'1' } else { b'0' };
    let wrong = format!("Bearer {}", String::from_utf8(wrong_token).unwrap());
    for (headers, expected) in [
        (vec![], 401),
        (vec![("Authorization", wrong.as_str())], 401),
        (vec![("Authorization", "Bearer short")], 401),
        (vec![("Authorization", token.as_str())], 401),
        (
            vec![
                ("Authorization", authorized.as_str()),
                ("authorization", authorized.as_str()),
            ],
            400,
        ),
        (
            vec![
                ("authorization", wrong.as_str()),
                ("Authorization", authorized.as_str()),
            ],
            400,
        ),
        (
            vec![
                ("Authorization", authorized.as_str()),
                ("Content-Length", "1"),
            ],
            400,
        ),
        (
            vec![
                ("Authorization", authorized.as_str()),
                ("Transfer-Encoding", "chunked"),
            ],
            400,
        ),
    ] {
        let mut raw = request("GET", "/v1/status", &headers);
        if headers.iter().any(|&(name, _)| name == "Content-Length") {
            raw.push(b'x');
        }
        let response = exchange(address, &raw);
        assert_eq!(response.code, expected, "{headers:?}: {}", response.body);
    }
    let observed = status(address, &token);
    assert_eq!(observed["archive"]["api_version"], 1);
    assert_eq!(
        observed["archive"]["application_start"],
        serde_json::to_value(fixture.config.application_start).unwrap()
    );
    assert_eq!(
        observed["archive"]["chain_genesis"],
        fixture.config.application_start.hash.to_string()
    );
    assert_eq!(observed["archive"]["selected_tip"], Value::Null);
    assert_eq!(observed["archive"]["scanned_blocks"], 0);
    assert_eq!(observed["last_sync_error"], Value::Null);
    assert_eq!(observed["last_retention_error"], Value::Null);
    assert_eq!(observed["last_names_error"], Value::Null);
    assert_eq!(observed["last_sync_error_at"], Value::Null);
    assert_eq!(observed["last_cache_error_at"], Value::Null);
    assert_eq!(observed["retention_configured"], false);
    let typed: urma_node::model::ServiceStatus = serde_json::from_value(observed.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), observed);
    assert_eq!(
        observed["capabilities"],
        json!([
            "status",
            "header-sync",
            "full-block-scan",
            "record-read",
            "object-status",
            "object-pin",
            "cache-prune",
            "wire-index",
            "names-index"
        ])
    );
    assert!(!fixture.data.join("headers").exists());
    let response = exchange(
        address,
        &request(
            "GET",
            "/v1/status",
            &[("aUtHoRiZaTiOn", &authorized), ("Content-Length", "0")],
        ),
    );
    assert_eq!(response.code, 200);
    for headers in [vec![], vec![("Authorization", wrong.as_str())]] {
        assert_eq!(
            exchange(address, &request("POST", "/v1/shutdown", &headers)).code,
            401
        );
        assert_eq!(status(address, &token), observed);
    }
    for (method, path) in [
        ("GET", "/missing"),
        ("GET", "/v1/shutdown"),
        ("POST", "/v1/status"),
    ] {
        assert_eq!(
            exchange(
                address,
                &request(method, path, &[("Authorization", &authorized)])
            )
            .code,
            404
        );
    }
    shutdown(child, address, &token);
}

#[test]
fn malformed_and_oversized_headers_do_not_stop_the_service() {
    let fixture = Fixture::new();
    let token = fixture.create_token();
    let (child, address) = fixture.serve();
    let mut oversized =
        format!("GET /v1/status HTTP/1.1\r\nAuthorization: Bearer {token}\r\nX-Fill: ")
            .into_bytes();
    oversized.resize(9000, b'x');
    for raw in [
        b"GET /v1/status HTTP/1.1\r\nmalformed\r\n\r\n".to_vec(),
        b"GET /v1/status HTTP/1.1\r\nX-Test: \xff\r\n\r\n".to_vec(),
        oversized,
    ] {
        assert_eq!(exchange(address, &raw).code, 400);
        status(address, &token);
    }
    // A client disappearing before the delimiter is a connection failure,
    // not a shutdown request. No sleeps are needed to serialize acceptance.
    let mut disconnected = connect(address);
    disconnected
        .write_all(b"GET /v1/status HTTP/1.1\r\n")
        .unwrap();
    disconnected.shutdown(std::net::Shutdown::Write).unwrap();
    disconnected.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
    assert_eq!(disconnected.read(&mut [0; 1]).unwrap(), 0);
    status(address, &token);
    shutdown(child, address, &token);
}

#[test]
fn slow_header_deadline_is_total_time_even_while_bytes_keep_arriving() {
    let fixture = Fixture::new();
    let token = fixture.create_token();
    let (child, address) = fixture.serve();
    let mut stream = connect(address);
    let began = Instant::now();
    stream.write_all(b"G").unwrap();
    let result = thread::scope(|scope| {
        let (stop, stopped) = mpsc::sync_channel::<()>(1);
        let mut writer = stream.try_clone().unwrap();
        scope.spawn(move || {
            let deadline = began + HTTP_TIMEOUT;
            while Instant::now() < deadline {
                match stopped.recv_timeout(Duration::from_millis(200)) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if writer.write_all(b"x").is_err() {
                            break;
                        }
                    }
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        let result = response(&mut stream, began + HTTP_TIMEOUT);
        drop(stop); // Also drops on panic, waking the scoped writer for cleanup.
        result
    });
    let elapsed = began.elapsed();
    assert_eq!(result.code, 400, "{}", result.body);
    assert!(
        result.body["error"]
            .as_str()
            .unwrap()
            .starts_with("request header")
    );
    // Allow accept-loop/scheduler jitter, but distinguish the 3s absolute
    // deadline from a 2s inactivity timeout or an indefinitely reset deadline.
    assert!(
        elapsed >= Duration::from_millis(2800),
        "closed too soon: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "absolute deadline exceeded: {elapsed:?}"
    );
    status(address, &token);
    shutdown(child, address, &token);
}

#[test]
fn non_loopback_bind_is_refused_without_starting_a_source() {
    let fixture = Fixture::new();
    fixture.create_token();
    for address in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0"] {
        let result = fixture.serve_at(address).finish();
        assert!(!result.status.success());
        assert!(
            result.stderr.contains("service requires loopback"),
            "{}",
            result.stderr
        );
        assert!(!result.stderr.contains("URMA Node listening at"));
        assert!(!fixture.data.join("headers").exists());
    }
}

#[test]
fn config_and_token_size_and_format_are_refused_before_listening() {
    let fixture = Fixture::new();
    fixture.create_token();
    fs::write(&fixture.config_path, vec![b' '; 65537]).unwrap();
    let result = fixture.spawn(&["status"]).finish();
    assert!(!result.status.success());
    assert!(
        result.stderr.contains("config exceeds 64 KiB"),
        "{}",
        result.stderr
    );
    assert!(!fixture.data.exists());
    fs::write(
        &fixture.config_path,
        serde_json::to_vec(&fixture.config).unwrap(),
    )
    .unwrap();
    for token in ["a".repeat(129), "a".repeat(63), "z".repeat(64)] {
        fs::write(&fixture.token_path, token).unwrap();
        let result = fixture.serve_at("127.0.0.1:0").finish();
        assert!(!result.status.success());
        assert!(result.stderr.contains("token"), "{}", result.stderr);
        assert!(!result.stderr.contains("URMA Node listening at"));
    }
    fs::remove_file(&fixture.token_path).unwrap();
    let result = fixture.serve_at("127.0.0.1:0").finish();
    assert!(!result.status.success());
    assert!(!result.stderr.contains("URMA Node listening at"));
}

#[cfg(unix)]
#[test]
fn group_readable_token_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.create_token();
    fs::set_permissions(&fixture.token_path, fs::Permissions::from_mode(0o640)).unwrap();
    let result = fixture.serve_at("127.0.0.1:0").finish();
    assert!(!result.status.success());
    assert!(
        result
            .stderr
            .contains("must not be accessible by group or others"),
        "{}",
        result.stderr
    );
    assert!(!result.stderr.contains("URMA Node listening at"));
}

#[test]
fn shutdown_restart_preserves_scans_and_owner_lock_precedes_p2p_cache_creation() {
    let fixture = Fixture::new();
    let token = fixture.create_token();
    let durable = fixture.seed_scanned_genesis();
    let (mut first, address) = fixture.serve();
    assert_eq!(status(address, &token)["archive"], durable);
    first.assert_running();
    assert!(!fixture.data.join("headers").exists());
    let busy = fixture.spawn(&["status"]).finish();
    assert!(!busy.status.success());
    assert!(busy.stderr.contains("archive busy:"), "{}", busy.stderr);
    // This is the ONLY --p2p invocation. The first service is still alive and
    // owns the archive; the contender must fail before constructing a source.
    first.assert_running();
    let busy = fixture
        .spawn(&[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            fixture.token_path.to_str().unwrap(),
            "--p2p",
            "--no-commit-public",
        ])
        .finish();
    assert!(!busy.status.success());
    assert!(busy.stderr.contains("archive busy:"), "{}", busy.stderr);
    assert!(
        !fixture.data.join("headers").exists(),
        "loser created header cache before ownership"
    );
    assert!(!busy.stderr.contains("URMA Node listening at"));
    assert_eq!(status(address, &token)["archive"], durable);
    shutdown(first, address, &token);
    let local = fixture.spawn(&["status"]).finish();
    assert!(local.status.success(), "{}", local.stderr);
    assert_eq!(
        serde_json::from_str::<Value>(&local.stdout).unwrap(),
        durable
    );
    let (second, address) = fixture.serve();
    assert_eq!(status(address, &token)["archive"], durable);
    assert!(!fixture.data.join("headers").exists());
    shutdown(second, address, &token);
}

#[test]
fn panic_unwind_kills_and_reaps_the_service_and_releases_ownership() {
    let fixture = Fixture::new();
    fixture.create_token();
    let (child, _address) = fixture.serve();
    let reaped = child.reaped.clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = child;
        panic!("intentional harness cleanup regression");
    }));
    assert!(panic.is_err());
    assert!(
        reaped.load(Ordering::Acquire),
        "service child was not reaped during unwind"
    );
    let result = fixture.spawn(&["status"]).finish();
    assert!(
        result.status.success(),
        "owner lock leaked: {}",
        result.stderr
    );
}
