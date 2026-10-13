//! Standalone client against owned fake loopback HTTP; no daemon or archive.
#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    cell::RefCell,
    fs::{self, File},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use urma_names::state::{Outcome, Resolution, Verdict};
use urma_node::{
    model::ChainPoint,
    names::{NamesResolution, NamesStatus, NamesStep},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ROOT: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const OTHER: &str = "0808080808080808080808080808080808080808080808080808080808080808";
const PROJECTED_HASH: &str = "0909090909090909090909090909090909090909090909090909090909090909";
const TIP_HASH: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
const MAX_HEIGHT: &str = "9223372036854775807";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const LOG_LIMIT: usize = 64 * 1024;

struct Completed {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// File-backed output avoids pipe-reader threads or waiting on a full pipe.
// Every child is guarded immediately after spawn, including assertion unwinds.
struct OwnedChild {
    child: Option<Child>,
    stdout: PathBuf,
    stderr: PathBuf,
    reaped: Arc<AtomicBool>,
}

impl OwnedChild {
    fn finish(mut self) -> Completed {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.child.take();
                self.reaped.store(true, Ordering::Release);
                return Completed {
                    status,
                    stdout: bounded_log(&self.stdout),
                    stderr: bounded_log(&self.stderr),
                };
            }
            assert!(
                Instant::now() < deadline,
                "control client exceeded process deadline"
            );
            thread::sleep(Duration::from_millis(5));
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
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                result => {
                    eprintln!("control child {} was not reaped: {result:?}", child.id());
                    return;
                }
            }
        }
    }
}

fn bounded_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(LOG_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= LOG_LIMIT, "child log exceeded bound");
    bytes
}

struct Fixture {
    directory: tempfile::TempDir,
    token: PathBuf,
    logs: RefCell<Vec<PathBuf>>,
}

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("control-token");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)
            .unwrap();
        file.write_all(bytes).unwrap();
        Self {
            directory,
            token,
            logs: RefCell::new(Vec::new()),
        }
    }

    fn spawn(&self, endpoint: SocketAddr, args: &[&str]) -> OwnedChild {
        self.spawn_with_token(endpoint, &self.token, args)
    }

    fn spawn_with_token(&self, endpoint: SocketAddr, token: &Path, args: &[&str]) -> OwnedChild {
        let stdout = tempfile::NamedTempFile::new_in(self.directory.path()).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(self.directory.path()).unwrap();
        let stdout_path = stdout.into_temp_path().keep().unwrap();
        let stderr_path = stderr.into_temp_path().keep().unwrap();
        self.logs
            .borrow_mut()
            .extend([stdout_path.clone(), stderr_path.clone()]);
        let reaped = Arc::new(AtomicBool::new(false));
        let child = Command::new(env!("CARGO_BIN_EXE_urma-node-control"))
            .env_clear()
            .current_dir(self.directory.path())
            .arg("--endpoint")
            .arg(endpoint.to_string())
            .arg("--token-file")
            .arg(token)
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout_path).unwrap())
            .stderr(File::create(&stderr_path).unwrap())
            .spawn()
            .unwrap();
        OwnedChild {
            child: Some(child),
            stdout: stdout_path,
            stderr: stderr_path,
            reaped,
        }
    }

    fn assert_only_owned_files(&self) {
        // Each invocation may read the token and write these two harness logs;
        // it must not create a DB, config, owner lock, wallet or daemon state.
        for entry in fs::read_dir(self.directory.path()).unwrap() {
            let path = entry.unwrap().path();
            assert!(path.is_file(), "CLI created an unexpected directory");
            assert!(
                path == self.token || self.logs.borrow().contains(&path),
                "CLI created a file outside token/harness logs"
            );
        }
    }
}

// Synchronous fake HTTP requires no worker thread. Keep the listener alive
// until child exit so a second connection exposes retries or implicit readback.
struct Mock {
    listener: TcpListener,
    address: SocketAddr,
}

impl Mock {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        Self { listener, address }
    }

    fn accept(&self) -> TcpStream {
        let deadline = Instant::now() + HTTP_TIMEOUT;
        loop {
            match self.listener.accept() {
                Ok((stream, address)) => {
                    assert!(address.ip().is_loopback());
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "client did not connect to owned HTTP endpoint"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fake accept: {error}"),
            }
        }
    }

    fn respond(&self, method: &str, path: &str, raw: &[u8]) {
        let mut stream = self.accept();
        let deadline = Instant::now() + HTTP_TIMEOUT;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096, "request exceeded mock header bound");
            stream.set_read_timeout(Some(remaining(deadline))).unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 1, "request truncated");
            request.push(byte[0]);
        }
        let request = std::str::from_utf8(&request).unwrap();
        assert!(
            request.starts_with(&format!("{method} {path} HTTP/1.1\r\n")),
            "unexpected method/path"
        );
        assert!(
            request.contains(&format!("\r\nAuthorization: Bearer {TOKEN}\r\n")),
            "missing bearer authentication"
        );
        assert!(request.contains("\r\nConnection: close\r\n"));
        if method == "POST" {
            assert_eq!(request.matches("Content-Length: 0\r\n").count(), 1);
        }
        let mut pending = raw;
        while !pending.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline))).unwrap();
            let count = stream.write(pending).unwrap();
            assert_ne!(count, 0);
            pending = &pending[count..];
        }
        stream.shutdown(Shutdown::Write).unwrap();
        // The client request has no body and finishes by closing the socket.
        // Retaining no unread byte also catches an accidental outbound body.
        let mut byte = [0];
        stream.set_read_timeout(Some(remaining(deadline))).unwrap();
        assert_eq!(
            stream.read(&mut byte).unwrap(),
            0,
            "request body must be empty"
        );
    }

    fn assert_no_connection(&self) {
        match self.listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("unexpected connection: retry/readback or invalid-input I/O"),
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .expect("mock HTTP deadline exceeded")
}

fn response(code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn success(output: Completed, value: Value) {
    assert!(output.status.success(), "control command failed");
    assert!(output.stderr.is_empty(), "success wrote stderr");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        value
    );
    assert!(output.stdout.ends_with(b"\n"));
}

fn failure(output: &Completed) {
    assert!(!output.status.success(), "invalid command succeeded");
    assert!(output.stdout.is_empty(), "failure wrote success JSON");
    assert!(!output.stderr.is_empty(), "failure omitted stderr");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(TOKEN),
        "failure exposed bearer token"
    );
}

fn object() -> Value {
    json!({"root": ROOT, "verified_generation": 9, "payload_bytes": 123,
        "members_total": 3, "members_local": 1, "members_selected": 3, "pinned": false})
}

// Complete service status. The control binary dumps the operator JSON
// verbatim: unknown fields survive and older, partial bodies still print.
fn service_status() -> Value {
    json!({
        "archive": {"api_version": 1, "chain_genesis": OTHER,
            "application_start": {"height": 100, "hash": OTHER}, "retention": "pruned",
            "generation": 9, "selected_tip": null, "indexed_through": null,
            "scanned_blocks": 0, "unresolved_dependencies": 0, "stored_transactions": 0,
            "scan_rules_version": 1, "peer_synced_through": null, "peer_omissions": 0,
            "unaudited_records": 0},
        "last_sync_error": "offline", "last_sync_error_at": 1_760_000_000u64,
        "last_retention_error": null, "last_retention_error_at": null,
        "last_names_error": null, "last_names_error_at": null,
        "last_dependency_error": null, "last_dependency_error_at": null,
        "last_inventory_error": null, "last_inventory_error_at": null,
        "commit_sources": [{"label": "A", "last_error": "down", "last_error_at": 7}],
        "cache_limit_bytes": 134_217_728u64, "last_cache_error": null,
        "last_cache_error_at": null, "last_cache_maintenance": null,
        "overlay": {"peer_id": "self", "listen": null, "peer_book": 2, "connected": 1,
            "admitted": 3, "rejected": 0, "peers": [{"label": "p", "cursor": 5,
            "synced_through": 4, "last_error": null, "last_error_at": null}]},
        "retention_configured": false, "record_sources_configured": 0,
        "capabilities": ["status"]
    })
}

fn future_service_status() -> Value {
    let mut status = service_status();
    status["field_from_a_newer_operator"] = json!(true);
    status
}

// Coherent operator DTOs for CLI transport/JSON tests, not chain placements,
// signed observations or evidence of real Names ownership/scan coverage.
fn names_status(height: u64) -> NamesStatus {
    let point = ChainPoint {
        height,
        hash: OTHER.parse().unwrap(),
    };
    NamesStatus {
        genesis: ROOT.parse().unwrap(),
        genesis_block: point,
        projected: point,
        generation: 9,
        selected_tip: Some(point),
        complete_to_tip: true,
    }
}

fn names_step() -> NamesStep {
    let mut status = names_status(100);
    status.projected = ChainPoint {
        height: 102,
        hash: PROJECTED_HASH.parse().unwrap(),
    };
    status.selected_tip = Some(ChainPoint {
        height: 103,
        hash: TIP_HASH.parse().unwrap(),
    });
    status.complete_to_tip = false;
    NamesStep {
        applied: Some(status.projected),
        status,
        rolled_back: 0,
        outcomes: vec![Outcome {
            txid: OTHER.parse().unwrap(),
            position: 1,
            verdict: Verdict::Pending,
        }],
    }
}

fn names_resolution() -> NamesResolution {
    NamesResolution {
        status: names_status(100),
        resolution: Resolution::Unbound,
    }
}

#[test]
fn status_and_object_emit_exact_json_and_404_emits_explicit_null() {
    let fixture = Fixture::new(format!("{TOKEN}\n").as_bytes());
    for (args, path, code, body, expected) in [
        (
            vec!["status"],
            "/v1/status".to_owned(),
            200,
            future_service_status(),
            future_service_status(),
        ),
        (
            vec!["status"],
            "/v1/status".to_owned(),
            200,
            json!({"archive":{"scanned_blocks":0},"last_sync_error":null}),
            json!({"archive":{"scanned_blocks":0},"last_sync_error":null}),
        ),
        (
            vec!["object", ROOT],
            format!("/v1/objects/{ROOT}"),
            200,
            object(),
            object(),
        ),
        (
            vec!["object", ROOT],
            format!("/v1/objects/{ROOT}"),
            404,
            json!({"error":"unknown locally"}),
            Value::Null,
        ),
        (
            vec!["names-status", ROOT],
            format!("/v1/names/{ROOT}"),
            200,
            serde_json::to_value(names_status(100)).unwrap(),
            serde_json::to_value(names_status(100)).unwrap(),
        ),
        (
            vec!["names-status", ROOT],
            format!("/v1/names/{ROOT}"),
            404,
            json!({"error":"unregistered locally"}),
            Value::Null,
        ),
        (
            vec!["names-resolve", ROOT, "atelier"],
            format!("/v1/names/{ROOT}/resolve/atelier"),
            200,
            serde_json::to_value(names_resolution()).unwrap(),
            serde_json::to_value(names_resolution()).unwrap(),
        ),
        (
            vec!["names-resolve", ROOT, "a-1"],
            format!("/v1/names/{ROOT}/resolve/a-1"),
            200,
            serde_json::to_value(names_resolution()).unwrap(),
            serde_json::to_value(names_resolution()).unwrap(),
        ),
    ] {
        let mock = Mock::new();
        let child = fixture.spawn(mock.address, &args);
        mock.respond(
            "GET",
            &path,
            &response(code, &serde_json::to_vec(&body).unwrap()),
        );
        success(child.finish(), expected);
        mock.assert_no_connection();
    }
    fixture.assert_only_owned_files();
}

#[test]
fn overlay_commands_print_lists_and_fail_on_disabled_overlay() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    let omission = json!({"peer":"p","block":{"height":1,"hash":OTHER},"position":0,"txid":ROOT,"generation":0});
    let entry = json!({"peer_id":null,"addrs":["/ip4/127.0.0.1/tcp/1"],"origin":"seed",
        "last_success":null,"failures":2,"banned_until":60});
    let disabled = json!({"error":"overlay disabled"});
    for (command, value) in [("omissions", json!([omission])), ("book", json!([entry]))] {
        for (code, body) in [(200, &value), (404, &disabled)] {
            let mock = Mock::new();
            let child = fixture.spawn(mock.address, &[&format!("overlay-{command}")]);
            let reply = response(code, &serde_json::to_vec(body).unwrap());
            mock.respond("GET", &format!("/v1/overlay/{command}"), &reply);
            let output = child.finish();
            match code {
                200 => success(output, value.clone()),
                _ => failure(&output),
            }
            mock.assert_no_connection();
        }
    }
    fixture.assert_only_owned_files();
}

#[test]
fn pin_unpin_and_prune_emit_typed_receipts_without_implicit_readback() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    for (args, path, value) in [
        (
            vec!["pin", ROOT],
            format!("/v1/objects/{ROOT}/pin"),
            json!({"root":ROOT,"pinned":true}),
        ),
        (
            vec!["unpin", ROOT],
            format!("/v1/objects/{ROOT}/unpin"),
            json!({"root":ROOT,"pinned":false}),
        ),
        (
            vec!["prune"],
            "/v1/cache/prune".into(),
            json!({"records_removed":7}),
        ),
        (
            vec!["prune"],
            "/v1/cache/prune".into(),
            json!({"records_removed":0}),
        ),
        (
            vec!["names-register", ROOT, "100", OTHER],
            format!("/v1/names/{ROOT}/register?height=100&hash={OTHER}"),
            serde_json::to_value(names_status(100)).unwrap(),
        ),
        (
            vec!["names-register", ROOT, "0", OTHER],
            format!("/v1/names/{ROOT}/register?height=0&hash={OTHER}"),
            serde_json::to_value(names_status(0)).unwrap(),
        ),
        (
            vec!["names-register", ROOT, MAX_HEIGHT, OTHER],
            format!("/v1/names/{ROOT}/register?height={MAX_HEIGHT}&hash={OTHER}"),
            serde_json::to_value(names_status(i64::MAX as u64)).unwrap(),
        ),
        (
            vec!["names-step", ROOT],
            format!("/v1/names/{ROOT}/step"),
            serde_json::to_value(names_step()).unwrap(),
        ),
    ] {
        let mock = Mock::new();
        let child = fixture.spawn(mock.address, &args);
        mock.respond(
            "POST",
            &path,
            &response(200, &serde_json::to_vec(&value).unwrap()),
        );
        success(child.finish(), value);
        mock.assert_no_connection();
    }
    fixture.assert_only_owned_files();
}

#[test]
fn authentication_conflict_incomplete_and_internal_failures_are_nonzero_without_retry() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    for code in [400, 401, 409, 422, 500] {
        for (args, method, path) in [
            (vec!["pin", ROOT], "POST", format!("/v1/objects/{ROOT}/pin")),
            (
                vec!["names-status", ROOT],
                "GET",
                format!("/v1/names/{ROOT}"),
            ),
            (
                vec!["names-register", ROOT, "100", OTHER],
                "POST",
                format!("/v1/names/{ROOT}/register?height=100&hash={OTHER}"),
            ),
            (
                vec!["names-step", ROOT],
                "POST",
                format!("/v1/names/{ROOT}/step"),
            ),
            (
                vec!["names-resolve", ROOT, "atelier"],
                "GET",
                format!("/v1/names/{ROOT}/resolve/atelier"),
            ),
        ] {
            let mock = Mock::new();
            let child = fixture.spawn(mock.address, &args);
            mock.respond(method, &path, &response(code, br#"{"error":"refused"}"#));
            let output = child.finish();
            failure(&output);
            let message = String::from_utf8_lossy(&output.stderr);
            if code == 409 && args[0].starts_with("names-") {
                assert!(message.contains("busy"));
            } else {
                assert!(message.contains(&format!("HTTP {code}")));
            }
            mock.assert_no_connection();
        }
    }
    fixture.assert_only_owned_files();
}

#[test]
fn malformed_receipts_and_truncated_response_fail_without_retry_or_token_logs() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    let mut lost_response = response(200, br#"{"records_removed":1}"#);
    let _ = lost_response.pop(); // Lost reply after possible mutation.
    let mut lost_register = response(200, &serde_json::to_vec(&names_status(100)).unwrap());
    let _ = lost_register.pop();
    let mut lost_step = response(200, &serde_json::to_vec(&names_step()).unwrap());
    let _ = lost_step.pop();
    let mut reflected_names = serde_json::to_value(names_status(100)).unwrap();
    reflected_names["generation"] = json!(TOKEN);
    for (args, path, raw) in [
        (
            vec!["pin", ROOT],
            format!("/v1/objects/{ROOT}/pin"),
            response(
                200,
                &serde_json::to_vec(&json!({"root":OTHER,"pinned":true})).unwrap(),
            ),
        ),
        (
            vec!["unpin", ROOT],
            format!("/v1/objects/{ROOT}/unpin"),
            response(
                200,
                &serde_json::to_vec(&json!({"root":ROOT,"pinned":true})).unwrap(),
            ),
        ),
        (
            vec!["pin", ROOT],
            format!("/v1/objects/{ROOT}/pin"),
            response(
                200,
                &serde_json::to_vec(&json!({"root":ROOT,"pinned":TOKEN})).unwrap(),
            ),
        ),
        (
            vec!["prune"],
            "/v1/cache/prune".into(),
            response(200, br#"{"records_removed":-1}"#),
        ),
        (vec!["status"], "/v1/status".into(), response(200, b"{")),
        (vec!["prune"], "/v1/cache/prune".into(), lost_response),
        (
            vec!["names-status", ROOT],
            format!("/v1/names/{ROOT}"),
            response(200, &serde_json::to_vec(&reflected_names).unwrap()),
        ),
        (
            vec!["names-register", ROOT, "100", OTHER],
            format!("/v1/names/{ROOT}/register?height=100&hash={OTHER}"),
            lost_register,
        ),
        (
            vec!["names-step", ROOT],
            format!("/v1/names/{ROOT}/step"),
            lost_step,
        ),
    ] {
        let mock = Mock::new();
        let child = fixture.spawn(mock.address, &args);
        mock.respond(
            if matches!(args[0], "status" | "names-status") {
                "GET"
            } else {
                "POST"
            },
            &path,
            &raw,
        );
        let output = child.finish();
        failure(&output);
        if raw
            .windows(TOKEN.len())
            .any(|bytes| bytes == TOKEN.as_bytes())
        {
            assert!(String::from_utf8_lossy(&output.stderr).contains("[redacted]"));
        }
        mock.assert_no_connection();
    }
    fixture.assert_only_owned_files();
}

#[test]
fn invalid_root_and_token_files_are_refused_before_any_http_connection() {
    let mock = Mock::new();
    let fixture = Fixture::new(TOKEN.as_bytes());
    for args in [
        vec!["object", "bad-root"],
        vec!["pin", "bad-root"],
        vec!["unpin", "bad-root"],
        vec!["names-status", "bad-genesis"],
        vec!["names-register", "bad-genesis", "100", OTHER],
        vec!["names-step", "bad-genesis"],
        vec!["names-resolve", "bad-genesis", "atelier"],
        vec!["names-register", ROOT, "100", "bad-hash"],
        vec!["names-status"],
        vec!["names-register", ROOT],
        vec!["names-register", ROOT, "100"],
        vec!["names-step"],
        vec!["names-resolve", ROOT],
    ] {
        failure(&fixture.spawn(mock.address, &args).finish());
        mock.assert_no_connection();
    }
    for height in [
        "-1",
        "+1",
        "one",
        "1.5",
        "",
        "9223372036854775808",
        "18446744073709551616",
    ] {
        failure(
            &fixture
                .spawn(mock.address, &["names-register", ROOT, height, OTHER])
                .finish(),
        );
        mock.assert_no_connection();
    }
    let too_long = "a".repeat(64);
    for name in [
        "",
        "Atelier",
        "atelier/child",
        "atelier%2fchild",
        "-atelier",
        "atelier-",
        "ab--cd",
        "café",
        &too_long,
    ] {
        failure(
            &fixture
                .spawn(mock.address, &["names-resolve", ROOT, name])
                .finish(),
        );
        mock.assert_no_connection();
    }
    let absent = fixture.directory.path().join("absent-token");
    failure(
        &fixture
            .spawn_with_token(mock.address, &absent, &["status"])
            .finish(),
    );
    mock.assert_no_connection();
    failure(
        &fixture
            .spawn_with_token(mock.address, fixture.directory.path(), &["status"])
            .finish(),
    );
    mock.assert_no_connection();
    for bytes in [
        vec![],
        vec![b'g'; 64],
        vec![b'1'; 63],
        vec![b'1'; 65],
        vec![0xff; 64],
    ] {
        let invalid = Fixture::new(&bytes);
        failure(&invalid.spawn(mock.address, &["status"]).finish());
        mock.assert_no_connection();
    }
    fs::set_permissions(&fixture.token, fs::Permissions::from_mode(0o644)).unwrap();
    failure(&fixture.spawn(mock.address, &["status"]).finish());
    mock.assert_no_connection();
    fixture.assert_only_owned_files();
}

#[test]
fn exact_256_byte_token_file_is_bounded_then_validated_and_nonloopback_is_refused() {
    let mut bytes = TOKEN.as_bytes().to_vec();
    bytes.resize(256, b'\n');
    let fixture = Fixture::new(&bytes);
    let mock = Mock::new();
    let child = fixture.spawn(mock.address, &["status"]);
    let body = serde_json::to_vec(&service_status()).unwrap();
    mock.respond("GET", "/v1/status", &response(200, &body));
    success(child.finish(), service_status());
    mock.assert_no_connection();
    let mut oversized = TOKEN.as_bytes().to_vec();
    oversized.resize(257, b'\n');
    let oversized = Fixture::new(&oversized);
    let output = oversized.spawn(mock.address, &["status"]).finish();
    failure(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("256"));
    mock.assert_no_connection();
    // Unspecified is not loopback; this control never targets an external host.
    let nonloopback = SocketAddr::new("0.0.0.0".parse().unwrap(), mock.address.port());
    failure(&fixture.spawn(nonloopback, &["status"]).finish());
    mock.assert_no_connection();
}

#[test]
fn child_guard_kills_and_reaps_during_assertion_unwind() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    let mock = Mock::new();
    let mut child = fixture.spawn(mock.address, &["status"]);
    let reaped = child.reaped.clone();
    let _stream = mock.accept(); // Deliberately withhold a response.
    assert!(child.child.as_mut().unwrap().try_wait().unwrap().is_none());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = child;
        panic!("intentional assertion unwind");
    }));
    assert!(panic.is_err());
    assert!(reaped.load(Ordering::Acquire), "child guard did not reap");
}
