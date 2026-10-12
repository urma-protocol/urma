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

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ROOT: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const OTHER: &str = "0808080808080808080808080808080808080808080808080808080808080808";
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

#[test]
fn status_and_object_emit_exact_json_and_404_emits_explicit_null() {
    let fixture = Fixture::new(format!("{TOKEN}\n").as_bytes());
    for (args, path, code, body, expected) in [
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
        let mock = Mock::new();
        let child = fixture.spawn(mock.address, &["pin", ROOT]);
        mock.respond(
            "POST",
            &format!("/v1/objects/{ROOT}/pin"),
            &response(code, br#"{"error":"refused"}"#),
        );
        let output = child.finish();
        failure(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!("HTTP {code}")));
        mock.assert_no_connection();
    }
}

#[test]
fn malformed_receipts_and_truncated_response_fail_without_retry_or_token_logs() {
    let fixture = Fixture::new(TOKEN.as_bytes());
    let mut lost_response = response(200, br#"{"records_removed":1}"#);
    let _ = lost_response.pop(); // Lost reply after possible mutation.
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
    ] {
        let mock = Mock::new();
        let child = fixture.spawn(mock.address, &args);
        mock.respond(
            if args[0] == "status" { "GET" } else { "POST" },
            &path,
            &raw,
        );
        failure(&child.finish());
        mock.assert_no_connection();
    }
}

#[test]
fn invalid_root_and_token_files_are_refused_before_any_http_connection() {
    let mock = Mock::new();
    let fixture = Fixture::new(TOKEN.as_bytes());
    for args in [
        ["object", "bad-root"],
        ["pin", "bad-root"],
        ["unpin", "bad-root"],
    ] {
        failure(&fixture.spawn(mock.address, &args).finish());
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
}

#[test]
fn exact_256_byte_token_file_is_bounded_then_validated_and_nonloopback_is_refused() {
    let mut bytes = TOKEN.as_bytes().to_vec();
    bytes.resize(256, b'\n');
    let fixture = Fixture::new(&bytes);
    let mock = Mock::new();
    let child = fixture.spawn(mock.address, &["status"]);
    mock.respond("GET", "/v1/status", &response(200, b"{}"));
    success(child.finish(), json!({}));
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
