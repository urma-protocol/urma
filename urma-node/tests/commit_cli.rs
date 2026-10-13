//! Linux real-binary checks for Serve --commit-rpc-url/--commit-rpc-cookie.
//! Every case runs in an owned user+network namespace whose only interface is
//! loopback, so --p2p discovery cannot leave the host. The JSON-RPC peer is an
//! in-process loopback stub, never a live node. Genuine signed public vectors
//! sit in a mock-selected witness block; no PoW or consensus claim is made.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Block, Txid};
use common::{
    Body, FIRST_HEIGHT, MemorySource, SignedPair, point, profile, readonly_archive, witness_block,
};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node::{
    engine::Engine,
    model::{ArchiveConfig, Retention},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const COOKIE: &str = "__cookie__:5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5c0ffee5";
const LISTENING: &str = "URMA Node listening at ";
const NO_SUCH_TX: &str =
    "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_TIMEOUT: Duration = Duration::from_secs(20);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(60);

type Snapshot = BTreeMap<String, Vec<Vec<SqlValue>>>;

// Call only after every Engine and service process has released the archive.
fn snapshot(directory: &Path) -> Snapshot {
    let db = readonly_archive(directory);
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let quoted = format!("\"{}\"", table.replace('"', "\"\""));
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
            (table, rows)
        })
        .collect()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

// Bounded HTTP/1.1 message reader shared by the status client and RPC stub.
fn read_message(stream: &mut TcpStream, deadline: Instant) -> io::Result<(String, Vec<u8>)> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 8192 {
            return Err(io::Error::other("header limit"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).map_err(io::Error::other)?;
    let length = header(&head, "content-length")
        .ok_or_else(|| io::Error::other("missing content length"))?
        .parse::<usize>()
        .map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("body limit"));
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
    Ok((head, body))
}

fn http(address: SocketAddr, method: &str, path: &str) -> io::Result<(u16, Value)> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let mut stream = TcpStream::connect_timeout(&address, HTTP_TIMEOUT)?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT))?;
    stream.write_all(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n\
             Authorization: Bearer {TOKEN}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    let (head, body) = read_message(&mut stream, deadline)?;
    let code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::other("missing status"))?
        .parse()
        .map_err(io::Error::other)?;
    Ok((
        code,
        serde_json::from_slice(&body).map_err(io::Error::other)?,
    ))
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let group = byte(0) << 16 | byte(1) << 8 | byte(2);
        for (index, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                let sextet = usize::try_from((group >> shift) & 63).unwrap();
                out.push(char::from(TABLE[sextet]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) -> io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

type Calls = Arc<Mutex<Vec<(String, Value)>>>;

// What a cookie-authenticated local Litecoin RPC answers for this archive.
struct Answers {
    authorization: String,
    genesis: String,
    parent: Txid,
    raw: Vec<u8>,
    // Whole getindexinfo ["txindex"] result, as the node would report it.
    txindex: Value,
}

impl Answers {
    fn answer(&self, method: &str, params: &Value) -> (Value, Value) {
        match method {
            "getblockhash" if *params == json!([0]) => (json!(self.genesis), Value::Null),
            "getindexinfo" if *params == json!(["txindex"]) => (self.txindex.clone(), Value::Null),
            "getblockcount" => (json!(100), Value::Null),
            "getrawtransaction" if *params == json!([self.parent, false]) => {
                (json!(hex::encode(&self.raw)), Value::Null)
            }
            // bitcoind/litecoind absence shape for any other transaction.
            "getrawtransaction" => (Value::Null, json!({"code": -5, "message": NO_SUCH_TX})),
            _ => (
                Value::Null,
                json!({"code": -32601, "message": "Method not found"}),
            ),
        }
    }

    fn serve(
        &self,
        mut stream: TcpStream,
        calls: &Calls,
        rejected: &AtomicUsize,
    ) -> io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_write_timeout(Some(HTTP_TIMEOUT))?;
        let (head, body) = read_message(&mut stream, Instant::now() + HTTP_TIMEOUT)?;
        if !head.starts_with("POST / HTTP/1.1\r\n")
            || header(&head, "authorization") != Some(self.authorization.as_str())
        {
            rejected.fetch_add(1, Ordering::SeqCst);
            return respond(&mut stream, "401 Unauthorized", b"");
        }
        let request: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
        let method = request["method"].as_str().unwrap_or_default().to_owned();
        let params = request["params"].clone();
        let (result, error) = self.answer(&method, &params);
        calls.lock().unwrap().push((method, params));
        let status = if error.is_null() {
            "200 OK"
        } else {
            "500 Internal Server Error"
        };
        let reply = json!({"result": result, "error": error, "id": request["id"]});
        respond(&mut stream, status, &serde_json::to_vec(&reply).unwrap())
    }
}

struct Stub {
    address: SocketAddr,
    calls: Calls,
    rejected: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Stub {
    fn start(answers: Answers) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Calls::default();
        let rejected = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, refused, halted) = (calls.clone(), rejected.clone(), stop.clone());
        let thread = thread::spawn(move || {
            while !halted.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = answers.serve(stream, &log, &refused) {
                            eprintln!("rpc stub connection: {error}");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("rpc stub accept: {error}"),
                }
            }
        });
        Self {
            address,
            calls,
            rejected,
            stop,
            thread: Some(thread),
        }
    }

    fn fetches(&self, txid: Txid) -> usize {
        let call = ("getrawtransaction".to_owned(), json!([txid, false]));
        let calls = self.calls.lock().unwrap();
        calls.iter().filter(|&observed| *observed == call).count()
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("rpc stub panicked");
        }
    }

    fn finish(mut self) -> (Vec<(String, Value)>, usize) {
        self.halt();
        let calls = self.calls.lock().unwrap().clone();
        (calls, self.rejected.load(Ordering::SeqCst))
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct Completed {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

// Every spawned binary is owned here; Drop kills and reaps within a bound.
struct OwnedChild {
    child: Option<Child>,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl OwnedChild {
    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "service exited unexpectedly: {}",
            self.stderr()
        );
    }

    fn listening_address(&mut self) -> SocketAddr {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            self.assert_running();
            let stderr = self.stderr();
            if let Some(address) = stderr.lines().find_map(|line| {
                line.strip_prefix(LISTENING)?
                    .strip_suffix(" (authenticated loopback)")
            }) {
                let address: SocketAddr = address.parse().unwrap();
                assert!(address.ip().is_loopback());
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
                return Completed {
                    status,
                    stdout: fs::read_to_string(&self.stdout).unwrap(),
                    stderr: self.stderr(),
                };
            }
            assert!(
                Instant::now() < deadline,
                "exit timed out: {}",
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
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => {
                    eprintln!("child {} cleanup did not reap: {result:?}", child.id());
                    return;
                }
            }
        }
    }
}

struct Fixture {
    root: PathBuf,
    data: PathBuf,
    config_path: PathBuf,
    token_path: PathBuf,
    cookie_path: PathBuf,
    pair: SignedPair,
    // A second pending parent that the local RPC does not have (-5).
    absent: SignedPair,
    block: Block,
    config: ArchiveConfig,
    sequence: Cell<u32>,
}

impl Fixture {
    // Files only: the archive directory is created by seed() alone.
    fn new(root: &Path) -> Self {
        let pair = profile();
        let absent = SignedPair::load("proof-post");
        let reveals = [pair.reveal.clone(), absent.reveal.clone()];
        let block = witness_block(&reveals, None, 40001);
        let config = ArchiveConfig {
            chain: Chain::LitecoinTestnet,
            application_start: point(FIRST_HEIGHT, &block),
            retention: Retention::Pruned,
        };
        let fixture = Self {
            root: root.to_owned(),
            data: root.join("archive"),
            config_path: root.join("config.json"),
            token_path: root.join("service.token"),
            cookie_path: root.join("rpc.cookie"),
            pair,
            absent,
            block,
            config,
            sequence: Cell::new(0),
        };
        fs::write(
            &fixture.config_path,
            serde_json::to_vec(&fixture.config).unwrap(),
        )
        .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&fixture.token_path)
            .unwrap()
            .write_all(TOKEN.as_bytes())
            .unwrap();
        fs::write(&fixture.cookie_path, COOKIE).unwrap();
        fixture
    }

    // In-process scan leaves exactly two unresolved commit parents.
    fn seed(&self) -> Snapshot {
        let source = Arc::new(MemorySource::with_bodies(
            Chain::LitecoinTestnet,
            FIRST_HEIGHT,
            vec![Body::from(&self.block)],
        ));
        let engine = Engine::open(&self.data, self.config.clone(), Some(source)).unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.unresolved_dependencies, 2);
        assert_eq!(status.indexed_through, None);
        assert_eq!(status.stored_transactions, 0);
        drop(engine);
        snapshot(&self.data)
    }

    fn cookie(&self) -> &str {
        self.cookie_path.to_str().unwrap()
    }

    fn stub(&self, txindex: Value) -> Stub {
        Stub::start(Answers {
            authorization: format!("Basic {}", base64(COOKIE.as_bytes())),
            genesis: Chain::LitecoinTestnet.genesis().unwrap().0.to_string(),
            parent: self.pair.commit.compute_txid(),
            raw: self.pair.raw_commit.clone(),
            txindex,
        })
    }

    fn serve_rpc(&self, authority: &str) -> OwnedChild {
        let url = format!("http://{authority}/");
        self.serve(&[
            "--p2p",
            "--commit-rpc-url",
            &url,
            "--commit-rpc-cookie",
            self.cookie(),
            "--no-commit-public",
        ])
    }

    fn serve(&self, commit: &[&str]) -> OwnedChild {
        let sequence = self.sequence.get();
        self.sequence.set(sequence + 1);
        let stdout = self.root.join(format!("child-{sequence}.stdout"));
        let stderr = self.root.join(format!("child-{sequence}.stderr"));
        let child = Command::new(env!("CARGO_BIN_EXE_urma-node"))
            .env_clear()
            .env("TMPDIR", &self.root)
            .current_dir(&self.root)
            .arg("--data")
            .arg(&self.data)
            .arg("--config")
            .arg(&self.config_path)
            .args(["serve", "--listen", "127.0.0.1:0", "--token-file"])
            .arg(&self.token_path)
            .args(commit)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        OwnedChild {
            child: Some(child),
            stdout,
            stderr,
        }
    }
}

fn poll(child: &mut OwnedChild, address: SocketAddr, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        child.assert_running();
        let (code, status) = http(address, "GET", "/v1/status").unwrap();
        assert_eq!(code, 200, "{status}");
        if ready(&status) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not reach expected state: {status}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn shutdown(child: OwnedChild, address: SocketAddr) {
    let reply = http(address, "POST", "/v1/shutdown").unwrap();
    assert_eq!(reply, (200, json!({"stopping": true})));
    let result = child.finish();
    assert!(result.status.success(), "{}", result.stderr);
    assert!(
        matches!(TcpStream::connect_timeout(&address, HTTP_TIMEOUT),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused),
        "listener remains after shutdown"
    );
}

fn flags(control: &Path) {
    let fixture = Fixture::new(control);
    let url = "http://127.0.0.1:9/";
    let cookie = fixture.cookie();
    for (extra, missing) in [
        (
            vec!["--p2p", "--commit-rpc-url", url],
            "--commit-rpc-cookie",
        ),
        (
            vec!["--p2p", "--commit-rpc-cookie", cookie],
            "--commit-rpc-url",
        ),
        (
            vec!["--commit-rpc-url", url, "--commit-rpc-cookie", cookie],
            "--p2p",
        ),
    ] {
        let result = fixture.serve(&extra).finish();
        assert_eq!(
            result.status.code(),
            Some(2),
            "{extra:?}: {}",
            result.stderr
        );
        assert!(
            result.stderr.contains(missing),
            "{extra:?}: {}",
            result.stderr
        );
        assert!(!result.stderr.contains(LISTENING), "{}", result.stderr);
        assert!(result.stdout.is_empty(), "{}", result.stdout);
        assert!(!fixture.data.exists(), "{extra:?} touched the data dir");
    }
}

// The daemon serves while litecoind is down; local-rpc reports why.
fn local_rpc_error(child: &mut OwnedChild, address: SocketAddr, expected: &str) {
    let status = poll(child, address, |status| {
        status["commit_sources"][0]["last_error"]
            .as_str()
            .is_some_and(|error| error.contains(expected))
    });
    let shown = (&status["commit_sources"][0]["label"], &status["archive"]);
    assert_eq!(shown.0, "local-rpc", "{status}");
    assert_eq!(shown.1["unresolved_dependencies"], 2, "{status}");
}

fn unreachable(control: &Path) {
    let fixture = Fixture::new(control);
    fixture.seed();
    // Bound then released inside this namespace: connecting is refused.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let authority = format!("127.0.0.1:{port}");
    let mut child = fixture.serve_rpc(&authority);
    let address = child.listening_address();
    local_rpc_error(&mut child, address, "commit source: ");
    shutdown(child, address);
    fs::remove_file(&fixture.cookie_path).unwrap();
    let mut child = fixture.serve_rpc(&authority);
    let address = child.listening_address();
    local_rpc_error(&mut child, address, "cookie file missing: litecoind");
    shutdown(child, address);
}

// The node answers network verification but cannot serve parents by txid.
fn txindex_refused(control: &Path) {
    let fixture = Fixture::new(control);
    fixture.seed();
    for txindex in [
        json!({}),
        json!({"txindex": {"synced": false, "best_block_height": 50}}),
    ] {
        let stub = fixture.stub(txindex.clone());
        let mut child = fixture.serve_rpc(&stub.address.to_string());
        let address = child.listening_address();
        local_rpc_error(&mut child, address, "txindex=1");
        shutdown(child, address);
        let (calls, rejected) = stub.finish();
        assert_eq!(rejected, 0, "cookie authentication mismatch");
        assert_eq!(calls[..2], startup_calls()[..], "{txindex}");
        let fetches = calls
            .iter()
            .filter(|(method, _)| method == "getrawtransaction");
        assert_eq!(fetches.count(), 0, "{calls:?}");
    }
}

fn startup_calls() -> Vec<(String, Value)> {
    vec![
        ("getblockhash".to_owned(), json!([0])),
        ("getindexinfo".to_owned(), json!(["txindex"])),
    ]
}

fn resolves(control: &Path) {
    let fixture = Fixture::new(control);
    fixture.seed();
    let parent = fixture.pair.commit.compute_txid();
    let stub = fixture.stub(json!({"txindex": {"synced": true, "best_block_height": 100}}));
    let mut child = fixture.serve_rpc(&stub.address.to_string());
    let address = child.listening_address();
    let absent = fixture.absent.commit.compute_txid();
    // One parent per round: a second -5 fetch of the absent parent means the
    // worker finished a whole round after the first absent answer was recorded.
    let status = poll(&mut child, address, |status| {
        status["archive"]["unresolved_dependencies"] == 1 && stub.fetches(absent) >= 2
    });
    assert_eq!(
        status["commit_sources"][0]["label"], "local-rpc",
        "{status}"
    );
    assert!(status["last_dependency_error"].is_null(), "{status}");
    assert!(status["archive"]["indexed_through"].is_null(), "{status}");
    shutdown(child, address);
    let (calls, rejected) = stub.finish();
    assert_eq!(rejected, 0, "cookie authentication mismatch");
    assert_eq!(calls[..2], startup_calls()[..], "{calls:?}");
    let fetched = |txid: Txid| {
        let call = ("getrawtransaction".to_owned(), json!([txid, false]));
        calls.iter().filter(|&observed| *observed == call).count()
    };
    assert_eq!(fetched(parent), 1, "{calls:?}");
    assert!(fetched(absent) >= 2, "{calls:?}");
    let probes = calls.iter().filter(|(method, _)| method == "getblockcount");
    assert_eq!(
        2 + fetched(parent) + fetched(absent) + probes.count(),
        calls.len(),
        "{calls:?}"
    );
    let engine = Engine::open(&fixture.data, fixture.config.clone(), None).unwrap();
    assert_eq!(engine.status().unwrap().unresolved_dependencies, 1);
    let record = engine
        .record(fixture.pair.reveal.compute_txid())
        .unwrap()
        .unwrap();
    assert_eq!(record.package.commit, fixture.pair.raw_commit);
    assert_eq!(record.package.reveal.transaction, fixture.pair.raw_reveal);
    let pending = engine.record(fixture.absent.reveal.compute_txid());
    assert!(pending.unwrap().is_none());
}

#[test]
#[ignore = "owned loopback-only namespace host, not a standalone case"]
fn commit_cli_host() {
    let control = PathBuf::from(std::env::var_os("COMMIT_CLI_TEMP").expect("owned TEMP"));
    let case = std::env::var("COMMIT_CLI_CASE").unwrap();
    match case.as_str() {
        "flags" => flags(&control),
        "unreachable" => unreachable(&control),
        "txindex" => txindex_refused(&control),
        "resolve" => resolves(&control),
        _ => panic!("unknown owned case"),
    }
    fs::write(control.join("result"), &case).unwrap();
}

// A process group belongs exclusively to this host; SIGKILL is cleanup only.
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

fn bounded_text(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(file) = File::open(path) {
        let _ = file.take(1024 * 1024).read_to_string(&mut text);
    }
    text
}

fn run_host(case: &str) {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "sh", "-c"])
        .args(["ip link set lo up && exec \"$@\"", "commit-cli-netns"])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "commit_cli_host", "--nocapture"])
        .arg("--test-threads=1")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", directory.path())
        .env("COMMIT_CLI_TEMP", directory.path())
        .env("COMMIT_CLI_CASE", case)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(directory.path().join("stdout")).unwrap())
        .stderr(File::create(directory.path().join("stderr")).unwrap())
        .spawn()
        .unwrap();
    let logs = || {
        ["stdout", "stderr"]
            .map(|name| bounded_text(&directory.path().join(name)))
            .join("\n")
    };
    let deadline = Instant::now() + HOST_TIMEOUT;
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            assert!(exit.success(), "commit CLI host {case}: {exit}; {}", logs());
            let result = fs::read_to_string(directory.path().join("result")).unwrap();
            assert_eq!(result, case);
            return;
        }
        if Instant::now() >= deadline {
            let pid = i32::try_from(child.id()).unwrap();
            // SAFETY: process_group(0) made this owned child a group leader;
            // nothing outside this test was admitted to that group.
            unsafe {
                kill(-pid, 9);
            }
            let _ = child.wait();
            panic!("commit CLI host {case} exceeded bound; {}", logs());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn commit_rpc_flags_require_each_other_and_p2p_before_touching_data() {
    run_host("flags");
}

#[test]
fn stopped_litecoind_or_missing_cookie_starts_and_reports_local_rpc_error() {
    run_host("unreachable");
}

#[test]
fn absent_or_unsynced_txindex_starts_and_reports_without_fetching() {
    run_host("txindex");
}

#[test]
fn local_rpc_stub_resolves_the_missing_parent_through_the_real_binary() {
    run_host("resolve");
}
