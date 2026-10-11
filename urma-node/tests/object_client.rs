//! Object status over owned loopback only: mocks plus one real Service/Engine.
//! Availability reported by a local operator is not independent chain evidence.
#[allow(dead_code)]
mod common;

use bitcoin::{Txid, hashes::Hash};
use common::{FIRST_HEIGHT, MemorySource, SignedPair, config, point, witness_block};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, atomic::Ordering, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::multipart::MultipartRecord;
use urma_node::{
    Error,
    client::Client,
    engine::Engine,
    model::{ObjectStatus, Retention},
    retrieval::recover,
    service::Service,
};
use urma_runtime::multipart::{RecoveredObject, RecoveryLimits};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MOCK_TIMEOUT: Duration = Duration::from_secs(9);

// One real loopback connection, no service binary, database, config or chain
// source. Drop cancels acceptance/delays, shuts down the active socket and reaps
// the thread even when a test assertion unwinds. All socket loops are bounded.
struct Mock {
    address: SocketAddr,
    stop: Option<mpsc::Sender<()>>,
    active: Arc<Mutex<Option<TcpStream>>>,
    worker: Option<JoinHandle<()>>,
    request: mpsc::Receiver<Vec<u8>>,
}

// The cleanup socket must also close when the worker finishes normally, so
// truncated fixtures deliver EOF rather than merely waiting for a timeout.
struct ActiveSocket(Arc<Mutex<Option<TcpStream>>>);

impl Drop for ActiveSocket {
    fn drop(&mut self) {
        self.0.lock().unwrap().take();
    }
}

impl Mock {
    fn new(script: impl FnOnce(&mut TcpStream, &mpsc::Receiver<()>) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = mpsc::channel();
        let (sent, request) = mpsc::channel();
        let active = Arc::new(Mutex::new(None));
        let socket = active.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + MOCK_TIMEOUT;
            let mut stream = loop {
                if Instant::now() >= deadline || stopped.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Ok((stream, peer)) => {
                        assert!(peer.ip().is_loopback());
                        break stream;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if !matches!(
                            stopped.recv_timeout(Duration::from_millis(10)),
                            Err(mpsc::RecvTimeoutError::Timeout)
                        ) {
                            return;
                        }
                    }
                    Err(error) => panic!("mock accept: {error}"),
                }
            };
            *socket.lock().unwrap() = Some(stream.try_clone().unwrap());
            let _active = ActiveSocket(socket);
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                if bytes.len() >= 4096 || Instant::now() >= deadline {
                    return;
                }
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) => bytes.push(byte[0]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        if stopped.try_recv().is_ok() {
                            return;
                        }
                    }
                    _ => return,
                }
            }
            sent.send(bytes).unwrap();
            script(&mut stream, &stopped);
        });
        Self {
            address,
            stop: Some(stop),
            active,
            worker: Some(worker),
            request,
        }
    }

    fn raw(bytes: Vec<u8>) -> Self {
        Self::new(move |stream, _stop| {
            let _ = write_bounded(stream, &bytes);
        })
    }

    fn client(&self) -> Client {
        Client::new(self.address, TOKEN.into()).unwrap()
    }

    fn request(&self) -> String {
        String::from_utf8(self.request.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap()
    }

    fn cleanup(&mut self) -> bool {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(stream) = self.active.lock().unwrap().take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        if let Some(worker) = self.worker.take() {
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if worker.is_finished() {
                return worker.join().is_ok();
            }
            return false;
        }
        true
    }

    fn finish(mut self) {
        assert!(self.cleanup(), "mock thread did not finish cleanly");
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        if !self.cleanup() {
            eprintln!("mock cleanup failed");
        }
    }
}

fn write_bounded(stream: &mut TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn reply(code: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {code} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

// Ownership starts immediately after spawn. Cleanup uses only the service's
// existing authenticated shutdown endpoint, including during assertion unwind.
// Socket I/O and joining have absolute bounds; there is no unbounded join/read.
struct RunningService {
    address: SocketAddr,
    worker: Option<JoinHandle<Result<(), Error>>>,
}

impl RunningService {
    fn start(engine: Arc<Engine>) -> Self {
        let service = Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine).unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(false));
        Self {
            address,
            worker: Some(worker),
        }
    }

    fn client(&self) -> Client {
        Client::new(self.address, TOKEN.into()).unwrap()
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        let shutdown = if worker.is_finished() {
            Err("service exited before authenticated shutdown".into())
        } else {
            request_shutdown(self.address, deadline).map_err(|error| error.to_string())
        };
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("service shutdown/join exceeded 8s".into());
        }
        let outcome = worker
            .join()
            .map_err(|_| "service worker panicked".to_string())?;
        outcome.map_err(|error| error.to_string())?;
        shutdown
    }

    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("service cleanup: {error}");
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn read(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let count = match stream.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        remaining(deadline)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(count);
    }
}

fn request_shutdown(address: SocketAddr, deadline: Instant) -> io::Result<()> {
    assert!(address.ip().is_loopback());
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(1).min(remaining(deadline)?))?;
    let request = format!(
        "POST /v1/shutdown HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    let mut pending = request.as_bytes();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = match stream.write(pending) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        remaining(deadline)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[count..];
    }
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == 8192 {
            return Err(io::Error::other("shutdown header too large"));
        }
        let mut byte = [0];
        read(&mut stream, &mut byte, deadline)?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(io::Error::other)?;
    if !header.starts_with("HTTP/1.1 200 OK\r\n") {
        return Err(io::Error::other("shutdown refused"));
    }
    let lengths = header
        .split("\r\n")
        .filter_map(|line| line.strip_prefix("Content-Length: "))
        .collect::<Vec<_>>();
    if lengths.len() != 1 {
        return Err(io::Error::other("shutdown length missing or duplicated"));
    }
    let length: usize = lengths[0].parse().map_err(io::Error::other)?;
    if length > 4096 {
        return Err(io::Error::other("shutdown body too large"));
    }
    let mut body = vec![0; length];
    let mut received = 0;
    while received < length {
        received += read(&mut stream, &mut body[received..], deadline)?;
    }
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
    if value != serde_json::json!({"stopping":true}) {
        return Err(io::Error::other("unexpected shutdown response"));
    }
    Ok(())
}

fn sample() -> ObjectStatus {
    ObjectStatus {
        root: Txid::from_byte_array([7; 32]),
        verified_generation: 11,
        payload_bytes: 123,
        members_total: 3,
        members_local: 3,
        members_selected: 3,
        pinned: false,
    }
}

fn assert_same(actual: &ObjectStatus, expected: &ObjectStatus) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn object_status_uses_authenticated_endpoint_and_keeps_counts_independent() {
    for (local, selected) in [(1, 3), (3, 1), (0, 0)] {
        let expected = ObjectStatus {
            members_local: local,
            members_selected: selected,
            ..sample()
        };
        let mock = Mock::raw(reply(
            200,
            "application/json; charset=utf-8",
            &serde_json::to_vec(&expected).unwrap(),
        ));
        let actual = mock.client().object_status(expected.root).unwrap().unwrap();
        assert_same(&actual, &expected);
        assert_eq!(
            mock.request(),
            format!(
                "GET /v1/objects/{} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
                expected.root, mock.address
            )
        );
        mock.finish();
    }
}

#[test]
fn object_status_refuses_wrong_root_and_impossible_counts() {
    let expected = sample();
    let mock = Mock::raw(reply(
        200,
        "application/json",
        &serde_json::to_vec(&expected).unwrap(),
    ));
    let error = mock
        .client()
        .object_status(Txid::from_byte_array([8; 32]))
        .unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("root differs")),
        "{error}"
    );
    mock.finish();
    for (total, local, selected) in [(0, 0, 0), (0, 1, 1), (3, 4, 1), (3, 1, 4)] {
        let invalid = ObjectStatus {
            members_total: total,
            members_local: local,
            members_selected: selected,
            ..sample()
        };
        let mock = Mock::raw(reply(
            200,
            "application/json",
            &serde_json::to_vec(&invalid).unwrap(),
        ));
        let error = mock.client().object_status(invalid.root).unwrap_err();
        assert!(
            matches!(error, Error::Invalid(ref message) if message.contains("impossible member counts")),
            "{error}"
        );
        mock.finish();
    }
    let mut malformed = Vec::new();
    for (field, value) in [
        ("members_total", json!(-1)),
        ("members_local", json!(1.5)),
        ("members_selected", json!("3")),
        ("pinned", json!(1)),
    ] {
        let mut value_json = serde_json::to_value(&expected).unwrap();
        value_json[field] = value;
        malformed.push(serde_json::to_vec(&value_json).unwrap());
    }
    let mut missing = serde_json::to_value(&expected).unwrap();
    missing.as_object_mut().unwrap().remove("members_total");
    malformed.extend([
        serde_json::to_vec(&missing).unwrap(),
        b"null".to_vec(),
        b"{broken".to_vec(),
    ]);
    for body in malformed {
        let mock = Mock::raw(reply(200, "application/json", &body));
        assert!(matches!(
            mock.client().object_status(expected.root),
            Err(Error::Json(_))
        ));
        mock.finish();
    }
}

#[test]
fn only_well_framed_json_404_is_local_unknown_other_codes_are_errors() {
    let root = sample().root;
    let mock = Mock::raw(reply(
        404,
        "application/json",
        br#"{"error":"no completed object recorded locally"}"#,
    ));
    assert!(mock.client().object_status(root).unwrap().is_none());
    mock.finish();
    for code in [201, 204, 301, 302, 307, 308, 400, 401, 403, 413, 500] {
        let mock = Mock::raw(reply(code, "application/json", b"{}"));
        let error = mock.client().object_status(root).unwrap_err();
        assert!(
            matches!(error, Error::Invalid(ref message) if message.contains(&format!("HTTP {code}"))),
            "{error}"
        );
        mock.finish();
    }
    let mock = Mock::raw(reply(404, "application/json", b"invalid"));
    assert!(matches!(
        mock.client().object_status(root),
        Err(Error::Json(_))
    ));
    mock.finish();
}

#[test]
fn object_status_inherits_strict_bounded_http_framing() {
    let expected = sample();
    let body = serde_json::to_vec(&expected).unwrap();
    let length = body.len();
    for header in [
        format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}"),
        format!("HTTP/1.1 20 OK\r\nContent-Type: application/json\r\nContent-Length: {length}"),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\ncontent-length: {length}"
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}, {length}"
        ),
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: +{length}"),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json".into(),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {length}"),
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {length}"),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nTransfer-Encoding: chunked"
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nMalformed"
        ),
    ] {
        let mut raw = format!("{header}\r\n\r\n").into_bytes();
        raw.extend_from_slice(&body);
        let mock = Mock::raw(raw);
        assert!(
            matches!(
                mock.client().object_status(expected.root),
                Err(Error::Invalid(_))
            ),
            "accepted malformed framing {header:?}"
        );
        mock.finish();
    }
    let mock = Mock::raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433\r\n\r\n"
            .to_vec(),
    );
    let error = mock.client().object_status(expected.root).unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("32 MiB")),
        "{error}"
    );
    mock.finish();
    let mut oversized = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    oversized.resize(8193, b'x');
    let mock = Mock::raw(oversized);
    let error = mock.client().object_status(expected.root).unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("8192")),
        "{error}"
    );
    mock.finish();

    let mut exact = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nX-Fill: "
    )
    .into_bytes();
    exact.resize(8192 - 4, b'x');
    exact.extend_from_slice(b"\r\n\r\n");
    exact.extend_from_slice(&body);
    let mock = Mock::raw(exact);
    assert_same(
        &mock.client().object_status(expected.root).unwrap().unwrap(),
        &expected,
    );
    mock.finish();

    for code in [200, 404] {
        let mut truncated = reply(code, "application/json", &body);
        truncated.pop();
        let mock = Mock::raw(truncated);
        let error = mock.client().object_status(expected.root).unwrap_err();
        assert!(
            matches!(error, Error::Io(ref cause) if cause.kind() == io::ErrorKind::UnexpectedEof),
            "{error}"
        );
        mock.finish();
    }
}

#[test]
fn object_status_uses_one_deadline_for_connect_headers_and_progressing_body() {
    let expected = sample();
    let body = serde_json::to_vec(&expected).unwrap();
    let mock = Mock::new(move |stream, stop| {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        if write_bounded(stream, header.as_bytes()).is_err() {
            return;
        }
        if !matches!(
            stop.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            return;
        }
        if write_bounded(stream, b"\r\n").is_err() {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(6);
        for byte in body {
            if Instant::now() >= deadline {
                return;
            }
            if !matches!(
                stop.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                return;
            }
            if write_bounded(stream, &[byte]).is_err() {
                return;
            }
        }
    });
    let began = Instant::now(); // Includes connect and all I/O in object_status.
    let error = mock.client().object_status(expected.root).unwrap_err();
    let elapsed = began.elapsed();
    assert!(
        matches!(error, Error::Io(ref cause) if matches!(cause.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)),
        "{error}"
    );
    assert!(
        elapsed >= Duration::from_millis(4700),
        "deadline too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(6500),
        "deadline reset: {elapsed:?}"
    );
    mock.finish();
}

fn assert_payload(mut object: RecoveredObject, root: Txid, expected: &[u8]) {
    assert_eq!(object.root(), root);
    assert_eq!(object.manifest().length, expected.len() as u64);
    let mut bytes = vec![0; expected.len()];
    object.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(object.read(&mut [0]).unwrap(), 0);
}

fn read_status(client: &Client, engine: &Engine, root: Txid) -> ObjectStatus {
    let remote = client.object_status(root).unwrap().unwrap();
    assert_same(&remote, &engine.object_status(root).unwrap().unwrap());
    remote
}

#[test]
fn real_service_reports_recovery_pruning_pin_and_reorg_without_mixing_selection_and_retention() {
    let pairs = ["one-root", "one-leaf", "one-part-0"]
        .map(|name| SignedPair::load(&format!("multipart/{name}")));
    let root = pairs[0].reveal.compute_txid();
    let leaf = pairs[1].reveal.compute_txid();
    let MultipartRecord::Data(data) = pairs[2].verified.decode().unwrap() else {
        panic!("data fixture");
    };
    let payload = data.payload;
    let blocks = pairs
        .iter()
        .enumerate()
        .fold(Vec::new(), |mut blocks, (i, pair)| {
            blocks.push(witness_block(
                &pair.transactions(),
                blocks.last(),
                80 + i as u32,
            ));
            blocks
        });
    let source = Arc::new(MemorySource::new(&blocks));
    let directory = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let engine = Arc::new(
        Engine::open(
            directory.path(),
            config(&blocks[0], Retention::Pruned),
            Some(source.clone()),
        )
        .unwrap(),
    );
    engine.synchronize_headers().unwrap();
    for _ in &blocks {
        engine.scan_next().unwrap();
    }
    let scanned = engine.status().unwrap();
    assert_eq!(scanned.scanned_blocks, 3);
    assert_eq!(
        scanned.indexed_through,
        Some(point(FIRST_HEIGHT + 2, &blocks[2]))
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 3);
    assert!(engine.record(root).unwrap().is_some());

    // Exactly one real Service and Engine; no daemon process or discovery.
    let service = RunningService::start(engine.clone());
    let client = service.client();
    assert!(
        client.object_status(root).unwrap().is_none(),
        "a known root record alone is not a reconstructed object"
    );
    assert!(client.object_status(Txid::all_zeros()).unwrap().is_none());
    let wrong = Client::new(service.address, "f".repeat(64)).unwrap();
    let error = wrong.object_status(root).unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("HTTP 401")),
        "{error}"
    );

    let limits = RecoveryLimits {
        timeout: Duration::from_secs(5),
        ..RecoveryLimits::new(payload.len() as u64, pairs.len() as u32)
    };
    assert_payload(
        recover(&engine, root, &[], limits, scratch.path()).unwrap(),
        root,
        &payload,
    );
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
    let complete = read_status(&client, &engine, root);
    assert_eq!(complete.members_total, 3);
    assert_eq!(complete.members_local, 3);
    assert_eq!(complete.members_selected, 3);
    assert_eq!(complete.payload_bytes, payload.len() as u64);
    assert_eq!(complete.verified_generation, scanned.generation);
    assert!(complete.locally_complete());
    assert!(complete.selected_complete());
    assert!(!complete.pinned);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 5);

    assert_eq!(engine.prune_cache().unwrap(), 2);
    let partial = read_status(&client, &engine, root);
    assert_eq!(partial.members_total, 3);
    assert_eq!(partial.members_local, 1);
    assert_eq!(
        partial.members_selected, 3,
        "pruning does not change selected placements"
    );
    assert_eq!(partial.verified_generation, complete.verified_generation);
    assert!(!partial.locally_complete());
    assert!(!partial.pinned);
    assert!(engine.record(root).unwrap().is_some());
    assert_eq!(
        engine.status().unwrap().indexed_through,
        scanned.indexed_through
    );
    assert_eq!(
        engine.status().unwrap().scanned_blocks,
        scanned.scanned_blocks
    );
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 5);

    assert_payload(
        recover(&engine, root, &[], limits, scratch.path()).unwrap(),
        root,
        &payload,
    );
    engine.set_pin(root, true).unwrap();
    let pinned = read_status(&client, &engine, root);
    assert!(pinned.pinned);
    assert_eq!((pinned.members_local, pinned.members_selected), (3, 3));
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_eq!(source.body_calls.load(Ordering::Relaxed), 7);

    let replacement_leaf = witness_block(&[], Some(&blocks[0]), 90);
    let replacement_data = witness_block(&[], Some(&replacement_leaf), 91);
    source.replace_branch(&[
        blocks[0].clone(),
        replacement_leaf,
        replacement_data.clone(),
    ]);
    let reorged = engine.synchronize_headers().unwrap();
    assert_eq!(reorged.generation, scanned.generation + 1);
    assert_eq!(
        reorged.selected_tip,
        Some(point(FIRST_HEIGHT + 2, &replacement_data))
    );
    let orphan_members = read_status(&client, &engine, root);
    assert_eq!(orphan_members.members_total, 3);
    assert_eq!(orphan_members.members_local, 3);
    assert_eq!(orphan_members.members_selected, 1);
    assert_eq!(
        orphan_members.verified_generation,
        complete.verified_generation
    );
    assert!(orphan_members.locally_complete());
    assert!(!orphan_members.selected_complete());
    assert!(orphan_members.pinned);
    assert!(
        client.record(leaf).unwrap().is_none(),
        "old member is no longer selected despite retained local bytes"
    );
    assert_eq!(engine.prune_cache().unwrap(), 0);
    assert_same(&read_status(&client, &engine, root), &orphan_members);
    assert_eq!(
        source.body_calls.load(Ordering::Relaxed),
        7,
        "status reads do not fetch blocks"
    );
    service.finish();
    assert_eq!(
        Arc::strong_count(&engine),
        1,
        "service Engine was not released"
    );
}
