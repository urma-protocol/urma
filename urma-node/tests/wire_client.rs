//! Wire pages from owned loopback mocks only; metadata is operator data. No daemon, chain
//! source, database, user state, DNS or external network is involved.
use bitcoin::{BlockHash, Txid, Wtxid, hashes::Hash};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::{
    format::{PublicRecord, RecordKind, Urma},
    topics::Topics,
};
use urma_node::{
    Error,
    client::Client,
    model::{ArchiveStatus, ChainPoint, Retention},
    projection::{IndexSnapshot, WireCursor, WirePage, WireRecord},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MOCK_TIMEOUT: Duration = Duration::from_secs(9);

// The listener stays alive after its first reply to catch accidental retries.
// After the client returns, cleanup drains already queued connections before
// joining. Socket shutdown and cancellation also work during assertion unwind.
struct Mock {
    address: SocketAddr,
    stop: Option<mpsc::Sender<()>>,
    active: Arc<Mutex<Option<TcpStream>>>,
    worker: Option<JoinHandle<usize>>,
    request: mpsc::Receiver<Vec<u8>>,
}

struct ActiveSocket(Arc<Mutex<Option<TcpStream>>>);

impl Drop for ActiveSocket {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take();
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
                    return 0;
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
                            return 0;
                        }
                    }
                    Err(error) => panic!("mock accept: {error}"),
                }
            };
            *socket.lock().unwrap() = Some(stream.try_clone().unwrap());
            let mut bytes = Vec::new();
            {
                let _active = ActiveSocket(socket);
                while !bytes.ends_with(b"\r\n\r\n") {
                    if bytes.len() >= 4096 || Instant::now() >= deadline {
                        return 1;
                    }
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(1) => bytes.push(byte[0]),
                        Err(error) if retryable(&error) => {
                            if stopped.try_recv().is_ok() {
                                return 1;
                            }
                        }
                        _ => return 1,
                    }
                }
                script(&mut stream, &stopped);
                // EOF lets the client reject truncated replies immediately.
                let _ = stream.shutdown(Shutdown::Write);
                // Capture any bytes after the header to prove GET has no body.
                while bytes.len() < 4096 && Instant::now() < deadline {
                    let mut tail = [0; 256];
                    match stream.read(&mut tail) {
                        Ok(0) => break,
                        Ok(count) => bytes.extend_from_slice(&tail[..count]),
                        Err(error) if retryable(&error) => {
                            if stopped.try_recv().is_ok() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = sent.send(bytes);
            }
            drop(stream);
            let mut connections = 1;
            loop {
                // Drain before checking cancellation so a retry queued during
                // the completed client call cannot be hidden by cleanup.
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections += 1;
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("mock retry accept: {error}"),
                    }
                    if Instant::now() >= deadline {
                        return connections;
                    }
                }
                if Instant::now() >= deadline {
                    return connections;
                }
                if !matches!(
                    stopped.recv_timeout(Duration::from_millis(10)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    // One final drain after the stop message.
                    while let Ok((stream, _)) = listener.accept() {
                        connections += 1;
                        let _ = stream.shutdown(Shutdown::Both);
                        if Instant::now() >= deadline {
                            break;
                        }
                    }
                    return connections;
                }
            }
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
        Self::new(move |stream, _| {
            let _ = write_bounded(stream, &bytes);
        })
    }

    fn client(&self) -> Client {
        Client::new(self.address, TOKEN.into()).unwrap()
    }

    fn request(&self) -> String {
        String::from_utf8(self.request.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap()
    }

    fn cleanup(&mut self) -> Option<usize> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(stream) = self.active.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        if let Some(worker) = self.worker.take() {
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if worker.is_finished() {
                return worker.join().ok();
            }
            return None;
        }
        Some(0)
    }

    fn finish(mut self) {
        assert_eq!(
            self.cleanup(),
            Some(1),
            "mock must see exactly one connection and be reaped"
        );
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        if self.cleanup().is_none() {
            eprintln!("mock cleanup failed");
        }
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
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

fn snapshot() -> IndexSnapshot {
    IndexSnapshot {
        instance: "0123456789abcdef0123456789ABCDEF".into(),
        revision: 7,
    }
}

fn cursor(height: u64, position: u32) -> WireCursor {
    WireCursor {
        snapshot: snapshot(),
        height,
        position,
    }
}

fn block(height: u64) -> BlockHash {
    BlockHash::from_byte_array([height as u8; 32])
}

// Synthetic identity/location metadata deliberately claims no chain proof.
fn record(height: u64, position: u32, payload: PublicRecord) -> WireRecord {
    let entry = urma_wire::index::entry_from_record(
        &payload.encode().unwrap(),
        Txid::from_byte_array([position as u8; 32]),
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        None,
        height,
        position,
    )
    .unwrap()
    .unwrap();
    WireRecord {
        block_hash: block(height),
        wtxid: Wtxid::from_byte_array([position as u8 + 1; 32]),
        entry,
    }
}

fn page(records: Vec<WireRecord>, next: Option<WireCursor>) -> WirePage {
    WirePage {
        snapshot: snapshot(),
        archive: ArchiveStatus {
            api_version: 1,
            chain_genesis: block(0),
            application_start: ChainPoint {
                height: 17,
                hash: block(17),
            },
            retention: Retention::Pruned,
            generation: 3,
            selected_tip: Some(ChainPoint {
                height: 19,
                hash: block(19),
            }),
            indexed_through: None,
            scanned_blocks: 0,
            unresolved_dependencies: 0,
            stored_transactions: 2,
            scan_rules_version: 1,
            peer_synced_through: None,
            peer_omissions: 0,
            unaudited_records: 0,
        },
        records,
        next,
    }
}

fn one_page() -> WirePage {
    page(
        vec![record(18, 1, PublicRecord::Post("hello".into()))],
        None,
    )
}

fn reply(code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn mock_page(value: &impl serde::Serialize) -> Mock {
    Mock::raw(reply(200, &serde_json::to_vec(value).unwrap()))
}

fn expected_request(mock: &Mock, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        mock.address
    )
}

fn rejected(value: Value, supplied: Option<&WireCursor>, limit: u32) {
    let mock = mock_page(&value);
    assert!(
        mock.client().wire_page(supplied, limit).is_err(),
        "accepted {value}"
    );
    mock.finish();
}

#[test]
fn initial_page_sends_exact_authenticated_empty_get_without_auto_paging() {
    let original = page(
        vec![
            record(17, 1, PublicRecord::Post("first".into())),
            record(17, 2, PublicRecord::Post("second".into())),
            record(18, 0, PublicRecord::Post("third".into())),
        ],
        Some(cursor(18, 0)),
    );
    let mock = mock_page(&original);
    let actual = mock.client().wire_page(None, 3).unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(original).unwrap()
    );
    assert_eq!(mock.request(), expected_request(&mock, "/v1/wire?limit=3"));
    mock.finish();
}

#[test]
fn continuation_is_exact_bounded_json_hex_and_preserves_coverage_separation() {
    let supplied = cursor(17, 4);
    let original = page(
        vec![record(18, 0, PublicRecord::Profile("operator".into()))],
        None,
    );
    let mock = mock_page(&original);
    let actual = mock.client().wire_page(Some(&supplied), 128).unwrap();
    let encoded = hex::encode(serde_json::to_vec(&supplied).unwrap());
    assert!(encoded.len() <= 1024);
    assert_eq!(
        mock.request(),
        expected_request(&mock, &format!("/v1/wire?limit=128&cursor={encoded}"))
    );
    assert!(actual.next.is_none()); // Local end, not proof of chain completeness.
    assert_eq!(actual.records.len(), 1);
    assert_eq!(actual.archive.scanned_blocks, 0);
    assert!(actual.archive.indexed_through.is_none());
    mock.finish();
}

#[test]
fn empty_page_is_valid_even_without_application_coverage() {
    for tip in [
        None,
        Some(ChainPoint {
            height: 16,
            hash: block(16),
        }),
    ] {
        let mut original = page(vec![], None);
        original.archive.selected_tip = tip;
        let mock = mock_page(&original);
        let actual = mock.client().wire_page(None, 1).unwrap();
        assert!(actual.records.is_empty() && actual.next.is_none());
        mock.finish();
    }
}

#[test]
fn invalid_limits_and_cursors_fail_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = Client::new(listener.local_addr().unwrap(), TOKEN.into()).unwrap();
    for limit in [0, 129, u32::MAX] {
        assert!(matches!(
            client.wire_page(None, limit),
            Err(Error::Invalid(_))
        ));
    }
    for instance in ["".into(), "f".repeat(31), "g".repeat(32), "f".repeat(1025)] {
        let mut supplied = cursor(17, 1);
        supplied.snapshot.instance = instance;
        assert!(matches!(
            client.wire_page(Some(&supplied), 1),
            Err(Error::Invalid(_))
        ));
    }
    assert!(
        client
            .wire_page(Some(&cursor(i64::MAX as u64 + 1, 0)), 1)
            .is_err()
    );
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn stale_snapshot_is_busy_and_other_http_codes_are_errors_without_retry() {
    for code in [400, 401, 404, 409, 422, 500, 301, 204] {
        let mock = Mock::raw(reply(code, br#"{"error":"unavailable"}"#));
        let result = mock.client().wire_page(Some(&cursor(17, 0)), 1);
        match code {
            409 => assert!(
                matches!(result, Err(Error::Busy(ref reason)) if reason.contains("restart"))
            ),
            _ => assert!(result.is_err()),
        }
        mock.finish();
    }
}

#[test]
fn snapshot_instance_and_supplied_snapshot_must_match() {
    for instance in ["".into(), "f".repeat(31), "f".repeat(33), "g".repeat(32)] {
        let mut value = serde_json::to_value(one_page()).unwrap();
        value["snapshot"]["instance"] = json!(instance);
        rejected(value, None, 1);
    }
    for field in ["instance", "revision"] {
        let mut value = serde_json::to_value(one_page()).unwrap();
        value["snapshot"][field] = if field == "instance" {
            json!("f".repeat(32))
        } else {
            json!(8)
        };
        rejected(value, Some(&cursor(17, 0)), 1);
    }
}

#[test]
fn records_are_bounded_strictly_ordered_and_after_cursor() {
    let posts = || {
        vec![
            record(18, 1, PublicRecord::Post("a".into())),
            record(18, 2, PublicRecord::Post("b".into())),
        ]
    };
    rejected(serde_json::to_value(page(posts(), None)).unwrap(), None, 1);
    let mut duplicated = posts();
    duplicated[1].entry.position = 1;
    rejected(
        serde_json::to_value(page(duplicated, None)).unwrap(),
        None,
        2,
    );
    let mut reversed = posts();
    reversed.reverse();
    rejected(serde_json::to_value(page(reversed, None)).unwrap(), None, 2);
    for supplied in [cursor(18, 1), cursor(18, 2), cursor(19, 0)] {
        rejected(
            serde_json::to_value(one_page()).unwrap(),
            Some(&supplied),
            1,
        );
    }
}

#[test]
fn continuation_requires_nonempty_page_and_exact_last_coordinate_and_snapshot() {
    rejected(
        serde_json::to_value(page(vec![], Some(cursor(18, 1)))).unwrap(),
        None,
        1,
    );
    for next in [cursor(17, 1), cursor(18, 0), cursor(18, 2), cursor(19, 1)] {
        let mut original = one_page();
        original.next = Some(next);
        rejected(serde_json::to_value(original).unwrap(), None, 1);
    }
    for field in ["instance", "revision"] {
        let mut original = one_page();
        original.next = Some(cursor(18, 1));
        let mut value = serde_json::to_value(original).unwrap();
        value["next"]["snapshot"][field] = if field == "instance" {
            json!("f".repeat(32))
        } else {
            json!(8)
        };
        rejected(value, None, 1);
    }
}

#[test]
fn archive_version_range_and_same_height_block_hash_are_consistent() {
    let mut original = one_page();
    original.archive.api_version = 2;
    rejected(serde_json::to_value(original).unwrap(), None, 1);
    let mut original = one_page();
    original.archive.selected_tip = None;
    rejected(serde_json::to_value(original).unwrap(), None, 1);
    for height in [16, 20] {
        rejected(
            serde_json::to_value(page(
                vec![record(height, 1, PublicRecord::Post("a".into()))],
                None,
            ))
            .unwrap(),
            None,
            1,
        );
    }
    for height in [17, 19] {
        let mut item = record(height, 1, PublicRecord::Post("a".into()));
        item.block_hash = block(99);
        rejected(
            serde_json::to_value(page(vec![item], None)).unwrap(),
            None,
            1,
        );
    }
    let first = record(18, 1, PublicRecord::Post("a".into()));
    let mut second = record(18, 2, PublicRecord::Post("b".into()));
    second.block_hash = block(99);
    rejected(
        serde_json::to_value(page(vec![first, second], None)).unwrap(),
        None,
        2,
    );
}

#[test]
fn all_wire_kinds_parse_strictly_and_public_byte_limit_is_inclusive() {
    let topics = Topics {
        wire: "urma".into(),
        hashtags: vec!["node".into()],
    };
    let records = vec![
        PublicRecord::Post("p".into()),
        PublicRecord::Reply {
            target: Txid::from_byte_array([9; 32]),
            text: "r".into(),
        },
        PublicRecord::Profile("p".repeat(Urma::MAX_PROFILE_BYTES)),
        PublicRecord::Avatar(Box::new([0; Urma::AVATAR_BYTES])),
        PublicRecord::WirePost {
            topics: topics.clone(),
            text: "wp".into(),
        },
        PublicRecord::WireReply {
            target: Txid::from_byte_array([9; 32]),
            topics,
            text: "wr".into(),
        },
        PublicRecord::Post("x".repeat(Urma::MAX_PUBLIC_BYTES - Urma::PREFIX_BYTES)),
    ];
    for payload in records {
        let original = page(vec![record(18, 1, payload)], None);
        let mock = mock_page(&original);
        let actual = mock.client().wire_page(None, 1).unwrap();
        assert_eq!(
            actual.records[0].entry.record,
            original.records[0].entry.record
        );
        mock.finish();
    }
}

#[test]
fn malformed_identity_hex_payload_and_non_wire_kinds_are_rejected() {
    for (field, values) in [
        ("txid", vec!["".into(), "f".repeat(63), "g".repeat(64)]),
        ("author", vec!["".into(), "f".repeat(64), "g".repeat(64)]),
        (
            "record",
            vec![
                "0".into(),
                "gg".into(),
                "00".repeat(Urma::MAX_PUBLIC_BYTES + 1),
            ],
        ),
    ] {
        for text in values {
            let mut value = serde_json::to_value(one_page()).unwrap();
            value["records"][0]["entry"][field] = json!(text);
            rejected(value, None, 1);
        }
    }
    let mut malformed = Vec::new();
    for (kind, body) in [
        (RecordKind::Post, vec![0xff]),
        (RecordKind::Reply, vec![0; 31]),
        (RecordKind::Profile, vec![b'a'; Urma::MAX_PROFILE_BYTES + 1]),
        (RecordKind::Avatar, vec![0; 512]), // Legacy cache exception is excluded.
        (RecordKind::WirePost, vec![0]),
        (RecordKind::WireReply, vec![0; 32]),
        (RecordKind::Private, vec![0; 32]),
    ] {
        let mut raw = kind.prefix().to_vec();
        raw.extend_from_slice(&body);
        malformed.push(raw);
    }
    malformed.push(
        PublicRecord::ProfileRecord {
            profile: *b"NAMESV00",
            payload: vec![1, 2],
        }
        .encode()
        .unwrap(),
    );
    malformed.push(b"URMA".to_vec());
    for raw in malformed {
        let mut value = serde_json::to_value(one_page()).unwrap();
        value["records"][0]["entry"]["record"] = json!(hex::encode(raw));
        rejected(value, None, 1);
    }
}

#[test]
fn malformed_json_unknown_fields_and_typed_hashes_are_rejected() {
    for body in [b"{".to_vec(), b"null".to_vec(), b"{}".to_vec()] {
        let mock = Mock::raw(reply(200, &body));
        assert!(mock.client().wire_page(None, 1).is_err());
        mock.finish();
    }
    for pointer in ["", "/snapshot", "/records/0", "/records/0/entry"] {
        let mut value = serde_json::to_value(one_page()).unwrap();
        value.pointer_mut(pointer).unwrap()["unexpected"] = json!(true);
        rejected(value, None, 1);
    }
    for pointer in [
        "/records/0/block_hash",
        "/records/0/wtxid",
        "/archive/chain_genesis",
    ] {
        let mut value = serde_json::to_value(one_page()).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!("not-a-hash");
        rejected(value, None, 1);
    }
}

#[test]
fn inherited_http_framing_bounds_and_content_type_apply_to_wire_pages() {
    let body = serde_json::to_vec(&one_page()).unwrap();
    for header in [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n",
            body.len(),
            body.len()
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            body.len()
        ),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".into(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433\r\n\r\n"
            .into(),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Pad: {}\r\nContent-Length: {}\r\n\r\n",
            "x".repeat(8192),
            body.len()
        ),
    ] {
        let mut bytes = header.into_bytes();
        bytes.extend_from_slice(&body);
        let mock = Mock::raw(bytes);
        assert!(mock.client().wire_page(None, 1).is_err());
        mock.finish();
    }
    let mut truncated = reply(200, &body);
    truncated.pop();
    let mock = Mock::raw(truncated);
    assert!(
        matches!(mock.client().wire_page(None, 1), Err(Error::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
    mock.finish();
}

#[test]
fn wire_reads_share_one_absolute_deadline_across_headers_and_body() {
    let mock = Mock::new(|stream, stop| {
        if write_bounded(
            stream,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
        )
        .is_err()
        {
            return;
        }
        if !matches!(
            stop.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            return;
        }
        if write_bounded(stream, b"Content-Length: 21\r\n\r\n{").is_err() {
            return;
        }
        let _ = stop.recv_timeout(Duration::from_secs(6));
    });
    let began = Instant::now();
    let error = mock.client().wire_page(None, 1).err().unwrap();
    let elapsed = began.elapsed();
    assert!(
        matches!(error, Error::Io(ref cause) if matches!(cause.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)),
        "{error}"
    );
    assert!(
        elapsed >= Duration::from_millis(4500),
        "early deadline {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(6500),
        "deadline restarted after headers {elapsed:?}"
    );
    mock.finish();
}
