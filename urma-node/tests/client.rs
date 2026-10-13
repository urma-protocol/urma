use bitcoin::{BlockHash, Txid, Wtxid, hashes::Hash};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::inclusion::{MerklePath, TransactionProof};
use urma_node::{
    Error,
    client::Client,
    model::{ArchivedRecord, ChainPoint, RecordPackage, RecordReceipt},
};

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

fn record() -> ArchivedRecord {
    let point = ChainPoint {
        height: 17,
        hash: BlockHash::from_byte_array([3; 32]),
    };
    let path = MerklePath {
        index: 1,
        tx_count: 2,
        siblings: vec![[0; 32]],
    };
    ArchivedRecord {
        receipt: RecordReceipt {
            generation: 4,
            block: point,
            position: 1,
            txid: Txid::from_byte_array([7; 32]),
            wtxid: Wtxid::from_byte_array([8; 32]),
        },
        package: RecordPackage {
            version: 1,
            chain_genesis: BlockHash::from_byte_array([2; 32]),
            block: point,
            reveal: TransactionProof {
                // Deliberately not a valid transaction/proof. The client returns
                // data and never represents it as independently verified.
                transaction: vec![0, 1, 255],
                txid_path: path.clone(),
                coinbase: vec![42],
                coinbase_path: path.clone(),
                witness_path: path.clone(),
                coinbase_witness_path: path,
            },
            commit: vec![254, 0, 13],
        },
    }
}

#[test]
fn construction_is_loopback_only_and_requires_exact_hex_without_io() {
    for address in ["0.0.0.0:1", "[::]:1", "192.0.2.1:1"] {
        assert!(Client::new(address.parse().unwrap(), TOKEN.into()).is_err());
    }
    for token in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64),
        format!("{}\r\n", "a".repeat(62)),
    ] {
        assert!(Client::new("127.0.0.1:1".parse().unwrap(), token).is_err());
    }
    for address in ["127.0.0.1:0", "127.0.0.2:1", "[::1]:1"] {
        assert!(Client::new(address.parse().unwrap(), TOKEN.to_uppercase()).is_ok());
    }
}

#[test]
fn status_sends_authenticated_bodyless_http11_to_the_explicit_address() {
    let value = json!({"archive":{"generation":9},"last_sync_error":null});
    let mock = Mock::raw(reply(
        200,
        "application/json",
        &serde_json::to_vec(&value).unwrap(),
    ));
    assert_eq!(mock.client().status_json().unwrap(), value);
    assert_eq!(
        mock.request(),
        format!(
            "GET /v1/status HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            mock.address
        )
    );
    mock.finish();
}

#[test]
fn record_preserves_unverified_data_and_compares_only_receipt_txid() {
    let expected = record();
    let mock = Mock::raw(reply(
        200,
        "Application/JSON; charset=\"utf-8\"",
        &serde_json::to_vec(&expected).unwrap(),
    ));
    let actual = mock
        .client()
        .record(expected.receipt.txid)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    assert!(mock.request().starts_with(&format!(
        "GET /v1/records/{} HTTP/1.1\r\n",
        expected.receipt.txid
    )));
    mock.finish();
    let mock = Mock::raw(reply(
        200,
        "application/json",
        &serde_json::to_vec(&expected).unwrap(),
    ));
    let error = mock
        .client()
        .record(Txid::from_byte_array([9; 32]))
        .unwrap_err();
    assert!(error.to_string().contains("receipt TXID"));
    mock.finish();
}

#[test]
fn only_record_404_is_missing_authentication_and_other_statuses_are_errors() {
    let txid = record().receipt.txid;
    let mock = Mock::raw(reply(
        404,
        "application/json; charset=utf-8",
        br#"{"error":"not locally available"}"#,
    ));
    assert!(mock.client().record(txid).unwrap().is_none());
    mock.finish();
    for code in [201, 204, 301, 302, 307, 308, 400, 401, 403, 413, 500] {
        let mock = Mock::raw(reply(code, "application/json", b"{}"));
        assert!(
            mock.client().record(txid).is_err(),
            "HTTP {code} became missing"
        );
        mock.finish();
    }
    for code in [201, 301, 401, 404, 500] {
        let mock = Mock::raw(reply(code, "application/json", b"{}"));
        assert!(
            mock.client().status_json().is_err(),
            "status accepted HTTP {code}"
        );
        mock.finish();
    }
}

#[test]
fn rejects_malformed_framing_lengths_transfer_encoding_and_content_types() {
    let faults = [
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 20 OK\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 200\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 999 OK\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nmalformed",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n Content-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length : 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\nInjected: yes",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json",
        "HTTP/1.1 200 OK\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2, 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: +2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: -1",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length:",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999999999999999999",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ntransfer-encoding: identity",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Encoding: gzip",
        "HTTP/1.1 200 OK\r\nContent-Type: text/json\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/jsonp\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; boundary=x\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8; charset=utf-8\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-type: application/json\r\nContent-Length: 2",
    ];
    for fault in faults {
        let mock = Mock::raw(format!("{fault}\r\n\r\n{{}}").into_bytes());
        assert!(mock.client().status_json().is_err(), "accepted {fault:?}");
        mock.finish();
    }
}

#[test]
fn rejects_truncated_oversized_headers_and_invalid_json_even_for_404() {
    let mut oversized = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    oversized.resize(8193, b'x');
    for bytes in [
        Vec::new(), b"HTTP/1.1 200 OK\r\n".to_vec(), oversized,
        b"HTTP/1.1 200 OK\r\nX: \xff\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}".to_vec(),
        reply(200, "application/json", b"{broken"), reply(200, "application/json", b"{}junk"),
    ] {
        let mock = Mock::raw(bytes);
        assert!(mock.client().status_json().is_err());
        mock.finish();
    }
    for bytes in [
        reply(200, "application/json", b"{}"),
        reply(404, "application/json", b"invalid"),
        b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}"
            .to_vec(),
    ] {
        let mock = Mock::raw(bytes);
        assert!(mock.client().record(record().receipt.txid).is_err());
        mock.finish();
    }
}

#[test]
fn accepts_exact_header_limit_and_case_insensitive_field_names() {
    let mut raw = b"HTTP/1.1 200 OK\r\ncOnTeNt-TyPe: application/json; CHARSET=utf-8\r\nCONTENT-LENGTH:\t2\r\nX-Fill: ".to_vec();
    raw.resize(8192 - 4, b'x');
    raw.extend_from_slice(b"\r\n\r\n{}");
    let mock = Mock::raw(raw);
    assert_eq!(mock.client().status_json().unwrap(), json!({}));
    mock.finish();
}

#[test]
fn resource_limits_reject_announced_excess_before_reading_body() {
    let mock = Mock::raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433\r\n\r\n"
            .to_vec(),
    );
    let error = mock.client().status_json().unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("32 MiB")),
        "{error}"
    );
    mock.finish();

    // At the exact allowed length, the missing bytes are a truncation, not an
    // oversize response. No 32 MiB payload is needed to exercise that boundary.
    let mock = Mock::raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554432\r\n\r\n"
            .to_vec(),
    );
    let error = mock.client().status_json().unwrap_err();
    assert!(
        matches!(error, Error::Io(ref cause) if cause.kind() == io::ErrorKind::UnexpectedEof),
        "{error}"
    );
    mock.finish();

    let mut bytes = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    bytes.resize(8193, b'x');
    let mock = Mock::raw(bytes);
    let error = mock.client().status_json().unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("8192")),
        "{error}"
    );
    mock.finish();
}

#[test]
fn absolute_deadline_covers_headers_and_body_while_progress_continues() {
    let mock = Mock::new(|stream, stop| {
        if write_bounded(
            stream,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\n",
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
        if write_bounded(stream, b"\r\n\"").is_err() {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            if !matches!(
                stop.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                return;
            }
            if write_bounded(stream, b"x").is_err() {
                return;
            }
        }
    });
    // Start before status opens its socket: this measures connect + request
    // write + delayed header + progressing body against one operation budget.
    let began = Instant::now();
    let error = mock.client().status_json().unwrap_err();
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
        "deadline reset between reads: {elapsed:?}"
    );
    mock.finish();
}

#[test]
fn refused_connection_is_an_error_and_caller_can_use_its_own_source() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let client = Client::new(address, TOKEN.into()).unwrap();
    assert!(client.status_json().is_err());
    assert!(client.record(record().receipt.txid).is_err());

    // Source selection belongs to the caller. It can use direct acquisition
    // without constructing a Client or installing/starting a node at all.
    fn fetch(
        client: Option<&Client>,
        txid: Txid,
        source: impl FnOnce(Txid) -> Result<Option<ArchivedRecord>, Error>,
    ) -> Result<Option<ArchivedRecord>, Error> {
        match client {
            Some(client) => client.record(txid),
            None => source(txid),
        }
    }
    let expected = record();
    let actual = fetch(None, expected.receipt.txid, |id| {
        assert_eq!(id, expected.receipt.txid);
        Ok(Some(expected.clone()))
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        actual.package.reveal.transaction,
        expected.package.reveal.transaction
    );
}

#[test]
fn mock_is_cancelled_and_reaped_during_panic_unwind() {
    let (exited, finished) = mpsc::channel();
    let mock = Mock::new(move |_stream, stop| {
        let _ = stop.recv_timeout(MOCK_TIMEOUT);
        let _ = exited.send(());
    });
    let mut socket = TcpStream::connect_timeout(&mock.address, Duration::from_secs(1)).unwrap();
    write_bounded(&mut socket, b"GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
    mock.request();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = mock;
        panic!("intentional mock cleanup regression");
    }));
    assert!(result.is_err());
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
}
