//! Control acknowledgements from owned loopback mocks only. No daemon, chain
//! source, database, user state, DNS or external network is involved.
use bitcoin::{BlockHash, Txid, hashes::Hash};
use serde_json::json;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_node::{Error, client::Client, model::BookOrigin};

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
                // Capture any bytes after the header to prove POST has no body.
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

fn root() -> Txid {
    Txid::from_byte_array([7; 32])
}

fn pin_body(pin: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({"root":root(), "pinned":pin})).unwrap()
}

fn reply(code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn post(mock: &Mock, pin: bool) -> Result<(), Error> {
    if pin {
        mock.client().set_pin(root(), true).map(|_| ())
    } else {
        mock.client().prune_cache().map(|_| ())
    }
}

fn expected_request(mock: &Mock, method: &str, path: &str) -> String {
    let length = if method == "POST" {
        "Content-Length: 0\r\n"
    } else {
        ""
    };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n{length}Connection: close\r\n\r\n",
        mock.address
    )
}

#[test]
fn pin_and_unpin_send_exact_authenticated_bodyless_routes_and_match_ack() {
    for pin in [true, false] {
        let mock = Mock::raw(reply(200, &pin_body(pin)));
        let receipt = mock.client().set_pin(root(), pin).unwrap();
        assert_eq!(receipt.root, root());
        assert_eq!(receipt.pinned, pin);
        let action = if pin { "pin" } else { "unpin" };
        assert_eq!(
            mock.request(),
            expected_request(&mock, "POST", &format!("/v1/objects/{}/{action}", root()))
        );
        mock.finish();
    }
}

#[test]
fn prune_sends_exact_bodyless_route_and_reads_u64_removal_count() {
    for count in [0_u64, 17, u64::MAX] {
        let body = serde_json::to_vec(&json!({"records_removed":count})).unwrap();
        let mock = Mock::raw(reply(200, &body));
        assert_eq!(mock.client().prune_cache().unwrap().records_removed, count);
        assert_eq!(
            mock.request(),
            expected_request(&mock, "POST", "/v1/cache/prune")
        );
        mock.finish();
    }
}

#[test]
fn generalized_transport_preserves_exact_get_request() {
    let mock = Mock::raw(reply(200, br#"{"archive":{}}"#));
    assert_eq!(mock.client().status_json().unwrap(), json!({"archive":{}}));
    assert_eq!(mock.request(), expected_request(&mock, "GET", "/v1/status"));
    mock.finish();
}

#[test]
fn pin_receipt_must_match_both_requested_root_and_pin_value() {
    for pin in [true, false] {
        for value in [
            json!({"root":Txid::from_byte_array([8;32]), "pinned":pin}),
            json!({"root":root(), "pinned":!pin}),
        ] {
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&value).unwrap()));
            assert!(
                matches!(mock.client().set_pin(root(), pin), Err(Error::Invalid(ref message)) if message.contains("receipt"))
            );
            mock.finish();
        }
    }
}

#[test]
fn only_200_acknowledges_control_other_statuses_never_retry_or_redirect() {
    for code in [201, 204, 301, 302, 307, 308, 400, 401, 404, 409, 422, 500] {
        for pin in [true, false] {
            // A valid receipt body must not turn an HTTP failure into success.
            let body = if pin {
                pin_body(true)
            } else {
                br#"{"records_removed":3}"#.to_vec()
            };
            let mock = Mock::raw(reply(code, &body));
            assert!(post(&mock, pin).is_err(), "accepted HTTP {code}");
            mock.finish();
        }
        let mock = Mock::raw(reply(code, &pin_body(false)));
        assert!(mock.client().set_pin(root(), false).is_err());
        mock.finish();
    }
}

#[test]
fn malformed_or_non_typed_receipts_are_errors_without_retry() {
    for body in [
        b"".to_vec(),
        b"{broken".to_vec(),
        b"null".to_vec(),
        b"{}".to_vec(),
        b"{\"records_removed\":-1}".to_vec(),
        b"{\"records_removed\":1.5}".to_vec(),
        b"{\"records_removed\":18446744073709551616}".to_vec(),
        b"{\"records_removed\":0,\"extra\":true}".to_vec(),
        b"{\"records_removed\":0,\"records_removed\":1}".to_vec(),
        b"{\"records_removed\":0}junk".to_vec(),
    ] {
        let mock = Mock::raw(reply(200, &body));
        assert!(mock.client().prune_cache().is_err());
        mock.finish();
    }
    for value in [
        json!({"root":root()}),
        json!({"pinned":true}),
        json!({"root":"bad", "pinned":true}),
        json!({"root":root(), "pinned":"true"}),
        json!({"root":root(), "pinned":true, "extra":true}),
        json!({"root":root(), "pinned":null}),
    ] {
        let mock = Mock::raw(reply(200, &serde_json::to_vec(&value).unwrap()));
        assert!(mock.client().set_pin(root(), true).is_err());
        mock.finish();
    }
}

#[test]
fn posts_inherit_strict_http_framing_and_content_type_without_retry() {
    for header in [
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 20 OK\r\nContent-Type: application/json\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json",
        "HTTP/1.1 200 OK\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: +2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2, 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: identity",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Encoding: gzip",
        "HTTP/1.1 200 OK\r\nContent-Type: text/json\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; boundary=x\r\nContent-Length: 2",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Type: application/json",
    ] {
        for pin in [true, false] {
            let mock = Mock::raw(format!("{header}\r\n\r\n{{}}").into_bytes());
            assert!(
                matches!(post(&mock, pin), Err(Error::Invalid(_))),
                "{header}"
            );
            mock.finish();
        }
    }
}

#[test]
fn incomplete_reply_after_received_command_is_not_automatically_repeated() {
    for bytes in [Vec::new(), b"HTTP/1.1 200 OK\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"records_removed\":1".to_vec()] {
        for pin in [true, false] {
            let mock = Mock::raw(bytes.clone());
            assert!(post(&mock, pin).is_err());
            assert!(mock.request().starts_with("POST "));
            mock.finish();
        }
    }
}

#[test]
fn post_header_and_body_size_boundaries_are_preserved() {
    let body = br#"{"records_removed":0}"#;
    let mut exact = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Fill: ",
        body.len()
    )
    .into_bytes();
    exact.resize(8192 - 4, b'x');
    exact.extend_from_slice(b"\r\n\r\n");
    exact.extend_from_slice(body);
    let mock = Mock::raw(exact);
    assert_eq!(mock.client().prune_cache().unwrap().records_removed, 0);
    mock.finish();
    let mut excessive = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    excessive.resize(8193, b'x');
    let mock = Mock::raw(excessive);
    assert!(
        matches!(mock.client().prune_cache(), Err(Error::Invalid(ref message)) if message.contains("8192"))
    );
    mock.finish();
    let mock = Mock::raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554432\r\n\r\n"
            .to_vec(),
    );
    assert!(
        matches!(mock.client().prune_cache(), Err(Error::Io(ref cause)) if cause.kind() == io::ErrorKind::UnexpectedEof)
    );
    mock.finish();
}

#[test]
fn overlay_omissions_and_book_send_exact_gets_and_read_typed_lists() {
    let omission = json!({"peer":"12D3KooWpeer","block":{"height":7,"hash":BlockHash::all_zeros()},
        "position":2,"txid":root(),"generation":1});
    let mock = Mock::raw(reply(200, &serde_json::to_vec(&json!([omission])).unwrap()));
    let omissions = mock.client().overlay_omissions().unwrap();
    assert_eq!(omissions.len(), 1);
    assert_eq!((omissions[0].block.height, omissions[0].position), (7, 2));
    assert_eq!(omissions[0].txid, root());
    assert_eq!(
        mock.request(),
        expected_request(&mock, "GET", "/v1/overlay/omissions")
    );
    mock.finish();
    let entry = json!({"peer_id":null,"addrs":["/ip4/127.0.0.1/tcp/4001"],"origin":"manual",
        "last_success":null,"failures":0,"banned_until":null});
    let mock = Mock::raw(reply(200, &serde_json::to_vec(&json!([entry])).unwrap()));
    let book = mock.client().overlay_book().unwrap();
    assert_eq!(book.len(), 1);
    assert_eq!(book[0].origin, BookOrigin::Manual);
    assert_eq!(book[0].addrs, ["/ip4/127.0.0.1/tcp/4001"]);
    assert_eq!(
        mock.request(),
        expected_request(&mock, "GET", "/v1/overlay/book")
    );
    mock.finish();
}

#[test]
fn overlay_404_is_overlay_disabled_and_other_failures_stay_errors() {
    for read in [0, 1] {
        let call = |mock: &Mock| match read {
            0 => mock.client().overlay_omissions().map(|_| ()),
            _ => mock.client().overlay_book().map(|_| ()),
        };
        let mock = Mock::raw(reply(404, br#"{"error":"unknown endpoint"}"#));
        assert!(
            matches!(call(&mock), Err(Error::Invalid(ref message)) if message == "overlay disabled")
        );
        mock.finish();
        for (code, body) in [
            (422, &b"[]"[..]),
            (500, b"[]"),
            (200, b"{}"),
            (200, b"[{}]"),
        ] {
            let mock = Mock::raw(reply(code, body));
            assert!(call(&mock).is_err(), "accepted HTTP {code}");
            mock.finish();
        }
    }
    let unbounded = json!([{"peer_id":null,"addrs":[],"origin":"seed",
        "last_success":null,"failures":0,"banned_until":null}]);
    let mock = Mock::raw(reply(200, &serde_json::to_vec(&unbounded).unwrap()));
    assert!(
        matches!(mock.client().overlay_book(), Err(Error::Invalid(ref message)) if message.contains("addresses"))
    );
    mock.finish();
}

#[test]
fn post_uses_one_absolute_deadline_across_header_and_body_reads() {
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
    let error = mock.client().prune_cache().unwrap_err();
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
