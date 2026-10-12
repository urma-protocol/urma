//! Names local-operator data through the shared client and Node compatibility wrapper.
//! Owned loopback mocks only: no daemon, SQL, user state, DNS or chain source.
//! Typed payloads and metadata are not independent cryptographic evidence.
use bitcoin::{BlockHash, Txid, XOnlyPublicKey, hashes::Hash};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_names::{
    name::Name,
    state::{Bound, Outcome, Rejection, Resolution, Target, Verdict},
};
use urma_node::{
    Error,
    client::Client,
    model::ChainPoint,
    names::{NamesResolution, NamesStatus, NamesStep},
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

#[derive(Clone, Copy, Debug)]
enum Api {
    Shared,
    Node,
}
const APIS: [Api; 2] = [Api::Shared, Api::Node];

#[derive(Clone, Copy, Debug)]
enum Operation {
    Register,
    Step,
    Status,
    Resolve,
}
const OPERATIONS: [Operation; 4] = [
    Operation::Register,
    Operation::Step,
    Operation::Status,
    Operation::Resolve,
];

fn genesis() -> Txid {
    Txid::from_byte_array([7; 32])
}

fn point(height: u64, marker: u8) -> ChainPoint {
    ChainPoint {
        height,
        hash: BlockHash::from_byte_array([marker; 32]),
    }
}

fn genesis_block() -> ChainPoint {
    point(100, 1)
}

fn status() -> NamesStatus {
    NamesStatus {
        genesis: genesis(),
        genesis_block: genesis_block(),
        projected: point(120, 2),
        generation: 9,
        selected_tip: Some(point(130, 3)),
        complete_to_tip: false,
    }
}

fn step(status: NamesStatus) -> NamesStep {
    NamesStep {
        applied: Some(status.projected),
        status,
        rolled_back: 2,
        outcomes: vec![Outcome {
            txid: Txid::from_byte_array([8; 32]),
            position: 3,
            verdict: Verdict::Applied,
        }],
    }
}

fn body(operation: Operation, status: NamesStatus) -> Value {
    match operation {
        Operation::Register | Operation::Status => serde_json::to_value(status).unwrap(),
        Operation::Step => serde_json::to_value(step(status)).unwrap(),
        Operation::Resolve => serde_json::to_value(NamesResolution {
            status,
            resolution: Resolution::Unbound,
        })
        .unwrap(),
    }
}

fn reply(code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn call(api: Api, address: SocketAddr, operation: Operation) -> Result<Value, Error> {
    let name = Name::parse("atelier-news").unwrap();
    match api {
        Api::Shared => {
            let client =
                urma_node_client::Client::new(address, TOKEN.into()).map_err(Error::from)?;
            match operation {
                Operation::Register => client
                    .register_names(genesis(), genesis_block())
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(Error::from),
                Operation::Step => client
                    .names_step(genesis())
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(Error::from),
                Operation::Status => client
                    .names_status(genesis())
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(Error::from),
                Operation::Resolve => client
                    .names_resolve(genesis(), &name)
                    .map(|v| serde_json::to_value(v).unwrap())
                    .map_err(Error::from),
            }
        }
        Api::Node => {
            let client = Client::new(address, TOKEN.into())?;
            match operation {
                Operation::Register => client
                    .register_names(genesis(), genesis_block())
                    .map(|v| serde_json::to_value(v).unwrap()),
                Operation::Step => client
                    .names_step(genesis())
                    .map(|v| serde_json::to_value(v).unwrap()),
                Operation::Status => client
                    .names_status(genesis())
                    .map(|v| serde_json::to_value(v).unwrap()),
                Operation::Resolve => client
                    .names_resolve(genesis(), &name)
                    .map(|v| serde_json::to_value(v).unwrap()),
            }
        }
    }
}

fn register(api: Api, address: SocketAddr, block: ChainPoint) -> Result<NamesStatus, Error> {
    match api {
        Api::Shared => urma_node_client::Client::new(address, TOKEN.into())
            .map_err(Error::from)?
            .register_names(genesis(), block)
            .map_err(Error::from),
        Api::Node => Client::new(address, TOKEN.into())?.register_names(genesis(), block),
    }
}

fn route(operation: Operation) -> (&'static str, String) {
    let id = genesis();
    match operation {
        Operation::Register => (
            "POST",
            format!(
                "/v1/names/{id}/register?height=100&hash={}",
                genesis_block().hash
            ),
        ),
        Operation::Step => ("POST", format!("/v1/names/{id}/step")),
        Operation::Status => ("GET", format!("/v1/names/{id}")),
        Operation::Resolve => ("GET", format!("/v1/names/{id}/resolve/atelier-news")),
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

fn reject_status(status: NamesStatus) {
    for api in APIS {
        for operation in OPERATIONS {
            let bytes = serde_json::to_vec(&body(operation, status.clone())).unwrap();
            let mock = Mock::raw(reply(200, &bytes));
            assert!(
                matches!(call(api, mock.address, operation), Err(Error::Invalid(_))),
                "{api:?} {operation:?} {status:?}"
            );
            mock.finish();
        }
    }
}

#[test]
fn shared_and_node_clients_send_all_four_exact_authenticated_bodyless_routes() {
    for api in APIS {
        for operation in OPERATIONS {
            let expected = body(operation, status());
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&expected).unwrap()));
            assert_eq!(call(api, mock.address, operation).unwrap(), expected);
            let (method, path) = route(operation);
            assert_eq!(mock.request(), expected_request(&mock, method, &path));
            mock.finish();
        }
    }
}

#[test]
fn registration_height_is_bounded_before_io_and_i64_max_is_allowed() {
    for api in APIS {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        for height in [i64::MAX as u64 + 1, u64::MAX] {
            let error =
                register(api, listener.local_addr().unwrap(), point(height, 1)).unwrap_err();
            assert!(matches!(error, Error::Invalid(ref message) if message.contains("height")));
            assert!(
                matches!(listener.accept(), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        }
        for height in [0, i64::MAX as u64] {
            let block = point(height, 1);
            let mut expected = status();
            expected.genesis_block = block;
            expected.projected = block;
            expected.selected_tip = Some(block);
            expected.complete_to_tip = true;
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&expected).unwrap()));
            assert_eq!(
                register(api, mock.address, block).unwrap().genesis_block,
                block
            );
            assert_eq!(
                mock.request(),
                expected_request(
                    &mock,
                    "POST",
                    &format!(
                        "/v1/names/{}/register?height={height}&hash={}",
                        genesis(),
                        block.hash
                    )
                )
            );
            mock.finish();
        }
    }
}

#[test]
fn only_status_404_means_locally_unregistered_and_still_requires_framed_json() {
    for api in APIS {
        for operation in OPERATIONS {
            let mock = Mock::raw(reply(404, br#"{"error":"unregistered"}"#));
            let result = call(api, mock.address, operation);
            if matches!(operation, Operation::Status) {
                assert_eq!(result.unwrap(), Value::Null);
            } else {
                assert!(matches!(result, Err(Error::Invalid(_))));
            }
            mock.finish();
        }
        for bytes in [b"".as_slice(), b"{broken".as_slice()] {
            let mock = Mock::raw(reply(404, bytes));
            assert!(matches!(
                call(api, mock.address, Operation::Status),
                Err(Error::Json(_))
            ));
            mock.finish();
        }
    }
}

#[test]
fn every_operation_maps_409_to_busy_without_retry_or_error_body_reflection() {
    for api in APIS {
        for operation in OPERATIONS {
            let mock = Mock::raw(reply(
                409,
                format!("{{\"error\":\"Bearer {TOKEN}\"}}").as_bytes(),
            ));
            let error = call(api, mock.address, operation).unwrap_err();
            assert!(matches!(error, Error::Busy(_)), "{error}");
            assert!(!error.to_string().contains(TOKEN));
            let (method, path) = route(operation);
            assert_eq!(mock.request(), expected_request(&mock, method, &path));
            mock.finish();
        }
    }
}

#[test]
fn other_status_codes_are_errors_even_with_valid_typed_bodies_and_never_redirect() {
    for api in APIS {
        for operation in OPERATIONS {
            for code in [201, 204, 301, 302, 307, 308, 400, 401, 422, 500] {
                let bytes = serde_json::to_vec(&body(operation, status())).unwrap();
                let mock = Mock::raw(reply(code, &bytes));
                assert!(
                    matches!(call(api, mock.address, operation), Err(Error::Invalid(_))),
                    "accepted {api:?} {operation:?} {code}"
                );
                mock.finish();
            }
        }
    }
}

#[test]
fn every_reply_must_match_requested_genesis() {
    let mut invalid = status();
    invalid.genesis = Txid::from_byte_array([8; 32]);
    reject_status(invalid);
}

#[test]
fn registration_ack_must_match_exact_requested_genesis_block() {
    for api in APIS {
        for wrong in [point(101, 1), point(100, 9)] {
            let mut invalid = status();
            invalid.genesis_block = wrong;
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&invalid).unwrap()));
            assert!(
                matches!(call(api, mock.address, Operation::Register), Err(Error::Invalid(ref message)) if message.contains("registration"))
            );
            mock.finish();
        }
    }
}

#[test]
fn projection_requires_selected_tip_and_ordered_genesis_projection_tip_heights() {
    let mut invalid = status();
    invalid.selected_tip = None;
    reject_status(invalid);
    let mut invalid = status();
    invalid.projected = point(99, 2);
    reject_status(invalid);
    let mut invalid = status();
    invalid.selected_tip = Some(point(119, 3));
    reject_status(invalid);
}

#[test]
fn equal_height_status_points_require_equal_hashes() {
    let mut invalid = status();
    invalid.projected = point(100, 2);
    reject_status(invalid);
    let mut invalid = status();
    invalid.selected_tip = Some(point(120, 3));
    reject_status(invalid);
    let mut invalid = status();
    invalid.projected = point(100, 1);
    invalid.selected_tip = Some(point(100, 3));
    invalid.complete_to_tip = true;
    reject_status(invalid);
}

#[test]
fn complete_to_tip_is_exactly_projection_equals_selected_tip() {
    let mut invalid = status();
    invalid.complete_to_tip = true;
    reject_status(invalid);
    let mut invalid = status();
    invalid.selected_tip = Some(invalid.projected);
    reject_status(invalid);
    let mut complete = status();
    complete.selected_tip = Some(complete.projected);
    complete.complete_to_tip = true;
    for api in APIS {
        for operation in OPERATIONS {
            let expected = body(operation, complete.clone());
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&expected).unwrap()));
            assert_eq!(call(api, mock.address, operation).unwrap(), expected);
            mock.finish();
        }
    }
}

#[test]
fn step_applied_must_equal_projection_and_typed_outcomes_are_operator_data() {
    for api in APIS {
        for applied in [None, Some(status().projected)] {
            let mut expected = step(status());
            expected.applied = applied;
            expected.rolled_back = u64::MAX; // Preserve a typed count; do not invent history.
            expected.outcomes = [
                Verdict::Applied,
                Verdict::Pending,
                Verdict::Inert(Rejection::Repeated),
                Verdict::Invalid(Rejection::RevealWindow),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, verdict)| Outcome {
                txid: genesis(),
                position: i as u32,
                verdict,
            })
            .collect();
            let bytes = serde_json::to_vec(&expected).unwrap();
            let mock = Mock::raw(reply(200, &bytes));
            assert_eq!(
                call(api, mock.address, Operation::Step).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
            mock.finish();
        }
        for wrong in [point(121, 2), point(120, 9)] {
            let mut invalid = step(status());
            invalid.applied = Some(wrong);
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&invalid).unwrap()));
            assert!(
                matches!(call(api, mock.address, Operation::Step), Err(Error::Invalid(ref message)) if message.contains("applied"))
            );
            mock.finish();
        }
    }
}

#[test]
fn resolution_preserves_existing_typed_variants_without_inventing_name_or_proof() {
    let owner: XOnlyPublicKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        .parse()
        .unwrap();
    for api in APIS {
        for resolution in [
            Resolution::Unbound,
            Resolution::Suspended,
            Resolution::Bound(Bound {
                owner,
                target: Target::Reserved,
                expiry: 170,
                claim_txid: genesis(),
                last_txid: genesis(),
            }),
            Resolution::Bound(Bound {
                owner,
                target: Target::Publication(Txid::from_byte_array([8; 32])),
                expiry: 190,
                claim_txid: genesis(),
                last_txid: Txid::from_byte_array([9; 32]),
            }),
        ] {
            let expected = NamesResolution {
                status: status(),
                resolution,
            };
            let mut value = serde_json::to_value(&expected).unwrap();
            if value["resolution"].get("Bound").is_some() {
                // Legacy Bound serde permits unknown fields. This scope does
                // not change its schema or add cryptographic/state claims.
                value["resolution"]["Bound"]["legacy_extra"] = json!(true);
            }
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&value).unwrap()));
            assert_eq!(
                call(api, mock.address, Operation::Resolve).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
            mock.finish();
        }
    }
}

#[test]
fn malformed_json_and_outer_dto_fields_are_refused() {
    for api in APIS {
        for operation in OPERATIONS {
            let mut extra = body(operation, status());
            extra["unknown"] = json!(true);
            let mut malformed_status = body(operation, status());
            let inner = match operation {
                Operation::Register | Operation::Status => &mut malformed_status,
                _ => &mut malformed_status["status"],
            };
            inner["genesis"] = json!("bad-txid");
            let mut nested_extra = body(operation, status());
            if matches!(operation, Operation::Step | Operation::Resolve) {
                nested_extra["status"]["extra"] = json!(true);
            } else {
                nested_extra["extra"] = json!(true);
            }
            for bytes in [
                b"".to_vec(),
                b"{broken".to_vec(),
                b"null".to_vec(),
                b"{}".to_vec(),
                serde_json::to_vec(&extra).unwrap(),
                serde_json::to_vec(&malformed_status).unwrap(),
                serde_json::to_vec(&nested_extra).unwrap(),
            ] {
                let mock = Mock::raw(reply(200, &bytes));
                assert!(matches!(
                    call(api, mock.address, operation),
                    Err(Error::Json(_))
                ));
                mock.finish();
            }
        }
        for operation in [Operation::Step, Operation::Resolve] {
            let mut invalid = body(operation, status());
            if matches!(operation, Operation::Step) {
                invalid["outcomes"][0]["verdict"] = json!("NotAVerdict");
            } else {
                invalid["resolution"] = json!("NotAResolution");
            }
            let mock = Mock::raw(reply(200, &serde_json::to_vec(&invalid).unwrap()));
            assert!(matches!(
                call(api, mock.address, operation),
                Err(Error::Json(_))
            ));
            mock.finish();
        }
    }
}

#[test]
fn names_requests_inherit_strict_framing_and_never_repeat_incomplete_commands() {
    for api in APIS {
        for operation in OPERATIONS {
            for bytes in [
                Vec::new(),
                b"HTTP/1.1 200 OK\r\n".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33554433\r\n\r\n".to_vec(),
            ] {
                let mock = Mock::raw(bytes);
                assert!(call(api, mock.address, operation).is_err());
                let (method, path) = route(operation);
                assert_eq!(mock.request(), expected_request(&mock, method, &path));
                mock.finish();
            }
        }
    }
}

#[test]
fn names_step_has_one_absolute_deadline_across_response_header_and_body() {
    // One delayed header stage distinguishes a shared 5s budget from resetting
    // another 5s timer for the body. Cleanup is cancellable, not an extra sleep.
    for api in APIS {
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
        let error = call(api, mock.address, Operation::Step).unwrap_err();
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
            "deadline reset between stages {elapsed:?}"
        );
        mock.finish();
    }
}
