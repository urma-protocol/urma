//! One real loopback Service thread, two embedded Engines and two local Clients.
//! This exercises local transport and selective admission; it is not a test of
//! two standalone processes, actual applications or URMA peer discovery.

#[allow(dead_code)]
mod common;

use common::*;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, atomic::Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_node::{
    Error,
    client::Client,
    engine::Engine,
    model::Retention,
    retrieval::{FetchLimits, RecordSource, fetch_record},
    service::Service,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

#[test]
fn local_service_shares_exact_packages_with_independent_selective_admission_and_audit() {
    let first = profile();
    let second = SignedPair::load("proof-post");
    let first_id = first.reveal.compute_txid();
    let second_id = second.reveal.compute_txid();
    assert_ne!(first_id, second_id);
    let anchor = witness_block(&[], None, 70);
    let original = witness_block(
        &[first.transactions(), second.transactions()].concat(),
        Some(&anchor),
        71,
    );
    let replacement = witness_block(&[], Some(&anchor), 72);
    let branch = [anchor.clone(), original.clone()];
    let source_a = Arc::new(MemorySource::new(&branch));
    let source_b = Arc::new(MemorySource::new(&branch));
    assert!(!Arc::ptr_eq(&source_a, &source_b));
    let directory_a = tempfile::tempdir().unwrap();
    let directory_b = tempfile::tempdir().unwrap();
    let archive_config = config(&anchor, Retention::Unpruned);
    let engine_a = Arc::new(
        Engine::open(
            directory_a.path(),
            archive_config.clone(),
            Some(source_a.clone()),
        )
        .unwrap(),
    );
    let engine_b =
        Engine::open(directory_b.path(), archive_config, Some(source_b.clone())).unwrap();

    engine_a.synchronize_headers().unwrap();
    engine_a.scan_next().unwrap();
    let scanned = engine_a.scan_next().unwrap();
    assert_eq!(scanned.scanned_blocks, 2);
    assert_eq!(
        scanned.indexed_through,
        Some(point(FIRST_HEIGHT + 1, &original))
    );
    assert_eq!(scanned.stored_transactions, 4);
    assert_eq!(source_a.body_calls.load(Ordering::Relaxed), 2);
    let exported = engine_a.record(first_id).unwrap().unwrap();
    let omitted = engine_a.record(second_id).unwrap().unwrap();
    assert_eq!(exported.package.reveal.transaction, first.raw_reveal);
    assert_eq!(exported.package.commit, first.raw_commit);
    assert_eq!(omitted.package.reveal.transaction, second.raw_reveal);
    assert_eq!(omitted.package.commit, second.raw_commit);

    let service = RunningService::start(engine_a.clone());
    let client_one = service.client();
    let client_two = service.client();
    // Equality includes original transaction/commit bytes and all four paths.
    for client in [&client_one, &client_two] {
        for (id, expected) in [(first_id, &exported), (second_id, &omitted)] {
            let actual = client.record(id).unwrap().unwrap();
            assert_eq!(
                serde_json::to_vec(&actual.package).unwrap(),
                serde_json::to_vec(&expected.package).unwrap()
            );
            assert_eq!(actual.receipt.txid, expected.receipt.txid);
            assert_eq!(actual.receipt.generation, scanned.generation);
        }
    }
    assert_eq!(source_a.body_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        client_one.status_json().unwrap()["archive"],
        serde_json::to_value(&scanned).unwrap()
    );

    // B selects headers through a separate source before fetching from Client A.
    let selected_b = engine_b.synchronize_headers().unwrap();
    assert_eq!(selected_b.selected_tip, scanned.selected_tip);
    assert_eq!(selected_b.scanned_blocks, 0);
    assert_eq!(selected_b.indexed_through, None);
    assert!(source_b.header_calls.load(Ordering::Relaxed) > 0);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    let verified = fetch_record(&engine_b, first_id, &[&client_one], FetchLimits::default())
        .unwrap()
        .unwrap();
    assert_eq!(verified.record_bytes(), first.verified.record_bytes());
    assert_eq!(verified.txid(), first_id);
    let selective = engine_b.status().unwrap();
    assert_eq!(selective.scanned_blocks, 0);
    assert_eq!(selective.indexed_through, None);
    assert_eq!(selective.stored_transactions, 2);
    assert_eq!(selective.unresolved_dependencies, 0);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    assert_eq!(source_a.body_calls.load(Ordering::Relaxed), 2);
    let cached = engine_b.record(first_id).unwrap().unwrap();
    assert_eq!(
        serde_json::to_vec(&cached.package).unwrap(),
        serde_json::to_vec(&exported.package).unwrap()
    );
    assert!(engine_b.record(second_id).unwrap().is_none());

    // Wrong authentication stays an error through the RecordSource adapter and
    // retrieval path; it must never be translated into a missing record.
    let wrong = Client::new(service.address, "f".repeat(64)).unwrap();
    let error = RecordSource::fetch(&wrong, second_id).unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("HTTP 401")),
        "{error}"
    );
    let error = fetch_record(&engine_b, second_id, &[&wrong], FetchLimits::default()).unwrap_err();
    assert!(
        matches!(error, Error::Invalid(ref message) if message.contains("HTTP 401")),
        "{error}"
    );
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 0);
    assert_eq!(engine_b.status().unwrap().stored_transactions, 2);

    // The selective import deliberately omitted the other signed record. Only
    // B's own full-block audit discovers it and establishes scan coverage.
    let anchor_audit = engine_b.scan_next().unwrap();
    assert_eq!(anchor_audit.scanned_blocks, 1);
    assert!(engine_b.record(second_id).unwrap().is_none());
    let audited_b = engine_b.scan_next().unwrap();
    assert_eq!(audited_b.scanned_blocks, 2);
    assert_eq!(
        audited_b.indexed_through,
        Some(point(FIRST_HEIGHT + 1, &original))
    );
    assert_eq!(audited_b.stored_transactions, 4);
    assert_eq!(source_b.body_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        serde_json::to_vec(&engine_b.record(second_id).unwrap().unwrap().package).unwrap(),
        serde_json::to_vec(&omitted.package).unwrap()
    );
    assert_eq!(source_a.body_calls.load(Ordering::Relaxed), 2);

    // A's independent reorg hides its old records. B still has its own selected
    // original branch: A's local 404 is not a statement of global absence.
    source_a.replace_branch(&[anchor, replacement.clone()]);
    let reorged_a = engine_a.synchronize_headers().unwrap();
    assert_eq!(reorged_a.generation, scanned.generation + 1);
    assert_eq!(
        reorged_a.selected_tip,
        Some(point(FIRST_HEIGHT + 1, &replacement))
    );
    for client in [&client_one, &client_two] {
        assert!(client.record(first_id).unwrap().is_none());
        assert!(RecordSource::fetch(client, second_id).unwrap().is_none());
    }
    assert_eq!(
        client_one.status_json().unwrap()["archive"],
        serde_json::to_value(&reorged_a).unwrap()
    );
    assert_eq!(
        engine_b.status().unwrap().selected_tip,
        audited_b.selected_tip
    );
    assert!(engine_b.record(first_id).unwrap().is_some());
    assert!(engine_b.record(second_id).unwrap().is_some());
    assert_eq!(source_a.body_calls.load(Ordering::Relaxed), 2);
    service.finish();
    assert_eq!(
        Arc::strong_count(&engine_a),
        1,
        "service did not release its Engine"
    );
}
