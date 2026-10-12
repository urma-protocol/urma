//! Names pages from owned loopback mocks for the common and Node clients.
//! Owned loopback mocks only: no daemon, SQL, user state, DNS or chain source.
//! Typed payloads and metadata are not independent cryptographic evidence.
use bitcoin::{
    BlockHash, Txid, XOnlyPublicKey,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use serde_json::json;
use std::collections::BTreeSet;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_names::{
    name::Name,
    payload::{Genesis, Mode},
    state::{Binding, Bound, NameState, PendingKind, PendingRecord, Target},
};
use urma_node::{
    Error,
    client::Client,
    model::ChainPoint,
    names::{
        MAX_NAMES_PAGE_BYTES, MAX_NAMES_STATE_BYTES, NamesCursor, NamesEntry, NamesKey, NamesPage,
        NamesStatus,
    },
    projection::IndexSnapshot,
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
    let deadline = Instant::now() + Duration::from_secs(2);
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

fn fetch(
    api: Api,
    address: SocketAddr,
    cursor: Option<&NamesCursor>,
    limit: u32,
) -> Result<NamesPage, Error> {
    match api {
        Api::Shared => urma_node_client::Client::new(address, TOKEN.into())
            .unwrap()
            .names_view(genesis(), cursor, limit)
            .map_err(Error::from),
        Api::Node => {
            Client::new(address, TOKEN.into())
                .unwrap()
                .names_view(genesis(), cursor, limit)
        }
    }
}

fn genesis() -> Txid {
    Txid::from_byte_array([7; 32])
}
fn point(height: u64, marker: u8) -> ChainPoint {
    ChainPoint {
        height,
        hash: BlockHash::from_byte_array([marker; 32]),
    }
}
fn snapshot() -> IndexSnapshot {
    IndexSnapshot {
        instance: "0123456789abcdef0123456789abcdef".into(),
        revision: 9,
    }
}
fn rules() -> Genesis {
    Genesis {
        mode: Mode::Open,
        expiry_blocks: 100,
        reveal_max_blocks: 10,
        threshold: 0,
        approvers: vec![],
    }
}
fn page(entries: Vec<NamesEntry>) -> NamesPage {
    NamesPage {
        snapshot: snapshot(),
        chain_genesis: BlockHash::from_byte_array([90; 32]),
        status: NamesStatus {
            genesis: genesis(),
            genesis_block: point(100, 1),
            projected: point(120, 2),
            generation: 9,
            selected_tip: Some(point(130, 3)),
            complete_to_tip: false,
        },
        rules: rules(),
        entries,
        next: None,
    }
}
fn cursor(after: NamesKey) -> NamesCursor {
    NamesCursor {
        genesis: genesis(),
        snapshot: snapshot(),
        after,
    }
}
fn name_entry(name: &str) -> NamesEntry {
    NamesEntry::Name {
        name: Name::parse(name).unwrap(),
        state: NameState::unbound(),
    }
}
fn owner() -> XOnlyPublicKey {
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .unwrap()
}
fn pending_record() -> PendingRecord {
    PendingRecord {
        kind: PendingKind::Request,
        name: Name::parse("a").unwrap(),
        author: owner(),
        target: Txid::from_byte_array([5; 32]),
        sha256: [0; 32],
        height: 110,
        approvals: BTreeSet::new(),
        completed: false,
    }
}
fn pending_entry(txid: Txid) -> NamesEntry {
    NamesEntry::Pending {
        txid,
        record: pending_record(),
    }
}
fn display_order_pair() -> (Txid, Txid) {
    let mut a = [0; 32];
    a[0] = 2;
    a[31] = 1;
    let mut b = [0; 32];
    b[0] = 1;
    b[31] = 2;
    let pair = (Txid::from_byte_array(a), Txid::from_byte_array(b));
    assert!(pair.0 > pair.1, "fixture must oppose internal Txid::Ord");
    assert!(pair.0.to_string() < pair.1.to_string());
    pair
}
fn reply(code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {code} Test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn encoded(page: &NamesPage) -> Vec<u8> {
    serde_json::to_vec(page).unwrap()
}
fn assert_rejected(page: &NamesPage, cursor: Option<&NamesCursor>, limit: u32) {
    for api in APIS {
        let mock = Mock::raw(reply(200, &encoded(page)));
        assert!(
            fetch(api, mock.address, cursor, limit).is_err(),
            "{api:?}: {page:?}"
        );
        mock.finish();
    }
}
fn assert_accepted(page: &NamesPage, cursor: Option<&NamesCursor>, limit: u32) {
    for api in APIS {
        let mock = Mock::raw(reply(200, &encoded(page)));
        let received = fetch(api, mock.address, cursor, limit).unwrap();
        assert_eq!(
            serde_json::to_value(received).unwrap(),
            serde_json::to_value(page).unwrap()
        );
        mock.finish();
    }
}

#[test]
fn first_page_exact_route_auth_empty_get_and_no_automatic_paging() {
    let mut page = page(vec![name_entry("alpha"), name_entry("beta")]);
    page.next = Some(cursor(page.entries.last().unwrap().key()));
    for api in APIS {
        let mock = Mock::raw(reply(200, &encoded(&page)));
        let received = fetch(api, mock.address, None, 2).unwrap();
        assert_eq!(received.next, page.next);
        let request = mock.request();
        assert_eq!(
            request,
            format!(
                "GET /v1/names/{}/view?limit=2 HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
                genesis(),
                mock.address
            )
        );
        mock.finish();
    }
}

#[test]
fn continuation_exact_hex_query_with_maximal_cursor_fields() {
    let mut cursor = cursor(NamesKey::Name(Name::parse(&"z".repeat(63)).unwrap()));
    cursor.snapshot.revision = u64::MAX;
    cursor.snapshot.instance = "ABCDEF0123456789ABCDEF0123456789".into();
    let hex = hex::encode(serde_json::to_vec(&cursor).unwrap());
    assert!(hex.len() <= 1024);
    let mut page = page(vec![pending_entry(Txid::from_byte_array([8; 32]))]);
    page.snapshot = cursor.snapshot.clone();
    page.next = Some(NamesCursor {
        after: page.entries[0].key(),
        ..cursor.clone()
    });
    for api in APIS {
        let mock = Mock::raw(reply(200, &encoded(&page)));
        fetch(api, mock.address, Some(&cursor), 128).unwrap();
        assert!(mock.request().starts_with(&format!(
            "GET /v1/names/{}/view?limit=128&cursor={hex} HTTP/1.1\r\n",
            genesis()
        )));
        mock.finish();
    }
}

#[test]
fn invalid_limit_genesis_and_snapshot_fail_before_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    for api in APIS {
        for limit in [0, 129, u32::MAX] {
            assert!(matches!(
                fetch(api, address, None, limit),
                Err(Error::Invalid(_))
            ));
        }
        let mut wrong = cursor(NamesKey::Name(Name::parse("a").unwrap()));
        wrong.genesis = Txid::from_byte_array([8; 32]);
        assert!(matches!(
            fetch(api, address, Some(&wrong), 1),
            Err(Error::Invalid(_))
        ));
        for instance in [
            "0".repeat(31),
            "0".repeat(33),
            "g".repeat(32),
            "é".repeat(16),
            "0".repeat(1025),
        ] {
            let mut wrong = cursor(NamesKey::Name(Name::parse("a").unwrap()));
            wrong.snapshot.instance = instance;
            assert!(matches!(
                fetch(api, address, Some(&wrong), 1),
                Err(Error::Invalid(_))
            ));
        }
    }
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn names_then_pending_use_display_txid_order_across_pages() {
    let (a, b) = display_order_pair();
    let entries = vec![
        name_entry("a"),
        name_entry("z"),
        pending_entry(a),
        pending_entry(b),
    ];
    assert_accepted(&page(entries.clone()), None, 4);
    let after_name = cursor(entries[1].key());
    assert_accepted(&page(entries[2..].to_vec()), Some(&after_name), 2);
    let after_pending = cursor(entries[2].key());
    assert_accepted(&page(entries[3..].to_vec()), Some(&after_pending), 1);
    assert_rejected(&page(vec![pending_entry(b), pending_entry(a)]), None, 2);
    assert_rejected(&page(vec![pending_entry(a), name_entry("z")]), None, 2);
    assert_rejected(&page(vec![name_entry("z")]), Some(&after_pending), 1);
}

#[test]
fn all_typed_states_completed_pending_and_local_metadata_are_preserved() {
    let mut suspended = NameState::unbound();
    suspended.suspended = true;
    suspended.suspend_votes.insert(owner());
    let bound = NameState {
        binding: Binding::Bound(Bound {
            owner: owner(),
            target: Target::Publication(genesis()),
            expiry: 170,
            claim_txid: Txid::from_byte_array([11; 32]),
            last_txid: Txid::from_byte_array([12; 32]),
        }),
        suspended: false,
        suspend_votes: BTreeSet::new(),
        restore_votes: BTreeSet::from([owner()]),
    };
    let (a, b) = display_order_pair();
    let mut completed = pending_record();
    completed.kind = PendingKind::Update;
    completed.completed = true;
    completed.approvals.insert(owner());
    let page = page(vec![
        name_entry("a"),
        NamesEntry::Name {
            name: Name::parse("b").unwrap(),
            state: suspended,
        },
        NamesEntry::Name {
            name: Name::parse("c").unwrap(),
            state: bound,
        },
        pending_entry(a),
        NamesEntry::Pending {
            txid: b,
            record: completed,
        },
    ]);
    // The client has no configured expected chain or previous page metadata.
    // It preserves these local operator fields for the consumer to compare.
    assert_accepted(&page, None, 5);
}

#[test]
fn entry_count_order_duplicates_and_after_cursor_are_checked() {
    assert_rejected(&page(vec![name_entry("a"), name_entry("b")]), None, 1);
    let entries: Vec<_> = (0..128)
        .map(|index| name_entry(&format!("n{index:03}")))
        .collect();
    assert_accepted(&page(entries.clone()), None, 128);
    let mut excess = entries;
    excess.push(name_entry("n128"));
    assert_rejected(&page(excess), None, 128);
    for entries in [
        vec![name_entry("b"), name_entry("a")],
        vec![name_entry("a"), name_entry("a")],
        vec![pending_entry(genesis()), pending_entry(genesis())],
    ] {
        assert_rejected(&page(entries), None, 2);
    }
    let cursor = cursor(NamesKey::Name(Name::parse("b").unwrap()));
    for name in ["a", "b"] {
        assert_rejected(&page(vec![name_entry(name)]), Some(&cursor), 1);
    }
    assert_accepted(&page(vec![name_entry("c")]), Some(&cursor), 1);
}

#[test]
fn snapshot_and_next_must_match_exact_last_entry() {
    let base = page(vec![name_entry("b")]);
    let input = cursor(NamesKey::Name(Name::parse("a").unwrap()));
    let mut wrong = base.clone();
    wrong.snapshot.revision += 1;
    assert_rejected(&wrong, Some(&input), 1);
    let mut wrong = base.clone();
    wrong.snapshot.instance = "g".repeat(32);
    assert_rejected(&wrong, None, 1);
    let expected = cursor(base.entries[0].key());
    for change in 0..4 {
        let mut wrong = base.clone();
        let mut next = expected.clone();
        match change {
            0 => next.genesis = Txid::from_byte_array([8; 32]),
            1 => next.snapshot.revision += 1,
            2 => next.snapshot.instance = "f".repeat(32),
            _ => next.after = NamesKey::Name(Name::parse("c").unwrap()),
        }
        wrong.next = Some(next);
        assert_rejected(&wrong, None, 1);
    }
    let mut empty = page(vec![]);
    empty.next = Some(expected.clone());
    assert_rejected(&empty, None, 1);
    let mut valid = base;
    valid.next = Some(expected);
    assert_accepted(&valid, Some(&input), 1);
    assert_accepted(&page(vec![]), Some(&input), 1);
}

#[test]
fn status_genesis_heights_hashes_selected_tip_and_completion_are_checked() {
    let base = page(vec![]);
    for change in 0..8 {
        let mut wrong = base.clone();
        match change {
            0 => wrong.status.genesis = Txid::from_byte_array([8; 32]),
            1 => wrong.status.selected_tip = None,
            2 => wrong.status.projected.height = 99,
            3 => wrong.status.selected_tip = Some(point(119, 3)),
            4 => wrong.status.projected = point(100, 99),
            5 => wrong.status.selected_tip = Some(point(120, 99)),
            6 => wrong.status.complete_to_tip = true,
            _ => wrong.status.selected_tip = Some(wrong.status.projected),
        }
        assert_rejected(&wrong, None, 1);
    }
    let mut complete = base;
    complete.status.selected_tip = Some(complete.status.projected);
    complete.status.complete_to_tip = true;
    assert_accepted(&complete, None, 1);
    complete.status.projected = complete.status.genesis_block;
    complete.status.selected_tip = Some(complete.status.genesis_block);
    assert_accepted(&complete, None, 1);
}

#[test]
fn rules_validate_and_have_serialized_byte_bound() {
    let base = page(vec![]);
    for change in 0..4 {
        let mut wrong = base.clone();
        match change {
            0 => wrong.rules.reveal_max_blocks = 0,
            1 => wrong.rules.expiry_blocks = u32::from(wrong.rules.reveal_max_blocks),
            2 => wrong.rules.threshold = 1,
            _ => {
                wrong.rules.mode = Mode::Administered;
                wrong.rules.threshold = 1;
            }
        }
        assert_rejected(&wrong, None, 1);
    }
    let mut valid = base.clone();
    valid.rules.mode = Mode::Administered;
    valid.rules.approvers = vec![owner()];
    valid.rules.threshold = 1;
    assert_accepted(&valid, None, 1);
    let mut oversized = base;
    oversized.rules.approvers = vec![owner(); 1024];
    assert!(serde_json::to_vec(&oversized.rules).unwrap().len() > MAX_NAMES_STATE_BYTES);
    for api in APIS {
        let mock = Mock::raw(reply(200, &encoded(&oversized)));
        assert!(
            matches!(fetch(api, mock.address, None, 1), Err(Error::Invalid(message)) if message.contains("rules exceed 64 KiB"))
        );
        mock.finish();
    }
}

// Real curve public keys supply typed local state, without a consensus/signature
// claim. The client checks size only; it does not replay registry rules here.
fn public_keys() -> Vec<XOnlyPublicKey> {
    let secp = Secp256k1::new();
    (1u32..=1100)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&index.to_be_bytes());
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&bytes).unwrap())
                .x_only_public_key()
                .0
        })
        .collect()
}

#[test]
fn pending_exact_64k_boundary_and_name_state_overflow() {
    let keys = public_keys();
    let mut record = pending_record();
    for key in &keys {
        let mut next = record.clone();
        next.approvals.insert(*key);
        if serde_json::to_vec(&next).unwrap().len() > MAX_NAMES_STATE_BYTES {
            break;
        }
        record = next;
    }
    let remaining = MAX_NAMES_STATE_BYTES - serde_json::to_vec(&record).unwrap().len();
    // Each approval adds 67 bytes. Name padding supplies 0..62 bytes; a decimal
    // hash byte supplies the remaining 1..4 when the gap is 63..66.
    let name_padding = remaining.min(62);
    record.name = Name::parse(&"a".repeat(1 + name_padding)).unwrap();
    let extra = remaining - name_padding;
    for byte in &mut record.sha256[..extra] {
        *byte = 10;
    }
    assert_eq!(
        serde_json::to_vec(&record).unwrap().len(),
        MAX_NAMES_STATE_BYTES
    );
    let exact = page(vec![NamesEntry::Pending {
        txid: genesis(),
        record: record.clone(),
    }]);
    assert_accepted(&exact, None, 1);
    record.sha256[31] = 10;
    assert_eq!(
        serde_json::to_vec(&record).unwrap().len(),
        MAX_NAMES_STATE_BYTES + 1
    );
    assert_rejected(
        &page(vec![NamesEntry::Pending {
            txid: genesis(),
            record,
        }]),
        None,
        1,
    );
    let mut state = NameState::unbound();
    state.suspend_votes = keys.into_iter().collect();
    assert!(serde_json::to_vec(&state).unwrap().len() > MAX_NAMES_STATE_BYTES);
    assert_rejected(
        &page(vec![NamesEntry::Name {
            name: Name::parse("a").unwrap(),
            state,
        }]),
        None,
        1,
    );
}

#[test]
fn raw_page_16m_boundary_is_exact_and_oversize_refused_whole() {
    let mut body = encoded(&page(vec![]));
    body.resize(MAX_NAMES_PAGE_BYTES, b' ');
    for api in APIS {
        let mock = Mock::raw(reply(200, &body));
        assert!(
            fetch(api, mock.address, None, 1)
                .unwrap()
                .entries
                .is_empty()
        );
        mock.finish();
    }
    body.push(b' ');
    for api in APIS {
        let mock = Mock::raw(reply(200, &body));
        assert!(
            matches!(fetch(api, mock.address, None, 1), Err(Error::Invalid(message)) if message.contains("16 MiB"))
        );
        mock.finish();
    }
}

#[test]
fn malformed_typed_payloads_and_strict_outer_fields_are_refused() {
    let base = serde_json::to_value(page(vec![name_entry("a")])).unwrap();
    let mut bodies = vec![b"{".to_vec(), b"null".to_vec()];
    for change in 0..6 {
        let mut value = base.clone();
        match change {
            0 => value["unexpected"] = json!(true),
            1 => value["chain_genesis"] = json!("not-a-hash"),
            2 => value["status"]["genesis"] = json!("not-a-txid"),
            3 => value["entries"][0]["Name"]["name"] = json!("NotCanonical"),
            4 => value["entries"][0]["Name"]["unexpected"] = json!(true),
            _ => value["entries"][0]["Name"]["state"]["binding"] = json!("UnknownBinding"),
        }
        bodies.push(serde_json::to_vec(&value).unwrap());
    }
    let pending = serde_json::to_value(page(vec![pending_entry(genesis())])).unwrap();
    for field in ["txid", "author"] {
        let mut value = pending.clone();
        if field == "txid" {
            value["entries"][0]["Pending"][field] = json!("invalid");
        } else {
            value["entries"][0]["Pending"]["record"][field] = json!("invalid");
        }
        bodies.push(serde_json::to_vec(&value).unwrap());
    }
    let mut bad_cursor = base.clone();
    bad_cursor["next"] =
        serde_json::to_value(cursor(NamesKey::Name(Name::parse("a").unwrap()))).unwrap();
    bad_cursor["next"]["unexpected"] = json!(true);
    bodies.push(serde_json::to_vec(&bad_cursor).unwrap());
    for api in APIS {
        for body in &bodies {
            let mock = Mock::raw(reply(200, body));
            assert!(fetch(api, mock.address, None, 1).is_err());
            mock.finish();
        }
        // Existing inner NameState serde is deliberately unchanged/legacy.
        let mut legacy = base.clone();
        legacy["entries"][0]["Name"]["state"]["future"] = json!(true);
        let mock = Mock::raw(reply(200, &serde_json::to_vec(&legacy).unwrap()));
        assert_eq!(
            fetch(api, mock.address, None, 1).unwrap().entries,
            page(vec![name_entry("a")]).entries
        );
        mock.finish();
    }
}

#[test]
fn http_errors_busy_and_inherited_framing_never_retry_or_reflect_body() {
    for api in APIS {
        for code in [201, 204, 301, 400, 401, 404, 409, 422, 500] {
            let mock = Mock::raw(reply(
                code,
                format!("{{\"reflected\":\"{TOKEN}\"}}").as_bytes(),
            ));
            let error = fetch(api, mock.address, None, 1).unwrap_err();
            assert_eq!(matches!(error, Error::Busy(_)), code == 409);
            assert!(!error.to_string().contains(TOKEN));
            mock.finish();
        }
        for response in [
            b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 Test\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 33554433\r\n\r\n".to_vec(),
        ] {
            let mock = Mock::raw(response); assert!(fetch(api, mock.address, None, 1).is_err()); mock.finish();
        }
        let header = format!(
            "HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX-Pad: {}\r\n\r\n{{}}",
            "x".repeat(8192)
        );
        let mock = Mock::raw(header.into_bytes());
        assert!(
            matches!(fetch(api, mock.address, None, 1), Err(Error::Invalid(message)) if message.contains("8192"))
        );
        mock.finish();
    }
}

#[test]
fn headers_and_body_share_one_absolute_five_second_deadline() {
    for api in APIS {
        let mock = Mock::new(|stream, stop| {
            let _ = write_bounded(
                stream,
                b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\n",
            );
            if !matches!(
                stop.recv_timeout(Duration::from_secs(2)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                return;
            }
            let _ = write_bounded(stream, b"Content-Length: 2\r\n\r\n{");
            let _ = stop.recv_timeout(Duration::from_secs(6));
        });
        let start = Instant::now();
        assert!(matches!(
            fetch(api, mock.address, None, 1),
            Err(Error::Io(_))
        ));
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_millis(6500),
            "{api:?} deadline: {elapsed:?}"
        );
        mock.finish();
    }
}
