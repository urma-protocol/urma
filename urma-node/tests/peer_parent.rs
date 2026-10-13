//! Overlay raw-parent requests between actual TCP/Noise/Yamux endpoints on
//! owned loopback. Genuine signed vectors sit in mock-selected
//! witness-authenticated blocks: no PoW, UTXO or consensus claim. A test-side
//! request-response peer speaks the same codec to lie or to send raw requests.
//! A subprocess supervises blocking library calls; killing it is cleanup only.
//! The server's TooLarge reply for a retained parent over PARENT_LIMIT is not
//! reachable here: genuine transactions decode under an 8,000,000-byte cap.
//! peer_codec.rs checks the limit relation; the client hex cap runs below.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{Transaction, Txid, hashes::Hash};
use common::{SignedPair, config, profile, readonly_archive, stored_bytes, witness_block};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    multiaddr::Protocol,
    noise,
    request_response::{self, Event, Message, OutboundRequestId, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::mpsc as async_mpsc;
use urma_chain::observation::Chain;
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, Retention},
    peer::PeerNetwork,
    peer_codec::Codec,
    peer_protocol::{Kind, PARENT_LIMIT, PROTOCOL, Reply, Request, Response, VERSION},
    peerbook::PeerAddress,
    source::CommitSource,
};

const CASE_TIMEOUT: Duration = Duration::from_secs(90);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_BOUND: Duration = Duration::from_secs(12);
const OVERLAY_BOUND: Duration = Duration::from_secs(40);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

fn stage(root: &Path, text: &str) {
    fs::write(root.join("stage"), text).unwrap();
}

fn status(engine: &Engine) -> Value {
    serde_json::to_value(engine.status().unwrap()).unwrap()
}

fn genesis() -> bitcoin::BlockHash {
    Chain::BitcoinRegtest.genesis().unwrap().0
}

struct Node {
    engine: Arc<Engine>,
    chain: Arc<common::MemorySource>,
    network: PeerNetwork,
    address: PeerAddress,
    config: ArchiveConfig,
    directory: PathBuf,
}

// One fully scanned block per node; only the scan above touches its source.
fn node(root: &Path, name: &str, transactions: &[Transaction], nonce: u32) -> Node {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    let block = witness_block(transactions, None, nonce);
    let config = config(&block, Retention::Unpruned);
    let chain = Arc::new(common::MemorySource::new(std::slice::from_ref(&block)));
    let engine = Engine::open(&directory, config.clone(), Some(chain.clone())).unwrap();
    let engine = Arc::new(engine);
    engine.synchronize_headers().unwrap();
    assert_eq!(engine.scan_next().unwrap().scanned_blocks, 1);
    let key = Keypair::generate_ed25519();
    let id = key.public().to_peer_id();
    let listen = Some("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    let network = PeerNetwork::start(engine.clone(), key, listen, Vec::new()).unwrap();
    let address = PeerAddress::new(id, network.listen_address().unwrap()).unwrap();
    Node {
        engine,
        chain,
        network,
        address,
        config,
        directory,
    }
}

impl Node {
    fn calls(&self) -> (usize, usize) {
        (
            self.chain.body_calls.load(Ordering::Relaxed),
            self.chain.header_calls.load(Ordering::Relaxed),
        )
    }

    // Normal shutdown returns, releases the Engine and its lock, and leaves
    // the archive exactly as last observed.
    fn finish(self) -> PathBuf {
        let before = status(&self.engine);
        let weak = Arc::downgrade(&self.engine);
        let began = Instant::now();
        self.network.shutdown().unwrap();
        assert!(began.elapsed() < CLEANUP_TIMEOUT, "network join bound");
        drop(self.engine);
        assert!(weak.upgrade().is_none(), "Engine retained after join");
        let reopened = Engine::open(&self.directory, self.config, None).unwrap();
        assert_eq!(status(&reopened), before);
        self.directory
    }
}

fn dead_address() -> PeerAddress {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let id = Keypair::generate_ed25519().public().to_peer_id();
    let address = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{id}")
        .parse()
        .unwrap();
    PeerAddress::new(id, address).unwrap()
}

fn timed<T>(call: impl FnOnce() -> T) -> T {
    let began = Instant::now();
    let result = call();
    assert!(began.elapsed() < OVERLAY_BOUND, "overlay call bound");
    result
}

fn resolve(engine: &Engine, source: &dyn CommitSource) -> Result<usize, Error> {
    timed(|| engine.resolve_next_dependency(source, &AtomicBool::new(false)))
}

fn assert_resolved(engine: &Engine, pair: &SignedPair, before: &ArchiveStatus) {
    let after = engine.status().unwrap();
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(after.indexed_through, Some(before.application_start));
    assert_eq!(after.scanned_blocks, before.scanned_blocks);
    assert_eq!(after.generation, before.generation);
    let record = engine.record(pair.reveal.compute_txid()).unwrap().unwrap();
    assert_eq!(record.package.commit, pair.raw_commit);
    assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
}

// Read-only after release: exact parent bytes, no invented placement, and
// none of the forbidden bytes ever stored.
fn assert_stored(directory: &Path, pair: &SignedPair, forbidden: &[Vec<u8>]) {
    let db = readonly_archive(directory);
    let stored = stored_bytes(&db);
    assert_eq!(
        stored[&pair.commit.compute_wtxid().to_string()],
        pair.raw_commit
    );
    for bytes in forbidden {
        assert!(!stored.values().any(|raw| raw == bytes), "peer lie stored");
    }
    let placed: i64 = db
        .query_row(
            "SELECT count(*) FROM locators WHERE txid=?1",
            [pair.commit.compute_txid().to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(placed, 0, "auxiliary parent invented placement");
}

struct Call {
    to: PeerAddress,
    request: Request,
    answer: mpsc::SyncSender<Result<Response, String>>,
}

// Test-side codec peer: answers every inbound request with one fixed reply,
// records what it was asked, and can send raw requests of its own.
struct RawPeer {
    address: Option<PeerAddress>,
    calls: async_mpsc::Sender<Call>,
    seen: Arc<Mutex<Vec<Request>>>,
    open: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

fn raw_swarm(key: Keypair) -> Swarm<request_response::Behaviour<Codec>> {
    let behaviour = request_response::Behaviour::with_codec(
        Codec,
        [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(8)),
    );
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(20)))
        .build()
}

struct RawState {
    reply: Option<Reply>,
    seen: Arc<Mutex<Vec<Request>>>,
    open: Arc<AtomicUsize>,
    ready: mpsc::SyncSender<Multiaddr>,
    pending: HashMap<OutboundRequestId, mpsc::SyncSender<Result<Response, String>>>,
}

fn raw_event(
    swarm: &mut Swarm<request_response::Behaviour<Codec>>,
    state: &mut RawState,
    event: SwarmEvent<Event<Request, Response>>,
) {
    match event {
        SwarmEvent::NewListenAddr { mut address, .. } => {
            address.push(Protocol::P2p(*swarm.local_peer_id()));
            let _ = state.ready.try_send(address);
        }
        SwarmEvent::ConnectionEstablished { .. } => {
            state.open.fetch_add(1, Ordering::AcqRel);
        }
        SwarmEvent::ConnectionClosed { .. } => {
            state.open.fetch_sub(1, Ordering::AcqRel);
        }
        SwarmEvent::Behaviour(Event::Message { message, .. }) => match message {
            Message::Request {
                request, channel, ..
            } => {
                state.seen.lock().unwrap().push(request.clone());
                if let Some(result) = state.reply.clone() {
                    let response = Response {
                        version: VERSION,
                        chain_genesis: request.chain_genesis,
                        kind: request.kind,
                        result,
                    };
                    let _ = swarm.behaviour_mut().send_response(channel, response);
                }
            }
            Message::Response {
                request_id,
                response,
            } => {
                if let Some(answer) = state.pending.remove(&request_id) {
                    let _ = answer.try_send(Ok(response));
                }
            }
        },
        SwarmEvent::Behaviour(Event::OutboundFailure {
            request_id, error, ..
        }) => {
            if let Some(answer) = state.pending.remove(&request_id) {
                let _ = answer.try_send(Err(error.to_string()));
            }
        }
        _ => (),
    }
}

async fn raw_loop(
    key: Keypair,
    mut calls: async_mpsc::Receiver<Call>,
    mut state: RawState,
    stop: Arc<AtomicBool>,
) {
    let mut swarm = raw_swarm(key);
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    while !stop.load(Ordering::Acquire) {
        tokio::select! {
            _ = tick.tick() => (),
            call = calls.recv() => {
                let Some(call) = call else { return };
                let id = swarm.behaviour_mut().send_request_with_addresses(
                    &call.to.peer_id(), call.request, vec![call.to.address().clone()]);
                state.pending.insert(id, call.answer);
            }
            event = swarm.select_next_some() => raw_event(&mut swarm, &mut state, event),
        }
    }
}

impl RawPeer {
    fn start(reply: Option<Reply>) -> Self {
        let key = Keypair::generate_ed25519();
        let id: PeerId = key.public().to_peer_id();
        let (calls, receiver) = async_mpsc::channel(4);
        let (ready, listening) = mpsc::sync_channel(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let open = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let state = RawState {
            reply,
            seen: seen.clone(),
            open: open.clone(),
            ready,
            pending: HashMap::new(),
        };
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(raw_loop(key, receiver, state, flag));
        });
        let mut peer = Self {
            address: None,
            calls,
            seen,
            open,
            stop,
            worker: Some(worker),
        };
        let listen = listening.recv_timeout(START_TIMEOUT).expect("raw listener");
        peer.address = Some(PeerAddress::new(id, listen).unwrap());
        peer
    }

    fn address(&self) -> PeerAddress {
        self.address.clone().unwrap()
    }

    fn seen(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }

    // Seen from the liar's side: every connection to it has closed.
    fn await_disconnected(&self) {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while self.open.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < deadline, "liar connection kept open");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn call(&self, to: &PeerAddress, request: Request) -> Result<Response, String> {
        let (answer, receiver) = mpsc::sync_channel(1);
        let to = to.clone();
        self.calls
            .try_send(Call {
                to,
                request,
                answer,
            })
            .unwrap();
        receiver
            .recv_timeout(CALL_BOUND)
            .map_err(|e| e.to_string())?
    }
}

impl Drop for RawPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("raw peer worker panicked");
            }
        }
    }
}

fn assert_asked_once(peer: &RawPeer, txid: Txid) {
    let seen = peer.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].version, VERSION);
    assert_eq!(seen[0].chain_genesis, genesis());
    assert_eq!(seen[0].kind, Kind::Parent { txid });
}

fn honest(root: &Path) -> Value {
    let pair = profile();
    let b = node(root, "b", &pair.transactions(), 7);
    let a = node(root, "a", std::slice::from_ref(&pair.reveal), 1);
    let before = a.engine.status().unwrap();
    assert_eq!(before.unresolved_dependencies, 1);
    let (b_status, b_calls, a_calls) = (status(&b.engine), b.calls(), a.calls());
    stage(root, "A resolves through overlay peer B");
    let overlay = a
        .network
        .commit_source(Chain::BitcoinRegtest, vec![b.address.clone()]);
    assert_eq!(resolve(&a.engine, &overlay).unwrap(), 1);
    assert_resolved(&a.engine, &pair, &before);
    // Serving a retained parent is a read: B neither scans nor calls a source.
    assert_eq!(status(&b.engine), b_status);
    assert_eq!(b.calls(), b_calls);
    assert_eq!(a.calls(), a_calls);
    drop(overlay);
    let a_dir = a.finish();
    b.finish();
    assert_stored(&a_dir, &pair, &[]);
    json!({"resolved":1,"b_unchanged":true,"source_calls":0})
}

fn malicious(root: &Path) -> Value {
    let pair = profile();
    let wrong = SignedPair::load("proof-post");
    let truncated = pair.raw_commit[..pair.raw_commit.len() - 1].to_vec();
    let b = node(root, "b", &pair.transactions(), 7);
    let a = node(root, "a", std::slice::from_ref(&pair.reveal), 1);
    let before = a.engine.status().unwrap();
    let b_calls = b.calls();
    // A different valid transaction (recomputed TXID differs), truncated
    // bytes the chain decoder rejects, the exact parent as uppercase hex,
    // hex over PARENT_LIMIT (refused before decode), then the honest peer.
    // A fresh source starts at the first peer; the four liars fill the first
    // window, so B is reached on the second round.
    let liars = [
        hex::encode(&wrong.raw_commit),
        hex::encode(&truncated),
        hex::encode(&pair.raw_commit).to_uppercase(),
        "00".repeat(PARENT_LIMIT + 1),
    ]
    .map(|hex| RawPeer::start(Some(Reply::Parent(hex))));
    stage(root, "A skips four lying peers before honest B");
    let mut peers: Vec<PeerAddress> = liars.iter().map(RawPeer::address).collect();
    peers.push(b.address.clone());
    let overlay = a.network.commit_source(Chain::BitcoinRegtest, peers);
    let rounds = resolve_within(&a.engine, &overlay, 2);
    assert_resolved(&a.engine, &pair, &before);
    for liar in &liars {
        assert_asked_once(liar, pair.commit.compute_txid());
        liar.await_disconnected();
    }
    assert_eq!(b.calls(), b_calls);
    drop(overlay);
    drop(liars);
    let a_dir = a.finish();
    b.finish();
    assert_stored(&a_dir, &pair, &[wrong.raw_commit, truncated]);
    json!({"lies_rejected":4,"rounds":rounds.len(),"resolved":1})
}

// A fetch visits at most four peers from a window that advances per fetch.
// A liar-only window is an explicit overlay error (or absence when every
// slot was locally Busy); the honest peer must resolve within `max` rounds.
fn resolve_within(engine: &Engine, source: &dyn CommitSource, max: usize) -> Vec<String> {
    let mut rounds = Vec::new();
    for _ in 0..max {
        let outcome = resolve(engine, source);
        rounds.push(format!("{outcome:?}"));
        if matches!(outcome, Ok(1)) {
            return rounds;
        }
        let liar_window =
            matches!(&outcome, Err(Error::CommitSource(m)) if m.starts_with("overlay"));
        assert!(liar_window || matches!(outcome, Ok(0)), "{rounds:?}");
    }
    panic!("honest peer not reached within {max} rounds: {rounds:?}");
}

fn lie(index: usize, pair: &SignedPair, wrong: &SignedPair) -> String {
    match index % 4 {
        0 => hex::encode(&wrong.raw_commit),
        1 => hex::encode(&pair.raw_commit[..pair.raw_commit.len() - 1]),
        2 => hex::encode(&pair.raw_commit).to_uppercase(),
        _ => "00".repeat(PARENT_LIMIT + 1),
    }
}

// Seven answering liars ahead of the honest peer: the bounded fetch window
// must still reach B within three resolution rounds, and A must close every
// liar connection instead of letting answers occupy its outbound slots.
fn crowd(root: &Path) -> Value {
    let pair = profile();
    let wrong = SignedPair::load("proof-post");
    let b = node(root, "b", &pair.transactions(), 7);
    let a = node(root, "a", std::slice::from_ref(&pair.reveal), 1);
    let before = a.engine.status().unwrap();
    let liars: Vec<RawPeer> = (0..7)
        .map(|i| RawPeer::start(Some(Reply::Parent(lie(i, &pair, &wrong)))))
        .collect();
    let mut peers: Vec<PeerAddress> = liars.iter().map(RawPeer::address).collect();
    peers.push(b.address.clone());
    let overlay = a.network.commit_source(Chain::BitcoinRegtest, peers);
    stage(root, "8-peer overlay: seven answering liars, honest last");
    let rounds = resolve_within(&a.engine, &overlay, 3);
    assert_resolved(&a.engine, &pair, &before);
    let parent = pair.commit.compute_txid();
    for liar in &liars {
        let seen = liar.seen();
        assert!(seen.len() <= rounds.len(), "{seen:?}");
        assert!(seen.iter().all(|r| r.kind == Kind::Parent { txid: parent }));
        liar.await_disconnected();
    }
    let asked: usize = liars.iter().map(|liar| liar.seen().len()).sum();
    drop(overlay);
    drop(liars);
    let a_dir = a.finish();
    b.finish();
    let truncated = pair.raw_commit[..pair.raw_commit.len() - 1].to_vec();
    assert_stored(&a_dir, &pair, &[wrong.raw_commit, truncated]);
    json!({"rounds":rounds.len(),"liars_asked":asked,"resolved":1})
}

fn missing(root: &Path) -> Value {
    let pair = profile();
    let other = SignedPair::load("proof-post");
    let b = node(root, "b", &other.transactions(), 7);
    let a = node(root, "a", std::slice::from_ref(&pair.reveal), 1);
    let before = status(&a.engine);
    let parent = pair.commit.compute_txid();
    let chain = Chain::BitcoinRegtest;
    stage(root, "Missing, dead and empty overlay peer lists");
    let live = a.network.commit_source(chain, vec![b.address.clone()]);
    assert_eq!(
        timed(|| live.fetch(parent, &AtomicBool::new(false))).unwrap(),
        None
    );
    let mixed = a
        .network
        .commit_source(chain, vec![dead_address(), b.address.clone()]);
    assert_eq!(
        timed(|| mixed.fetch(parent, &AtomicBool::new(false))).unwrap(),
        None
    );
    assert_eq!(resolve(&a.engine, &mixed).unwrap(), 0);
    let dead = a
        .network
        .commit_source(chain, vec![dead_address(), dead_address()]);
    let error = timed(|| dead.fetch(parent, &AtomicBool::new(false))).unwrap_err();
    assert!(
        matches!(&error, Error::CommitSource(m) if m.starts_with("overlay")),
        "{error}"
    );
    assert!(error.to_string().contains("overlay"));
    // Busy is capacity, not an answer: alone it is absence, beside a
    // transport failure the failure is reported.
    let busy = RawPeer::start(Some(Reply::Busy));
    let only_busy = a.network.commit_source(chain, vec![busy.address()]);
    assert_eq!(
        timed(|| only_busy.fetch(parent, &AtomicBool::new(false))).unwrap(),
        None
    );
    let busy_dead = a
        .network
        .commit_source(chain, vec![dead_address(), busy.address()]);
    let failed = timed(|| busy_dead.fetch(parent, &AtomicBool::new(false))).unwrap_err();
    assert!(
        matches!(&failed, Error::CommitSource(m) if m.starts_with("overlay")),
        "{failed}"
    );
    assert_eq!(busy.seen().len(), 2);
    let empty = a.network.commit_source(chain, vec![]);
    assert_eq!(empty.fetch(parent, &AtomicBool::new(false)).unwrap(), None);
    assert_eq!(status(&a.engine), before);
    drop((live, mixed, dead, only_busy, busy_dead, empty, busy));
    a.finish();
    b.finish();
    json!({"missing":true,"mixed":true,"dead_error":error.to_string(),"busy":true,"empty":true})
}

fn ask(client: &RawPeer, to: &PeerAddress, version: u32, kind: Kind) -> Reply {
    // The server's per-identity bucket refills four requests per second.
    thread::sleep(Duration::from_millis(300));
    let request = Request {
        version,
        chain_genesis: genesis(),
        kind,
    };
    let response = client.call(to, request).unwrap();
    assert_eq!(response.kind, kind);
    assert_eq!(response.chain_genesis, genesis());
    response.result
}

fn server(root: &Path) -> Value {
    let pair = profile();
    let b = node(root, "b", &pair.transactions(), 7);
    let (b_status, b_calls) = (status(&b.engine), b.calls());
    let client = RawPeer::start(None);
    let to = b.address.clone();
    stage(root, "raw requests against node B");
    let v1 = ask(
        &client,
        &to,
        1,
        Kind::Parent {
            txid: pair.commit.compute_txid(),
        },
    );
    assert!(matches!(v1, Reply::UnsupportedVersion), "{v1:?}");
    for (txid, raw) in [
        (pair.commit.compute_txid(), &pair.raw_commit),
        (pair.reveal.compute_txid(), &pair.raw_reveal),
    ] {
        match ask(&client, &to, VERSION, Kind::Parent { txid }) {
            Reply::Parent(hex) => assert_eq!(hex, hex::encode(raw)),
            other => panic!("retained raw transaction not served: {other:?}"),
        }
    }
    let unknown = Txid::from_byte_array([7; 32]);
    let absent = ask(&client, &to, VERSION, Kind::Parent { txid: unknown });
    assert!(matches!(absent, Reply::Missing), "{absent:?}");
    let record = ask(
        &client,
        &to,
        VERSION,
        Kind::Record {
            txid: pair.reveal.compute_txid(),
        },
    );
    assert!(matches!(record, Reply::Record(_)), "{record:?}");
    // Answers come from retained bytes only: no fetch, scan or archive write.
    assert_eq!(status(&b.engine), b_status);
    assert_eq!(b.calls(), b_calls);
    assert!(client.seen().is_empty());
    drop(client);
    b.finish();
    json!({"v1_refused":true,"parents_exact":2,"unknown_missing":true,"record":true})
}

#[test]
#[ignore = "owned subprocess host, invoked only by the overlay parent cases"]
fn peer_parent_host() {
    let root = PathBuf::from(std::env::var_os("PEER_PARENT_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("PEER_PARENT_SCENARIO").unwrap();
    let deadline = Instant::now() + CASE_TIMEOUT;
    let checks = match scenario.as_str() {
        "honest" => honest(&root),
        "malicious" => malicious(&root),
        "crowd" => crowd(&root),
        "missing" => missing(&root),
        "server" => server(&root),
        _ => panic!("unknown owned scenario"),
    };
    assert!(Instant::now() < deadline, "case exceeded bound");
    let report = json!({"scenario":scenario,"checks":checks});
    fs::write(
        root.join("result.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
}

struct OwnedChild {
    child: Option<Child>,
    directory: PathBuf,
}

impl OwnedChild {
    fn logs(&self) -> String {
        ["stage", "stdout.log", "stderr.log"]
            .map(|name| {
                let mut text = String::new();
                if let Ok(file) = File::open(self.directory.join(name)) {
                    let _ = file.take(64 * 1024).read_to_string(&mut text);
                }
                text
            })
            .join("\n")
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
                other => {
                    eprintln!("overlay host reap exceeded bound: {other:?}");
                    return;
                }
            }
        }
    }
}

fn run(scenario: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "peer_parent_host"])
        .args(["--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PEER_PARENT_TEMP", path)
        .env("PEER_PARENT_SCENARIO", scenario)
        .env("TMPDIR", path)
        .stdin(Stdio::null())
        .stdout(File::create(path.join("stdout.log")).unwrap())
        .stderr(File::create(path.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut owned = OwnedChild {
        child: Some(child),
        directory: path.to_owned(),
    };
    let deadline = Instant::now() + CASE_TIMEOUT + CLEANUP_TIMEOUT;
    loop {
        if let Some(exit) = owned.child.as_mut().unwrap().try_wait().unwrap() {
            owned.child.take();
            assert!(exit.success(), "{scenario}: {exit}; {}", owned.logs());
            let report: Value =
                serde_json::from_slice(&fs::read(path.join("result.json")).unwrap()).unwrap();
            assert_eq!(report["scenario"], scenario);
            return report["checks"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "{scenario} exceeded bound; kill is cleanup only; {}",
            owned.logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn overlay_parent_from_retained_peer_record_resolves_without_peer_scan_or_source_call() {
    let checks = run("honest");
    assert_eq!(checks["resolved"], 1);
    assert_eq!(checks["b_unchanged"], true);
}

#[test]
fn lying_parent_peers_are_rejected_unstored_before_honest_peer_resolves() {
    let checks = run("malicious");
    assert_eq!(checks["lies_rejected"], 4);
    assert_eq!(checks["resolved"], 1);
}

#[test]
fn seven_answering_liars_cannot_eclipse_the_honest_eighth_peer() {
    let checks = run("crowd");
    assert_eq!(checks["resolved"], 1);
    assert!(checks["rounds"].as_u64().unwrap() <= 3);
}

#[test]
fn missing_and_dead_overlay_peers_yield_none_or_explicit_overlay_error() {
    let checks = run("missing");
    assert_eq!(checks["missing"], true);
    assert_eq!(checks["mixed"], true);
    assert_eq!(checks["busy"], true);
    assert_eq!(checks["empty"], true);
}

#[test]
fn server_answers_parent_only_from_retained_raw_and_refuses_v1() {
    let checks = run("server");
    assert_eq!(checks["v1_refused"], true);
    assert_eq!(checks["parents_exact"], 2);
    assert_eq!(checks["record"], true);
}
