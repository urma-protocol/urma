//! M9: the same verification rules embedded and standalone. One corpus of
//! record packages, valid and adversarial, goes through an embedded Engine
//! and through the real urma-node binary fed by test peers over the overlay
//! inventory path; verdicts and stored bytes must agree per package. The real
//! daemon then serves its archive back to a fresh embedded Engine. Genuine
//! signed vectors sit in mock-selected witness blocks: no PoW or consensus
//! claim. The host runs in an owned user+network namespace with loopback only.
//! A foreign-genesis package is refused by the overlay transport before
//! admission: same outcome at an earlier layer, so its message differs.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[path = "common/parity_peer.rs"]
mod parity_peer;
use bitcoin::{Amount, Block, BlockHash, Transaction, Witness, consensus::serialize};
use common::{
    Body, FIRST_HEIGHT, MemorySource, SignedPair, point, profile, readonly_archive, stored_bytes,
    witness_block,
};
use libp2p::identity::Keypair;
use parity_peer::{Offer, ServingPeer};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, RecordPackage, RecordReceipt, Retention},
    peer::PeerNetwork,
    peer_protocol::Placement,
    peerbook::PeerAddress,
    retrieval::RecordSource,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const LISTENING: &str = "URMA Node listening at ";
const CHAIN: Chain = Chain::LitecoinTestnet;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const SYNC_TIMEOUT: Duration = Duration::from_secs(150);
const EXIT_TIMEOUT: Duration = Duration::from_secs(20);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(240);
/// The overlay transport refuses a foreign-network package before admission.
const TRANSPORT_NETWORK: &str = "peer refused record or returned wrong network";
/// Extra refusing peers in `Mode::Keep`: with the corpus peers, more refusing
/// and stale peers than the daemon's eight outbound connection slots.
const CROWD: usize = 8;
/// Peers serving a package proven in an orphaned block, never blamed.
const STALE_CROWD: usize = 8;
const STALE_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest wait for every stale peer to hold a connection before the honest
/// peer comes up anyway.
const STALE_CROWD_WAIT: Duration = Duration::from_secs(30);

/// Whether a serving peer is stopped once its verdict settles.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Release,
    Keep,
}

/// One admission outcome, comparable across embedded and standalone runs.
#[derive(Clone, Debug, PartialEq)]
enum Verdict {
    Stored(Value),
    Stale,
    Invalid(String),
}

fn verdict(result: Result<RecordReceipt, Error>) -> Verdict {
    match result {
        Ok(receipt) => Verdict::Stored(serde_json::to_value(receipt).unwrap()),
        Err(Error::Stale) => Verdict::Stale,
        Err(Error::Invalid(message)) => Verdict::Invalid(message),
        Err(other) => panic!("unexpected admission error: {other:?}"),
    }
}

struct Case {
    name: &'static str,
    offer: Offer,
    /// Expected standalone message when the transport decides first.
    transport: Option<&'static str>,
}

struct Corpus {
    main: Block,
    cases: Vec<Case>,
}

fn genesis(chain: Chain) -> BlockHash {
    chain.genesis().unwrap().0
}

fn position(block: &Block, reveal: &Transaction) -> u32 {
    let wtxid = reveal.compute_wtxid();
    let index = block
        .txdata
        .iter()
        .position(|tx| tx.compute_wtxid() == wtxid);
    u32::try_from(index.expect("reveal in block")).unwrap()
}

fn package(block: &Block, reveal: &Transaction, raw_commit: &[u8]) -> RecordPackage {
    let at = position(block, reveal);
    let index = usize::try_from(at).unwrap();
    RecordPackage {
        version: API_VERSION,
        chain_genesis: genesis(CHAIN),
        block: point(FIRST_HEIGHT, block),
        reveal: TransactionProof::from_block(
            block,
            at,
            serialize(&block.txdata[index]),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: raw_commit.to_vec(),
    }
}

/// The main-chain placement a peer advertises for this reveal.
fn placement(main: &Block, reveal: &Transaction) -> Placement {
    Placement {
        height: FIRST_HEIGHT,
        block_hash: main.block_hash(),
        position: position(main, reveal),
        txid: reveal.compute_txid(),
        wtxid: reveal.compute_wtxid(),
    }
}

/// Same TXID, different witness: flips one byte of one witness item.
fn retouched(reveal: &Transaction, item: usize, byte: usize) -> Transaction {
    let mut changed = reveal.clone();
    let mut items = changed.input[0].witness.to_vec();
    items[item][byte] ^= 1;
    changed.input[0].witness = Witness::from_slice(&items);
    assert_eq!(changed.compute_txid(), reveal.compute_txid());
    assert_ne!(changed.compute_wtxid(), reveal.compute_wtxid());
    changed
}

fn case(name: &'static str, main: &Block, reveal: &Transaction, package: RecordPackage) -> Case {
    Case {
        name,
        offer: Offer {
            genesis: genesis(CHAIN),
            placement: placement(main, reveal),
            package,
        },
        transport: None,
    }
}

/// Every case owns a distinct TXID, so no admission can mask another.
fn corpus() -> Corpus {
    let amount = profile();
    let [valid, witness, avatar, mismatch, foreign, stale, child] = [
        "proof-post",
        "proof-reply",
        "proof-avatar-ega16-reference",
        "proof-profile",
        "proof-private",
        "proof-post-max",
        "multipart/one-leaf",
    ]
    .map(SignedPair::load);
    // Signed bytes stay intact; a Schnorr signature byte flips after signing.
    let forged = retouched(&avatar.reveal, 0, 63);
    let mut included: Vec<Transaction> = [
        &valid, &witness, &amount, &mismatch, &foreign, &stale, &child,
    ]
    .iter()
    .flat_map(|pair| pair.transactions())
    .collect();
    included.extend([avatar.commit.clone(), forged.clone()]);
    let main = witness_block(&included, None, 1);
    let fork = witness_block(&stale.transactions(), None, 2);
    let mut cases = vec![case(
        "valid",
        &main,
        &valid.reveal,
        package(&main, &valid.reveal, &valid.raw_commit),
    )];
    let mut changed = package(&main, &witness.reveal, &witness.raw_commit);
    changed.reveal.transaction = serialize(&retouched(&witness.reveal, 0, 0));
    cases.push(case(
        "witness tampered, same TXID",
        &main,
        &witness.reveal,
        changed,
    ));
    let mut commit = amount.commit.clone();
    commit.output[0].value = commit.output[0].value + Amount::from_sat(1);
    let wrong = package(&main, &amount.reveal, &serialize(&commit));
    cases.push(case("wrong prevout amount", &main, &amount.reveal, wrong));
    let invalid = package(&main, &forged, &avatar.raw_commit);
    cases.push(case("invalid URMA proof", &main, &forged, invalid));
    let crossed = package(&main, &mismatch.reveal, &valid.raw_commit);
    cases.push(case("commit mismatch", &main, &mismatch.reveal, crossed));
    let mut network = package(&main, &foreign.reveal, &foreign.raw_commit);
    network.chain_genesis = genesis(Chain::BitcoinRegtest);
    let mut wrong_chain = case("wrong chain genesis", &main, &foreign.reveal, network);
    wrong_chain.transport = Some(TRANSPORT_NETWORK);
    cases.push(wrong_chain);
    let orphaned = package(&fork, &stale.reveal, &stale.raw_commit);
    cases.push(case("stale generation", &main, &stale.reveal, orphaned));
    let leaf = package(&main, &child.reveal, &child.raw_commit);
    cases.push(case(
        "multipart child without root",
        &main,
        &child.reveal,
        leaf,
    ));
    Corpus { main, cases }
}

fn config(main: &Block) -> ArchiveConfig {
    ArchiveConfig {
        chain: CHAIN,
        application_start: point(FIRST_HEIGHT, main),
        retention: Retention::Unpruned,
    }
}

/// An archive whose only selected header is the main block; never scanned.
fn selected(directory: &Path, main: &Block) -> Engine {
    let bodies = vec![Body::from(main)];
    let source = Arc::new(MemorySource::with_bodies(CHAIN, FIRST_HEIGHT, bodies));
    let engine = Engine::open(directory, config(main), Some(source)).unwrap();
    engine.synchronize_headers().unwrap();
    engine
}

fn embedded(directory: &Path, corpus: &Corpus) -> Vec<Verdict> {
    let engine = selected(directory, &corpus.main);
    corpus
        .cases
        .iter()
        .map(|case| verdict(engine.admit_record(case.offer.package.clone())))
        .collect()
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn http(address: SocketAddr, method: &str, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\nContent-Length: 0\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.take(4 * 1024 * 1024).read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let code = head.split(' ').nth(1).unwrap().parse().unwrap();
    (code, serde_json::from_slice(&raw[split + 4..]).unwrap())
}

/// The spawned binary is owned here; Drop kills and reaps within a bound.
struct Daemon {
    child: Option<Child>,
    stderr: PathBuf,
    control: SocketAddr,
    overlay: PeerAddress,
}

impl Daemon {
    fn start(root: &Path, main: &Block, peers: &[PeerAddress]) -> Self {
        let data = root.join("daemon");
        drop(selected(&data, main));
        let config_path = root.join("config.json");
        fs::write(&config_path, serde_json::to_vec(&config(main)).unwrap()).unwrap();
        private_file(&root.join("service.token"), TOKEN.as_bytes());
        let key = Keypair::generate_ed25519();
        private_file(&root.join("peer.key"), &key.to_protobuf_encoding().unwrap());
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let overlay = format!(
            "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
            key.public().to_peer_id()
        );
        let overlay =
            PeerAddress::new(key.public().to_peer_id(), overlay.parse().unwrap()).unwrap();
        let stderr = root.join("daemon.stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma-node"));
        command
            .env_clear()
            .env("TMPDIR", root)
            .current_dir(root)
            .arg("--data")
            .arg(&data)
            .arg("--config")
            .arg(&config_path)
            .args(["serve", "--listen", "127.0.0.1:0", "--token-file"])
            .arg(root.join("service.token"))
            .args(["--p2p", "--no-commit-public", "--no-seeds", "--peer-key"])
            .arg(root.join("peer.key"))
            .args(["--urma-listen", &format!("127.0.0.1:{port}")]);
        for peer in peers {
            command.args(["--urma-peer", &peer.address().to_string()]);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(File::create(root.join("daemon.stdout")).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut daemon = Self {
            child: Some(child),
            stderr,
            control: "127.0.0.1:0".parse().unwrap(),
            overlay,
        };
        daemon.control = daemon.listening();
        daemon
    }

    fn logs(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn assert_running(&mut self) {
        let exited = self.child.as_mut().unwrap().try_wait().unwrap();
        assert!(
            exited.is_none(),
            "daemon exited: {exited:?}; {}",
            self.logs()
        );
    }

    fn listening(&mut self) -> SocketAddr {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            self.assert_running();
            let logs = self.logs();
            let found = logs.lines().find_map(|line| {
                line.strip_prefix(LISTENING)?
                    .strip_suffix(" (authenticated loopback)")
            });
            if let Some(address) = found {
                return address.parse().unwrap();
            }
            assert!(Instant::now() < deadline, "startup timed out: {logs}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn get(&mut self, path: &str) -> (u16, Value) {
        self.assert_running();
        http(self.control, "GET", path)
    }

    /// Poll status, taking each case's verdict once it settles. With
    /// `Mode::Release` a settled peer is then stopped, freeing its connection
    /// slot; with `Mode::Keep` every peer stays up and the daemon must free
    /// slots itself. A refusal settles only once the peer is backed off with a
    /// recorded error, so a quiet transport retry or an eviction hold-off is
    /// never read as a verdict.
    fn settle(
        &mut self,
        corpus: &Corpus,
        peers: &mut [Option<ServingPeer>],
        expected: &[Verdict],
        mode: Mode,
    ) -> (Vec<Verdict>, Value) {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        let mut verdicts: Vec<Option<Verdict>> = vec![None; corpus.cases.len()];
        loop {
            let (code, status) = self.get("/v1/status");
            assert_eq!(code, 200, "{status}");
            for (index, (case, want)) in corpus.cases.iter().zip(expected).enumerate() {
                let (None, Some(peer)) = (&verdicts[index], &peers[index]) else {
                    continue;
                };
                let entry = peer_status(&status, peer);
                let settled = match want {
                    Verdict::Stored(_) => entry["synced_through"] == json!(FIRST_HEIGHT),
                    Verdict::Invalid(_) => {
                        !entry["backoff_until"].is_null() && entry["last_error"].is_string()
                    }
                    // Stale leaves no error: a second fetch proves a completed turn.
                    Verdict::Stale => peer.served() >= 2,
                };
                if settled {
                    verdicts[index] = Some(standalone(self, &status, case, peer));
                    if mode == Mode::Release {
                        peers[index] = None;
                    }
                }
            }
            if verdicts.iter().all(Option::is_some) {
                return (verdicts.into_iter().flatten().collect(), status);
            }
            assert!(
                Instant::now() < deadline,
                "parity sync bound: {status}; {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn shutdown(mut self) {
        let reply = http(self.control, "POST", "/v1/shutdown");
        assert_eq!(reply, (200, json!({"stopping": true})));
        let mut child = self.child.take().unwrap();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(exit) = child.try_wait().unwrap() {
                assert!(exit.success(), "{exit}; {}", self.logs());
                return;
            }
            assert!(Instant::now() < deadline, "exit timed out: {}", self.logs());
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !matches!(child.try_wait(), Ok(Some(_))) {
            if Instant::now() >= deadline {
                eprintln!("daemon cleanup did not reap");
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn peer_status<'a>(status: &'a Value, peer: &ServingPeer) -> &'a Value {
    let label = peer.address().peer_id().to_string();
    let peers = status["overlay"]["peers"].as_array().unwrap();
    peers
        .iter()
        .find(|entry| entry["label"] == json!(label))
        .unwrap()
}

/// The standalone verdict: stored record, else the peer's recorded error,
/// else (settled with no error and no record) a stale claim.
fn standalone(daemon: &mut Daemon, status: &Value, case: &Case, peer: &ServingPeer) -> Verdict {
    let txid = case.offer.placement.txid;
    let (code, record) = daemon.get(&format!("/v1/records/{txid}"));
    match code {
        200 => Verdict::Stored(record["receipt"].clone()),
        404 => match &peer_status(status, peer)["last_error"] {
            Value::String(message) => Verdict::Invalid(message.clone()),
            Value::Null => Verdict::Stale,
            other => panic!("unexpected last_error shape: {other}"),
        },
        _ => panic!("record lookup {code}: {record}"),
    }
}

fn assert_parity(case: &Case, embedded: &Verdict, standalone: &Verdict) {
    match (case.transport, embedded) {
        (Some(message), Verdict::Invalid(_)) => {
            assert_eq!(
                standalone,
                &Verdict::Invalid(message.into()),
                "{}",
                case.name
            )
        }
        (Some(_), other) => panic!("{}: transport case admitted embedded: {other:?}", case.name),
        (None, _) => assert_eq!(standalone, embedded, "{}", case.name),
    }
}

/// The running daemon serves its archive to a fresh embedded Engine.
fn reverse(root: &Path, corpus: &Corpus, daemon: &Daemon, expected: &[Verdict]) -> usize {
    let engine = Arc::new(selected(&root.join("reverse"), &corpus.main));
    let key = Keypair::generate_ed25519();
    let network = PeerNetwork::start(engine.clone(), key, None, Vec::new()).unwrap();
    let source = network.source(daemon.overlay.clone());
    let mut served = 0;
    for (case, want) in corpus.cases.iter().zip(expected) {
        // The server's per-identity bucket refills four requests per second.
        thread::sleep(Duration::from_millis(300));
        let txid = case.offer.placement.txid;
        let fetched = RecordSource::fetch(&source, txid).unwrap();
        match (want, fetched) {
            (Verdict::Stored(_), Some(package)) => {
                assert_eq!(
                    serde_json::to_value(&package).unwrap(),
                    serde_json::to_value(&case.offer.package).unwrap(),
                    "{}: served package differs",
                    case.name
                );
                assert_eq!(
                    &verdict(engine.admit_record(package)),
                    want,
                    "{}",
                    case.name
                );
                served += 1;
            }
            (Verdict::Stored(_), None) => panic!("{}: daemon lost a stored record", case.name),
            (_, Some(_)) => panic!("{}: daemon serves a refused package", case.name),
            (_, None) => assert!(engine.record(txid).unwrap().is_none()),
        }
    }
    network.shutdown().unwrap();
    served
}

/// Extra refusing peers that, with `Mode::Keep`, outnumber the daemon's
/// outbound connection slots, so convergence needs the daemon to free them.
fn crowd(corpus: &Corpus, mode: Mode) -> Vec<ServingPeer> {
    if mode == Mode::Release {
        return Vec::new();
    }
    let refused = corpus.cases.iter().find(|c| c.name == "commit mismatch");
    let offer = &refused.unwrap().offer;
    (0..CROWD)
        .map(|_| ServingPeer::start(offer.clone()))
        .collect()
}

fn parity(root: &Path, mode: Mode) -> Value {
    let corpus = corpus();
    let expected = embedded(&root.join("embedded"), &corpus);
    let started: Vec<ServingPeer> = corpus
        .cases
        .iter()
        .map(|c| ServingPeer::start(c.offer.clone()))
        .collect();
    let crowd = crowd(&corpus, mode);
    let everyone: Vec<PeerAddress> = started
        .iter()
        .chain(&crowd)
        .map(|peer| peer.address().clone())
        .collect();
    let mut daemon = Daemon::start(root, &corpus.main, &everyone);
    let mut peers: Vec<Option<ServingPeer>> = started.into_iter().map(Some).collect();
    let (verdicts, status) = daemon.settle(&corpus, &mut peers, &expected, mode);
    let mut report = Vec::new();
    for ((case, got), want) in corpus.cases.iter().zip(&verdicts).zip(&expected) {
        assert_parity(case, want, got);
        if let Verdict::Stored(_) = want {
            let txid = case.offer.placement.txid;
            let engine = Engine::open(&root.join("embedded"), config(&corpus.main), None);
            let local = serde_json::to_value(engine.unwrap().record(txid).unwrap()).unwrap();
            let (_, remote) = daemon.get(&format!("/v1/records/{txid}"));
            assert_eq!(remote, local, "{}: stored record differs", case.name);
        }
        report.push(json!({"case":case.name,"embedded":format!("{want:?}"),"standalone":format!("{got:?}")}));
    }
    let overlay = &status["overlay"];
    let stored = expected
        .iter()
        .filter(|v| matches!(v, Verdict::Stored(_)))
        .count();
    let refused = corpus
        .cases
        .iter()
        .zip(&expected)
        .filter(|(c, v)| c.transport.is_none() && matches!(v, Verdict::Invalid(_)))
        .count();
    assert_eq!(overlay["admitted"], json!(stored), "{status}");
    assert!(
        overlay["rejected"].as_u64().unwrap() >= u64::try_from(refused).unwrap(),
        "{status}"
    );
    assert_eq!(status["archive"]["peer_omissions"], 0, "{status}");
    assert_eq!(daemon.get("/v1/overlay/omissions"), (200, json!([])));
    assert!(status["last_inventory_error"].is_null(), "{status}");
    let served = reverse(root, &corpus, &daemon, &expected);
    daemon.shutdown();
    let bytes = |name: &str| stored_bytes(&readonly_archive(&root.join(name)));
    let reference = bytes("embedded");
    assert!(!reference.is_empty());
    assert_eq!(bytes("daemon"), reference, "standalone stored bytes differ");
    assert_eq!(bytes("reverse"), reference, "reverse stored bytes differ");
    json!({"cases":report,"stored":stored,"refused":refused,"reverse_served":served,"crowd":crowd.len()})
}

fn offer(corpus: &Corpus, name: &str) -> Offer {
    let case = corpus.cases.iter().find(|c| c.name == name);
    case.unwrap().offer.clone()
}

/// One observation of the stale crowd and the honest peer, from both sides.
fn sample(
    status: &Value,
    honest: (&PeerAddress, Option<&ServingPeer>),
    crowd: &[ServingPeer],
) -> Value {
    let label = json!(honest.0.peer_id().to_string());
    let peers = status["overlay"]["peers"].as_array().unwrap();
    let entry = peers.iter().find(|entry| entry["label"] == label).unwrap();
    json!({
        "connected": status["overlay"]["connected"],
        "crowd_connected": crowd.iter().filter(|p| p.connections() > 0).count(),
        "crowd_served": crowd.iter().map(ServingPeer::served).sum::<usize>(),
        "honest_up": honest.1.is_some(),
        "honest_connected": honest.1.is_some_and(|peer| peer.connections() > 0),
        "honest_requests": honest.1.map_or(0, ServingPeer::requests),
        "honest_error": entry["last_error"],
        "honest_synced": entry["synced_through"],
    })
}

/// STALE_CROWD peers prove one package in the orphaned fork block at the
/// selected height. The honest peer is configured from the start but only
/// comes up once every stale peer holds a connection (or after a bound), the
/// worst case for slots. Records each distinct observation until the honest
/// record syncs or the bound expires.
fn stale_crowd(root: &Path) -> Value {
    let corpus = corpus();
    let stale = offer(&corpus, "stale generation");
    let crowd: Vec<ServingPeer> = (0..STALE_CROWD)
        .map(|_| ServingPeer::start(stale.clone()))
        .collect();
    let key = Keypair::generate_ed25519();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let at = format!(
        "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
        key.public().to_peer_id()
    );
    let address = PeerAddress::new(key.public().to_peer_id(), at.parse().unwrap()).unwrap();
    let mut everyone: Vec<PeerAddress> = crowd.iter().map(|p| p.address().clone()).collect();
    everyone.push(address.clone());
    let mut daemon = Daemon::start(root, &corpus.main, &everyone);
    let began = Instant::now();
    let (mut timeline, mut last) = (Vec::new(), Value::Null);
    let (mut pending, mut honest) = (Some(key), None);
    let converged = loop {
        let full = crowd.iter().all(|peer| peer.connections() > 0);
        if full || began.elapsed() >= STALE_CROWD_WAIT {
            if let Some(key) = pending.take() {
                honest = Some(ServingPeer::start_at(offer(&corpus, "valid"), key, port));
            }
        }
        let (_, status) = daemon.get("/v1/status");
        let state = sample(&status, (&address, honest.as_ref()), &crowd);
        let synced = state["honest_synced"] == json!(FIRST_HEIGHT);
        if state != last {
            let at = began.elapsed().as_millis();
            timeline.push(json!({"ms": at, "state": state.clone()}));
            last = state;
        }
        if synced || began.elapsed() >= STALE_TIMEOUT {
            break synced;
        }
        thread::sleep(Duration::from_millis(250));
    };
    let seconds = began.elapsed().as_secs();
    let txid = offer(&corpus, "valid").placement.txid;
    let stored = daemon.get(&format!("/v1/records/{txid}")).0 == 200;
    daemon.shutdown();
    json!({"converged":converged,"stored":stored,"seconds":seconds,"timeline":timeline})
}

#[test]
#[ignore = "owned loopback-only namespace host, not a standalone case"]
fn parity_host() {
    let root = PathBuf::from(std::env::var_os("PARITY_TEMP").expect("owned TEMP"));
    let report = match std::env::var("PARITY_MODE").unwrap().as_str() {
        "release" => parity(&root, Mode::Release),
        "keep" => parity(&root, Mode::Keep),
        "stale" => stale_crowd(&root),
        other => panic!("unknown parity mode {other}"),
    };
    fs::write(
        root.join("result.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
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

fn run_host(mode: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "sh", "-c"])
        .args(["ip link set lo up && exec \"$@\"", "parity-netns"])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "parity_host", "--nocapture"])
        .arg("--test-threads=1")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", path)
        .env("PARITY_TEMP", path)
        .env("PARITY_MODE", mode)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(path.join("stdout")).unwrap())
        .stderr(File::create(path.join("stderr")).unwrap())
        .spawn()
        .unwrap();
    let logs = || {
        ["stdout", "stderr", "daemon.stderr"]
            .map(|name| bounded_text(&path.join(name)))
            .join("\n")
    };
    let deadline = Instant::now() + HOST_TIMEOUT;
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            assert!(exit.success(), "parity host: {exit}; {}", logs());
            return serde_json::from_slice(&fs::read(path.join("result.json")).unwrap()).unwrap();
        }
        if Instant::now() >= deadline {
            let pid = i32::try_from(child.id()).unwrap();
            // SAFETY: process_group(0) made this owned child a group leader;
            // nothing outside this test was admitted to that group.
            unsafe {
                kill(-pid, 9);
            }
            let _ = child.wait();
            panic!("parity host exceeded bound; {}", logs());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_report(report: &Value, crowd: usize) {
    assert_eq!(report["cases"].as_array().unwrap().len(), 8, "{report}");
    assert_eq!(report["stored"], 2, "{report}");
    assert_eq!(report["refused"], 4, "{report}");
    assert_eq!(report["reverse_served"], 2, "{report}");
    assert_eq!(report["crowd"], crowd, "{report}");
}

#[test]
fn embedded_and_standalone_engines_reach_identical_verdicts_and_bytes() {
    assert_report(&run_host("release"), 0);
}

#[test]
fn standalone_converges_with_refusing_peers_beyond_its_connection_slots() {
    assert_report(&run_host("keep"), CROWD);
}

#[test]
fn stale_crowd_does_not_starve_an_honest_peer() {
    let report = run_host("stale");
    // The timeline characterizes slot use; shown with --show-output.
    println!("{report}");
    assert_eq!(report["converged"], true, "{report}");
    assert_eq!(report["stored"], true, "{report}");
}
