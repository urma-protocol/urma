//! Two actual TCP/Noise/Yamux library endpoints, independent archive engines,
//! and genuine signed fixtures. Owned loopback only; no daemon/discovery claim.
//! A subprocess supervises blocking library calls. An overrun is a test failure;
//! killing that subprocess is cleanup, never evidence of a successful join.

#[allow(dead_code)]
mod common;

use bitcoin::{Block, Network, Txid, consensus::serialize};
use common::{
    Body, FIRST_HEIGHT, MemorySource, SignedPair, config, point, profile, readonly_archive,
    witness_block,
};
use libp2p::{Multiaddr, identity::Keypair, multiaddr::Protocol};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use urma_chain::{inclusion::TransactionProof, observation::Chain};
use urma_node::{
    Error,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, RecordPackage, Retention},
    peer::PeerNetwork,
    peerbook::PeerAddress,
    retrieval::RecordSource,
};

const CASE_TIMEOUT: Duration = Duration::from_secs(45);
const START_TIMEOUT: Duration = Duration::from_secs(15);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

fn stage(directory: &Path, text: &str) {
    fs::write(directory.join("stage"), text).unwrap();
}

fn fixture_block() -> (SignedPair, SignedPair, Block) {
    let first = profile();
    let second = SignedPair::load("proof-post");
    assert_ne!(first.reveal.compute_txid(), second.reveal.compute_txid());
    let block = witness_block(
        &[first.transactions(), second.transactions()].concat(),
        None,
        9900,
    );
    (first, second, block)
}

fn package(block: &Block, pair: &SignedPair) -> RecordPackage {
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_txid() == pair.reveal.compute_txid())
        .unwrap();
    RecordPackage {
        version: API_VERSION,
        chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
        block: point(FIRST_HEIGHT, block),
        reveal: TransactionProof::from_block(
            block,
            position as u32,
            pair.raw_reveal.clone(),
            serialize(&block.txdata[0]),
        )
        .unwrap(),
        commit: pair.raw_commit.clone(),
    }
}

fn socket(address: &Multiaddr, expected: libp2p::PeerId) -> SocketAddr {
    let mut parts = address.iter();
    let ip = match parts.next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
        other => panic!("non-owned listener IP: {other:?}"),
    };
    assert!(ip.is_loopback());
    let port = match parts.next() {
        Some(Protocol::Tcp(port)) if port != 0 => port,
        other => panic!("invalid listener port: {other:?}"),
    };
    assert!(matches!(parts.next(), Some(Protocol::P2p(id)) if id == expected));
    assert!(parts.next().is_none());
    SocketAddr::new(ip, port)
}

fn fetch(
    source: &dyn RecordSource,
    txid: Txid,
    deadline: Instant,
) -> Result<Option<RecordPackage>, Error> {
    // Retry only temporary Busy, preserving all success/failure/data assertions.
    // Each production call has its own 10s bound; never begin another call when
    // insufficient case time remains for it and cleanup.
    for attempt in 0..3 {
        assert!(
            deadline.saturating_duration_since(Instant::now()) > CALL_TIMEOUT + CLEANUP_TIMEOUT,
            "insufficient bounded fetch budget"
        );
        let began = Instant::now();
        let result = source.fetch(txid);
        assert!(
            began.elapsed() < CALL_TIMEOUT + Duration::from_secs(1),
            "source exceeded its documented call timeout"
        );
        if !matches!(&result, Err(Error::Busy(_) | Error::PeerBusy)) || attempt == 2 {
            return result;
        }
        thread::sleep(Duration::from_millis(300));
    }
    unreachable!()
}

fn assert_exact(actual: &RecordPackage, expected: &RecordPackage, pair: &SignedPair) {
    assert_eq!(
        serde_json::to_vec(actual).unwrap(),
        serde_json::to_vec(expected).unwrap()
    );
    assert_eq!(actual.reveal.transaction, pair.raw_reveal);
    assert_eq!(actual.commit, pair.raw_commit);
}

fn status(engine: &Engine) -> Value {
    serde_json::to_value(engine.status().unwrap()).unwrap()
}

// A normal archive-reader/network shutdown must release the Engine, its lock,
// both listen sockets, and its owned threads. Linux checks are process-local;
// they never inspect other processes or enumerate any public peers.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    tasks: BTreeSet<(String, String)>,
    sockets: BTreeSet<String>,
}

fn footprint() -> Footprint {
    #[cfg(target_os = "linux")]
    {
        let tasks = fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                let id = entry.file_name().to_string_lossy().into_owned();
                match fs::read_to_string(entry.path().join("comm")) {
                    Ok(name) => Some((id, name.trim_end().to_owned())),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("cannot read process-local task name: {error}"),
                }
            })
            .collect();
        let sockets = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
            .filter_map(|path| {
                let name = path.to_string_lossy().into_owned();
                name.starts_with("socket:[").then_some(name)
            })
            .collect();
        Footprint { tasks, sockets }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Footprint {
            tasks: BTreeSet::new(),
            sockets: BTreeSet::new(),
        }
    }
}

fn assert_closed(addresses: &[SocketAddr]) {
    for address in addresses {
        assert!(address.ip().is_loopback());
        assert!(
            TcpStream::connect_timeout(address, Duration::from_millis(200)).is_err(),
            "listener remains reachable after cleanup: {address}"
        );
    }
}

enum Seed {
    Audited,
    Selective,
    WrongChain,
}
#[derive(Clone, Copy)]
enum Finish {
    Shutdown,
    Drop,
}

struct Pair {
    directory: PathBuf,
    config_a: ArchiveConfig,
    config_b: ArchiveConfig,
    engine_a: Arc<Engine>,
    engine_b: Arc<Engine>,
    source_a: Arc<MemorySource>,
    source_b: Arc<MemorySource>,
    network_a: PeerNetwork,
    network_b: PeerNetwork,
    address_a: PeerAddress,
    address_b: PeerAddress,
    sockets: [SocketAddr; 2],
    first: SignedPair,
    second: SignedPair,
    block: Block,
}

impl Pair {
    fn start(directory: &Path, seed: Seed, control: &Path) -> Self {
        fs::create_dir_all(directory).unwrap();
        let (first, second, block) = fixture_block();
        let config_a = config(&block, Retention::Unpruned);
        let source_a = Arc::new(MemorySource::new(std::slice::from_ref(&block)));
        let (config_b, source_b) = if matches!(&seed, Seed::WrongChain) {
            let genesis = bitcoin::blockdata::constants::genesis_block(Network::Testnet4);
            (
                ArchiveConfig {
                    chain: Chain::BitcoinTestnet4,
                    application_start: point(0, &genesis),
                    retention: Retention::Unpruned,
                },
                Arc::new(MemorySource::with_bodies(
                    Chain::BitcoinTestnet4,
                    0,
                    vec![Body::from(&genesis)],
                )),
            )
        } else {
            (
                config_a.clone(),
                Arc::new(MemorySource::new(std::slice::from_ref(&block))),
            )
        };
        assert!(!Arc::ptr_eq(&source_a, &source_b));
        let engine_a = Arc::new(
            Engine::open(
                &directory.join("a"),
                config_a.clone(),
                Some(source_a.clone()),
            )
            .unwrap(),
        );
        let engine_b = Arc::new(
            Engine::open(
                &directory.join("b"),
                config_b.clone(),
                Some(source_b.clone()),
            )
            .unwrap(),
        );
        engine_a.synchronize_headers().unwrap();
        engine_b.synchronize_headers().unwrap();
        if matches!(&seed, Seed::Selective) {
            engine_a.admit_record(package(&block, &first)).unwrap();
            assert_eq!(engine_a.status().unwrap().scanned_blocks, 0);
        } else {
            assert_eq!(engine_a.scan_next().unwrap().scanned_blocks, 1);
        }
        assert_eq!(engine_b.status().unwrap().scanned_blocks, 0);
        assert!(engine_b.status().unwrap().indexed_through.is_none());
        stage(control, "starting two actual TCP/Noise/Yamux endpoints");
        let key_a = Keypair::generate_ed25519();
        let key_b = Keypair::generate_ed25519();
        let expected_a = key_a.public().to_peer_id();
        let expected_b = key_b.public().to_peer_id();
        assert_ne!(expected_a, expected_b);
        let network_a = PeerNetwork::start(
            Arc::clone(&engine_a),
            key_a,
            Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            Vec::new(),
        )
        .unwrap();
        let network_b = PeerNetwork::start(
            Arc::clone(&engine_b),
            key_b,
            Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(network_a.peer_id(), expected_a);
        assert_eq!(network_b.peer_id(), expected_b);
        let listen_a = network_a.listen_address().expect("actual listener A");
        let listen_b = network_b.listen_address().expect("actual listener B");
        let sockets = [socket(&listen_a, expected_a), socket(&listen_b, expected_b)];
        assert_ne!(sockets[0], sockets[1]);
        let address_a = PeerAddress::new(expected_a, listen_a).unwrap();
        let address_b = PeerAddress::new(expected_b, listen_b).unwrap();
        let pair = Self {
            directory: directory.to_owned(),
            config_a,
            config_b,
            engine_a,
            engine_b,
            source_a,
            source_b,
            network_a,
            network_b,
            address_a,
            address_b,
            sockets,
            first,
            second,
            block,
        };
        // Atomically publish readiness for the parent supervisor.
        let ready = json!({"sockets":pair.sockets,"archive":pair.directory,"config_a":pair.config_a,"config_b":pair.config_b});
        fs::write(
            control.join("ready.tmp"),
            serde_json::to_vec(&ready).unwrap(),
        )
        .unwrap();
        fs::rename(control.join("ready.tmp"), control.join("ready.json")).unwrap();
        pair
    }

    fn finish(self, mode: Finish, control: &Path) -> Value {
        let weak_a = Arc::downgrade(&self.engine_a);
        let weak_b = Arc::downgrade(&self.engine_b);
        let before_a = status(&self.engine_a);
        let before_b = status(&self.engine_b);
        let Self {
            directory,
            config_a,
            config_b,
            engine_a,
            engine_b,
            network_a,
            network_b,
            sockets,
            ..
        } = self;
        stage(
            control,
            "waiting for normal network A shutdown/drop to RETURN",
        );
        let began = Instant::now();
        match mode {
            Finish::Shutdown => network_a.shutdown().unwrap(),
            Finish::Drop => drop(network_a),
        }
        assert!(
            began.elapsed() < CLEANUP_TIMEOUT,
            "normal A join exceeded cleanup bound"
        );
        stage(
            control,
            "waiting for normal network B shutdown/drop to RETURN",
        );
        let began = Instant::now();
        match mode {
            Finish::Shutdown => network_b.shutdown().unwrap(),
            Finish::Drop => drop(network_b),
        }
        assert!(
            began.elapsed() < CLEANUP_TIMEOUT,
            "normal B join exceeded cleanup bound"
        );
        drop(engine_a);
        drop(engine_b);
        assert!(
            weak_a.upgrade().is_none(),
            "A Engine Arc retained after join"
        );
        assert!(
            weak_b.upgrade().is_none(),
            "B Engine Arc retained after join"
        );
        assert_closed(&sockets);
        let reopened_a = Engine::open(&directory.join("a"), config_a, None).unwrap();
        let reopened_b = Engine::open(&directory.join("b"), config_b, None).unwrap();
        assert_eq!(status(&reopened_a), before_a);
        assert_eq!(status(&reopened_b), before_b);
        drop(reopened_a);
        drop(reopened_b);
        json!({"normal_joins_returned":true,"engine_arcs_released":true,"locks_reopened":true,"listeners_closed":true,"archive_a":before_a,"archive_b":before_b})
    }
}

fn selective(pair: &Pair, deadline: Instant) -> Value {
    let first_id = pair.first.reveal.compute_txid();
    let omitted_id = pair.second.reveal.compute_txid();
    let before = pair.engine_b.status().unwrap();
    assert_eq!(before.scanned_blocks, 0);
    assert_eq!(before.stored_transactions, 0);
    assert!(before.indexed_through.is_none());
    let source = pair.network_b.source(pair.address_a.clone());
    let received = fetch(&source, first_id, deadline)
        .unwrap()
        .expect("actual peer package");
    let exported = pair.engine_a.record(first_id).unwrap().unwrap();
    assert_exact(&received, &exported.package, &pair.first);
    let receipt = pair.engine_b.admit_record(received).unwrap();
    assert_eq!(receipt.txid, first_id);
    assert_eq!(receipt.wtxid, pair.first.reveal.compute_wtxid());
    assert_eq!(receipt.block, point(FIRST_HEIGHT, &pair.block));
    let admitted = pair.engine_b.record(first_id).unwrap().unwrap();
    assert_exact(&admitted.package, &exported.package, &pair.first);
    let after = pair.engine_b.status().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.selected_tip, before.selected_tip);
    assert_eq!(after.scanned_blocks, 0);
    assert!(after.indexed_through.is_none());
    assert_eq!(after.unresolved_dependencies, 0);
    assert_eq!(after.stored_transactions, 2);
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 0);
    assert!(pair.engine_b.record(omitted_id).unwrap().is_none());
    let audited = pair.engine_b.scan_next().unwrap();
    assert_eq!(audited.scanned_blocks, 1);
    assert_eq!(
        audited.indexed_through,
        Some(point(FIRST_HEIGHT, &pair.block))
    );
    assert_eq!(audited.stored_transactions, 4);
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 1);
    assert_eq!(pair.source_a.body_calls.load(Ordering::Relaxed), 1);
    let recovered_omission = pair.engine_b.record(omitted_id).unwrap().unwrap();
    let expected_omission = pair.engine_a.record(omitted_id).unwrap().unwrap();
    assert_exact(
        &recovered_omission.package,
        &expected_omission.package,
        &pair.second,
    );
    json!({"selective_scanned":after.scanned_blocks,"selective_indexed":after.indexed_through,"audit_found_omitted":true})
}

fn missing(pair: &Pair, deadline: Instant) -> Value {
    let id = pair.second.reveal.compute_txid();
    assert!(
        pair.block
            .txdata
            .iter()
            .any(|transaction| transaction.compute_txid() == id)
    );
    assert!(pair.engine_a.record(id).unwrap().is_none());
    let before_a = status(&pair.engine_a);
    let before_b = status(&pair.engine_b);
    let source = pair.network_b.source(pair.address_a.clone());
    assert!(fetch(&source, id, deadline).unwrap().is_none());
    assert_eq!(status(&pair.engine_a), before_a);
    assert_eq!(status(&pair.engine_b), before_b);
    assert_eq!(pair.source_a.body_calls.load(Ordering::Relaxed), 0);
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 0);
    assert!(pair.engine_b.record(id).unwrap().is_none());
    assert_eq!(pair.engine_a.scan_next().unwrap().scanned_blocks, 1);
    let after_audit = fetch(&source, id, deadline)
        .unwrap()
        .expect("formerly Missing becomes available after A audit");
    assert_exact(
        &after_audit,
        &pair.engine_a.record(id).unwrap().unwrap().package,
        &pair.second,
    );
    // Fetching an untrusted package alone does not perform B admission/scan.
    assert_eq!(status(&pair.engine_b), before_b);
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 0);
    json!({"missing_was_local":true,"same_source_found_after_audit":true,"b_coverage_unchanged":true})
}

fn wrong_identity(pair: &Pair, deadline: Instant) -> Value {
    let before = status(&pair.engine_b);
    let wrong_id = Keypair::generate_ed25519().public().to_peer_id();
    assert_ne!(wrong_id, pair.address_a.peer_id());
    assert_ne!(wrong_id, pair.address_b.peer_id());
    let mut wrong_address = pair.address_a.address().clone();
    assert!(
        matches!(wrong_address.pop(), Some(Protocol::P2p(id)) if id == pair.address_a.peer_id())
    );
    wrong_address.push(Protocol::P2p(wrong_id));
    // Syntactically valid hint points to the correct owned listener but expects
    // another Noise identity. Public fetch exposes aggregate acquisition failure.
    assert_eq!(socket(&wrong_address, wrong_id), pair.sockets[0]);
    let wrong = pair
        .network_b
        .source(PeerAddress::new(wrong_id, wrong_address).unwrap());
    let first_id = pair.first.reveal.compute_txid();
    let error = fetch(&wrong, first_id, deadline).unwrap_err();
    assert!(matches!(&error, Error::Transport(_)), "{error}");
    assert_eq!(status(&pair.engine_b), before);
    assert!(pair.engine_b.record(first_id).unwrap().is_none());
    // Positive control excludes a dead/wrong TCP address as the explanation.
    let correct = pair.network_b.source(pair.address_a.clone());
    let received = fetch(&correct, first_id, deadline)
        .unwrap()
        .expect("correct identity control");
    assert_exact(
        &received,
        &pair.engine_a.record(first_id).unwrap().unwrap().package,
        &pair.first,
    );
    assert_eq!(status(&pair.engine_b), before);
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 0);
    json!({"wrong_identity_refused":true,"same_socket_correct_identity_succeeded":true,"error":error.to_string()})
}

fn wrong_chain(pair: &Pair, deadline: Instant) -> Value {
    let before_a = status(&pair.engine_a);
    let before_b = status(&pair.engine_b);
    assert_ne!(before_a["chain_genesis"], before_b["chain_genesis"]);
    let source = pair.network_b.source(pair.address_a.clone());
    let error = fetch(&source, pair.first.reveal.compute_txid(), deadline).unwrap_err();
    assert!(
        matches!(&error, Error::Invalid(message) if message.contains("network")),
        "{error}"
    );
    assert_eq!(status(&pair.engine_a), before_a);
    assert_eq!(status(&pair.engine_b), before_b);
    assert!(
        pair.engine_b
            .record(pair.first.reveal.compute_txid())
            .unwrap()
            .is_none()
    );
    assert_eq!(pair.source_b.body_calls.load(Ordering::Relaxed), 0);
    json!({"correct_peer_wrong_chain_refused":true,"error":error.to_string()})
}

fn echo_both_directions(pair: &Pair, deadline: Instant) {
    let id = pair.first.reveal.compute_txid();
    let on_b = pair.network_b.source(pair.address_a.clone());
    let received = fetch(&on_b, id, deadline).unwrap().unwrap();
    pair.engine_b.admit_record(received).unwrap();
    let on_a = pair.network_a.source(pair.address_b.clone());
    let echoed = fetch(&on_a, id, deadline).unwrap().unwrap();
    assert_exact(
        &echoed,
        &pair.engine_a.record(id).unwrap().unwrap().package,
        &pair.first,
    );
}

fn assert_footprint_returns(baseline: &Footprint, global_timer: &mut Option<(String, String)>) {
    if !cfg!(target_os = "linux") {
        // /proc task/socket accounting is Linux-only. The portable checks for
        // returned joins, Engine release, archive locks and ports still run.
        assert_eq!(&footprint(), baseline);
        return;
    }
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        let actual = footprint();
        // futures-timer 3.0.4 deliberately keeps one process-global helper.
        // Record its exact identity once, after an actual exchange. Do not
        // filter threads by name: every other task and every socket must match
        // the original baseline, and a second cycle must reuse this SAME ID.
        let mut expected_tasks = baseline.tasks.clone();
        let candidate = match global_timer.as_ref() {
            Some(timer) => Some(timer.clone()),
            None => {
                let additions: Vec<_> = actual.tasks.difference(&baseline.tasks).collect();
                if additions.len() == 1 && additions[0].1 == "futures-timer" {
                    Some(additions[0].clone())
                } else {
                    None
                }
            }
        };
        if let Some(timer) = candidate {
            expected_tasks.insert(timer.clone());
            if actual.tasks == expected_tasks && actual.sockets == baseline.sockets {
                *global_timer = Some(timer);
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "network tasks/sockets differ from baseline plus exact single global timer {global_timer:?}: baseline {baseline:?}, actual {actual:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_no_scan_rows(directory: &Path) {
    let db = readonly_archive(directory);
    for table in ["scans", "dependencies"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let count: i64 = db
        .query_row("SELECT count(*) FROM events WHERE kind='scan'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
#[ignore = "owned subprocess host, invoked only by the five peer-exchange cases"]
fn peer_exchange_host() {
    let root = PathBuf::from(std::env::var_os("U4_PEER_TEMP").expect("owned TEMP host"));
    let scenario = std::env::var("U4_PEER_SCENARIO").unwrap();
    let deadline = Instant::now() + CASE_TIMEOUT;
    let baseline = footprint();
    assert!(
        baseline
            .tasks
            .iter()
            .all(|(_, name)| name != "futures-timer")
    );
    let mut global_timer = None;
    let seed = match scenario.as_str() {
        "missing" => Seed::Selective,
        "wrong-chain" => Seed::WrongChain,
        _ => Seed::Audited,
    };
    let pair = Pair::start(&root.join("first"), seed, &root);
    stage(&root, &format!("actual endpoints ready: {scenario}"));
    let report = match scenario.as_str() {
        "selective" => selective(&pair, deadline),
        "missing" => missing(&pair, deadline),
        "wrong-id" => wrong_identity(&pair, deadline),
        "wrong-chain" => wrong_chain(&pair, deadline),
        "lifecycle" => {
            echo_both_directions(&pair, deadline);
            json!({"both_directions":true})
        }
        "panic-live" => {
            echo_both_directions(&pair, deadline);
            // Parent intentionally panics only after active endpoints/connections
            // exist. Killing this host is abnormal cleanup, never a graceful join.
            fs::write(root.join("panic-ready"), b"active endpoints").unwrap();
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
            panic!("parent did not reap panic-cleanup host within case deadline");
        }
        _ => panic!("unknown owned peer scenario"),
    };
    let normal = pair.finish(Finish::Shutdown, &root);
    assert_footprint_returns(&baseline, &mut global_timer);
    if scenario != "selective" {
        assert_no_scan_rows(&root.join("first/b"));
    }
    let dropped = if scenario == "lifecycle" {
        let pair = Pair::start(&root.join("drop"), Seed::Audited, &root);
        echo_both_directions(&pair, deadline);
        let outcome = pair.finish(Finish::Drop, &root);
        assert_footprint_returns(&baseline, &mut global_timer);
        outcome
    } else {
        Value::Null
    };
    assert!(Instant::now() < deadline, "case exceeded 45s");
    stage(
        &root,
        "all normal joins returned, Engine ownership and process footprint checked",
    );
    fs::write(root.join("result.json"), serde_json::to_vec(&json!({"actual_endpoints":2,"scenario":scenario,"checks":report,"shutdown":normal,"drop":dropped,"footprint_returned":true,"global_timer":global_timer})).unwrap()).unwrap();
}

struct Host {
    child: Option<Child>,
    directory: PathBuf,
    deadline: Instant,
    ready: Value,
    reaped: Arc<AtomicBool>,
}

impl Host {
    fn spawn(directory: &Path, scenario: &str) -> Self {
        let deadline = Instant::now() + CASE_TIMEOUT;
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "peer_exchange_host",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("U4_PEER_TEMP", directory)
            .env("U4_PEER_SCENARIO", scenario)
            .env("TMPDIR", directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                File::create(directory.join("stdout.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(directory.join("stderr.log")).unwrap(),
            ))
            .spawn()
            .unwrap();
        // Own the child BEFORE any startup assertions, including bind failures.
        let mut host = Self {
            child: Some(child),
            directory: directory.to_owned(),
            deadline,
            ready: Value::Null,
            reaped: Arc::new(AtomicBool::new(false)),
        };
        let startup_deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Ok(bytes) = fs::read(host.directory.join("ready.json")) {
                if let Ok(ready) = serde_json::from_slice::<Value>(&bytes) {
                    host.ready = ready;
                    break;
                }
            }
            if let Some(exit) = host.child.as_mut().unwrap().try_wait().unwrap() {
                host.reaped.store(true, Ordering::Release);
                panic!("peer host exited before readiness: {exit}; {}", host.logs());
            }
            assert!(
                Instant::now() < startup_deadline,
                "peer host startup exceeded bound; {}",
                host.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
        let addresses: Vec<SocketAddr> =
            serde_json::from_value(host.ready["sockets"].clone()).unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(
            addresses
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() != 0)
        );
        host
    }

    fn logs(&self) -> String {
        ["stage", "stdout.log", "stderr.log"]
            .map(|name| {
                let mut output = String::new();
                if let Ok(file) = File::open(self.directory.join(name)) {
                    let _ = file.take(64 * 1024).read_to_string(&mut output);
                }
                output
            })
            .join("\n")
    }

    fn finish(mut self) -> Value {
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.reaped.store(true, Ordering::Release);
                self.child.take();
                assert!(exit.success(), "peer host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                assert_eq!(report["actual_endpoints"], 2);
                assert_eq!(report["shutdown"]["normal_joins_returned"], true);
                assert_eq!(report["shutdown"]["engine_arcs_released"], true);
                assert_eq!(report["shutdown"]["locks_reopened"], true);
                assert_eq!(report["shutdown"]["listeners_closed"], true);
                assert_eq!(report["footprint_returned"], true);
                let timer: (String, String) =
                    serde_json::from_value(report["global_timer"].clone()).unwrap();
                assert!(!timer.0.is_empty());
                assert_eq!(timer.1, "futures-timer");
                return report;
            }
            assert!(
                Instant::now() < self.deadline,
                "peer case exceeded 45s, including shutdown/drop; kill is only failure cleanup, not a successful join; {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn await_panic_ready(&mut self) {
        loop {
            if self.directory.join("panic-ready").exists() {
                return;
            }
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.reaped.store(true, Ordering::Release);
                panic!(
                    "panic host exited before active exchange: {exit}; {}",
                    self.logs()
                );
            }
            assert!(
                Instant::now() < self.deadline,
                "panic readiness exceeded case bound; {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped.store(true, Ordering::Release);
                    return;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => {
                    // Preserve the original assertion during unwinding.
                    eprintln!("peer host cleanup/reap exceeded bound: {result:?}");
                    return;
                }
            }
        }
    }
}

fn run(scenario: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    Host::spawn(directory.path(), scenario).finish()
}

#[test]
fn real_peer_selective_fetch_preserves_exact_package_until_independent_full_audit() {
    let report = run("selective");
    assert_eq!(report["checks"]["selective_scanned"], 0);
    assert!(report["checks"]["selective_indexed"].is_null());
    assert_eq!(report["checks"]["audit_found_omitted"], true);
}

#[test]
fn real_peer_missing_means_local_unavailability_not_chain_absence() {
    let report = run("missing");
    assert_eq!(report["checks"]["missing_was_local"], true);
    assert_eq!(report["checks"]["same_source_found_after_audit"], true);
    assert_eq!(report["checks"]["b_coverage_unchanged"], true);
}

#[test]
fn real_peer_wrong_expected_identity_refuses_same_socket_with_positive_control() {
    let report = run("wrong-id");
    assert_eq!(report["checks"]["wrong_identity_refused"], true);
    assert_eq!(
        report["checks"]["same_socket_correct_identity_succeeded"],
        true
    );
}

#[test]
fn real_peer_correct_identity_wrong_chain_refuses_without_admission() {
    let report = run("wrong-chain");
    assert_eq!(report["checks"]["correct_peer_wrong_chain_refused"], true);
}

#[test]
fn real_peer_shutdown_drop_and_panic_cleanup_release_owned_resources() {
    // These receipts exist only AFTER production shutdown/drop have returned,
    // independent of the parent's abnormal-path kill/reap safety net.
    let report = run("lifecycle");
    assert_eq!(report["checks"]["both_directions"], true);
    for key in [
        "normal_joins_returned",
        "engine_arcs_released",
        "locks_reopened",
        "listeners_closed",
    ] {
        assert_eq!(report["drop"][key], true, "{report}");
    }
    let directory = tempfile::tempdir().unwrap();
    let mut host = Host::spawn(directory.path(), "panic-live");
    host.await_panic_ready();
    let ready = host.ready.clone();
    let reaped = Arc::clone(&host.reaped);
    let began = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned_host = host;
        panic!("intentional parent assertion panic with live peer endpoints");
    }));
    assert!(result.is_err());
    assert!(
        reaped.load(Ordering::Acquire),
        "panic must reap the test host"
    );
    assert!(began.elapsed() < CLEANUP_TIMEOUT + Duration::from_secs(1));
    let addresses: Vec<SocketAddr> = serde_json::from_value(ready["sockets"].clone()).unwrap();
    assert_closed(&addresses);
    let archive = PathBuf::from(ready["archive"].as_str().unwrap());
    assert!(archive.starts_with(directory.path()));
    let config_a: ArchiveConfig = serde_json::from_value(ready["config_a"].clone()).unwrap();
    let config_b: ArchiveConfig = serde_json::from_value(ready["config_b"].clone()).unwrap();
    let engine_a = Engine::open(&archive.join("a"), config_a, None).unwrap();
    let engine_b = Engine::open(&archive.join("b"), config_b, None).unwrap();
    assert_eq!(engine_a.status().unwrap().scanned_blocks, 1);
    assert_eq!(engine_b.status().unwrap().scanned_blocks, 0);
    // This subcase asserts abnormal cleanup and lock release, not graceful
    // PeerNetwork shutdown, crash atomicity, or power-loss durability.
}
