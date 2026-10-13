//! Automatic peer discovery between real TCP/Noise/Yamux PeerNetworks. Gossip
//! only carries public addresses, so every case runs in a private user and
//! network namespace whose loopback also owns three public-looking addresses;
//! nothing leaves that namespace. Seeds and manual entries may be loopback.
//! Rounds are driven directly through `Discovery::step`, except the Service
//! case which checks status and the book endpoint over the control API.
//! Counting sinks accept and drop TCP connections to observe dial attempts.
//! A subprocess owns each case; killing it is cleanup only.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
#[path = "common/inventory_peer.rs"]
mod inventory_peer;
use bitcoin::BlockHash;
use common::{FIRST_HEIGHT, MemorySource, config, profile, witness_block};
use inventory_peer::RawPeer;
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{self, ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use urma_node::{
    engine::Engine,
    model::Retention,
    peer::PeerNetwork,
    peer_discovery::Discovery,
    peer_protocol::{GossipPeer, Kind, Reply, VERSION},
    peerbook::{BookEntry, Origin, PeerAddress, PeerBook},
    service::Service,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PUBLIC: [&str; 3] = ["11.0.0.2", "12.0.0.3", "13.0.0.4"];
const CASE_TIMEOUT: Duration = Duration::from_secs(150);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_FIRST: u64 = 60;

fn stage(root: &Path, text: &str) {
    fs::write(root.join("stage"), text).unwrap();
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bare(address: &Multiaddr) -> Multiaddr {
    address
        .iter()
        .filter(|part| !matches!(part, Protocol::P2p(_)))
        .collect()
}

/// Accepts and drops every TCP connection, counting dial attempts.
struct Sink {
    address: Multiaddr,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Sink {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, flag) = (accepted.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count.fetch_add(1, Ordering::AcqRel);
                        drop(stream);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("sink accept: {error}"),
                }
            }
        });
        Self {
            address: format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap(),
            accepted,
            stop,
            worker: Some(worker),
        }
    }

    fn count(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn closed_port() -> Multiaddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

struct Node {
    engine: Arc<Engine>,
    network: Arc<PeerNetwork>,
    id: PeerId,
    address: Option<Multiaddr>,
}

impl Node {
    fn listening(&self) -> Multiaddr {
        self.address.clone().expect("node listens")
    }

    fn connected(&self) -> Vec<PeerId> {
        self.network.connected_peer_ids()
    }

    fn genesis(&self) -> BlockHash {
        self.engine.status().unwrap().chain_genesis
    }
}

fn offline(root: &Path, name: &str) -> Arc<Engine> {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    let block = witness_block(&[], None, 1);
    let config = config(&block, Retention::Unpruned);
    Arc::new(Engine::open(&directory, config, None).unwrap())
}

fn node_on(engine: Arc<Engine>, ip: Option<&str>) -> Node {
    let key = Keypair::generate_ed25519();
    let id = key.public().to_peer_id();
    let listen = ip.map(|ip| format!("/ip4/{ip}/tcp/0").parse().unwrap());
    let network = Arc::new(PeerNetwork::start(engine.clone(), key, listen).unwrap());
    let address = network.listen_address();
    Node {
        engine,
        network,
        id,
        address,
    }
}

fn node(root: &Path, name: &str, ip: Option<&str>) -> Node {
    node_on(offline(root, name), ip)
}

/// Discovery over `book`, saved at `<root>/<name>/peers.json`. Each step
/// hands the network its gossip snapshot from the same book.
fn discover(root: &Path, name: &str, node: &Node, book: PeerBook) -> (Discovery, PathBuf) {
    let path = root.join(name).join("peers.json");
    let book = Arc::new(Mutex::new(book));
    (
        Discovery::new(node.network.clone(), book, path.clone()),
        path,
    )
}

fn rounds(discovery: &Discovery, node: &Node, count: u64) {
    let stop = AtomicBool::new(false);
    for _ in 0..count {
        discovery.step(&node.engine, &stop).unwrap();
    }
}

fn entry_of(book: &PeerBook, id: PeerId) -> BookEntry {
    book.entries()
        .iter()
        .find(|entry| entry.peer_id == Some(id))
        .unwrap_or_else(|| panic!("{id} not in book"))
        .clone()
}

/// A v2 manual entry with (last_success, failures, banned_until).
fn manual_entry(
    id: Option<PeerId>,
    address: &Multiaddr,
    state: (Option<u64>, u32, Option<u64>),
) -> Value {
    json!({"peer_id":id.map(|id| id.to_string()),"addrs":[bare(address).to_string()],
        "origin":"manual","last_success":state.0,"failures":state.1,"banned_until":state.2})
}

fn write_book(path: &Path, genesis: BlockHash, entries: Vec<Value>) -> PeerBook {
    let document = json!({"version":2,"chain_genesis":genesis.to_string(),"entries":entries});
    fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
    PeerBook::load(path, genesis).unwrap()
}

fn discovers(root: &Path) -> Value {
    let c = node(root, "c", Some(PUBLIC[1]));
    let b = node(root, "b", Some("127.0.0.1"));
    stage(root, "B verifies C from a manual entry");
    let mut book = PeerBook::empty(b.genesis());
    book.add(c.listening(), Origin::Manual).unwrap();
    let (b_discovery, _) = discover(root, "b", &b, book);
    rounds(&b_discovery, &b, 1);
    assert!(b.connected().contains(&c.id));
    stage(root, "fresh A with only B as a loopback seed");
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(bare(&b.listening()), Origin::Seed).unwrap();
    let (a_discovery, path) = discover(root, "a", &a, book);
    rounds(&a_discovery, &a, 1);
    assert_eq!(a.connected(), vec![b.id], "seed dialed at startup");
    rounds(&a_discovery, &a, Discovery::GOSSIP_EVERY);
    let connected = a.connected();
    assert!(
        connected.contains(&b.id) && connected.contains(&c.id),
        "{connected:?}"
    );
    let saved = PeerBook::load(&path, a.genesis()).unwrap();
    let learned = entry_of(&saved, c.id);
    assert_eq!(learned.origin, Origin::Gossip);
    assert_eq!(learned.addrs, vec![bare(&c.listening())]);
    assert!(learned.last_success.is_some());
    let seed = entry_of(&saved, b.id);
    assert_eq!(seed.origin, Origin::Seed, "the seed learned its identity");
    let status = a_discovery.status().unwrap();
    assert_eq!(status["seeds"], 1);
    assert_eq!(status["book"], 2);
    assert_eq!(status["verified"], 2);
    assert_eq!(status["gossip"], 1);
    assert!(status["last_seed_round_error"].is_null(), "{status}");
    assert!(status["last_gossip_error"].is_null(), "{status}");
    json!({"connected":connected.len(),"learned":c.id.to_string()})
}

fn private(root: &Path) -> Value {
    let d = node(root, "d", Some(PUBLIC[2]));
    let a = node(root, "a", Some(PUBLIC[0]));
    let other = || Keypair::generate_ed25519().public().to_peer_id();
    let hint = |addrs: &[&str]| GossipPeer {
        peer_id: other(),
        addrs: addrs.iter().map(|text| text.parse().unwrap()).collect(),
        last_seen: now(),
    };
    let listed = vec![
        GossipPeer {
            peer_id: d.id,
            addrs: vec![bare(&d.listening())],
            last_seen: now(),
        },
        hint(&[
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/10.0.0.1/tcp/1",
            "/ip4/192.168.0.1/tcp/1",
            "/ip4/169.254.1.1/tcp/1",
        ]),
        hint(&["/ip6/::1/tcp/1", "/ip6/fd00::1/tcp/1", "/ip6/fe80::1/tcp/1"]),
        // Names and mapped or reserved literals are refused from gossip too.
        hint(&[
            "/dns4/peer.example/tcp/1",
            "/dnsaddr/peer.example",
            "/ip6/::ffff:8.8.8.8/tcp/1",
            "/ip4/240.0.0.1/tcp/1",
        ]),
        GossipPeer {
            peer_id: a.id,
            addrs: vec![bare(&a.listening())],
            last_seen: now(),
        },
    ];
    let g = RawPeer::gossiping(listed);
    stage(root, "A asks a raw peer that gossips private addresses");
    let mut book = PeerBook::empty(a.genesis());
    book.add(g.address().address().clone(), Origin::Manual)
        .unwrap();
    let (discovery, path) = discover(root, "a", &a, book);
    rounds(&discovery, &a, Discovery::GOSSIP_EVERY + 1);
    let asked: Vec<Kind> = g.requests().iter().map(|request| request.kind).collect();
    // The dial's zero-limit chain probe, then one bounded gossip request.
    assert_eq!(
        asked,
        vec![Kind::Peers { limit: 0 }, Kind::Peers { limit: 32 }]
    );
    assert!(
        g.requests()
            .iter()
            .all(|request| request.version == VERSION)
    );
    let saved = PeerBook::load(&path, a.genesis()).unwrap();
    assert_eq!(saved.entries().len(), 2, "{:?}", saved.entries());
    assert_eq!(entry_of(&saved, d.id).origin, Origin::Gossip);
    assert_eq!(
        entry_of(&saved, g.address().peer_id()).origin,
        Origin::Manual
    );
    assert!(a.connected().contains(&d.id));
    json!({"stored":saved.entries().len(),"dialed_public":true})
}

fn backoff(root: &Path) -> Value {
    let sink = Sink::start();
    let a = node(root, "a", None);
    let ghost = Keypair::generate_ed25519().public().to_peer_id();
    let mut book = PeerBook::empty(a.genesis());
    book.add(
        sink.address.clone().with(Protocol::P2p(ghost)),
        Origin::Manual,
    )
    .unwrap();
    let (discovery, path) = discover(root, "a", &a, book);
    stage(root, "a failed dial backs off and is not retried");
    let before = now();
    rounds(&discovery, &a, 5);
    let after = now();
    assert_eq!(sink.count(), 1, "one dial, then backoff");
    let failed = entry_of(&PeerBook::load(&path, a.genesis()).unwrap(), ghost);
    assert_eq!(failed.failures, 1);
    let until = failed.banned_until.unwrap();
    assert!(
        until >= before + BACKOFF_FIRST && until <= after + BACKOFF_FIRST,
        "{until}"
    );
    assert_eq!(failed.last_success, None);
    stage(root, "an expired backoff is dialed and reset on success");
    let x = node(root, "x", Some("127.0.0.1"));
    let y = node(root, "y", Some("127.0.0.1"));
    let a2 = node(root, "a2", None);
    let path = root.join("a2").join("peers.json");
    let entries = vec![
        manual_entry(Some(x.id), &x.listening(), (None, 3, Some(now() - 1))),
        manual_entry(Some(y.id), &y.listening(), (None, 2, Some(now() + 3600))),
    ];
    let book = write_book(&path, a2.genesis(), entries);
    let (discovery, path) = discover(root, "a2", &a2, book);
    let started = now();
    rounds(&discovery, &a2, 3);
    assert!(a2.connected().contains(&x.id));
    assert!(!a2.connected().contains(&y.id) && y.connected().is_empty());
    let reloaded = PeerBook::load(&path, a2.genesis()).unwrap();
    let reset = entry_of(&reloaded, x.id);
    assert_eq!((reset.failures, reset.banned_until), (0, None));
    assert!(reset.last_success.is_some_and(|at| at >= started));
    assert_eq!(entry_of(&reloaded, y.id).failures, 2);
    json!({"backoff":failed.failures,"reset":true})
}

// A's own scan proves L omitted a record in a range L claimed to cover.
fn omitting_archive(root: &Path, liar: PeerId) -> Arc<Engine> {
    let directory = root.join("a");
    fs::create_dir_all(&directory).unwrap();
    let pair = profile();
    let blocks = vec![witness_block(&pair.transactions(), None, 1)];
    let source = Arc::new(MemorySource::new(&blocks));
    let config = config(&blocks[0], Retention::Unpruned);
    let engine = Engine::open(&directory, config, Some(source)).unwrap();
    let generation = engine.synchronize_headers().unwrap().generation;
    let id = liar.to_string();
    engine
        .record_peer_coverage(&id, FIRST_HEIGHT, FIRST_HEIGHT, generation)
        .unwrap();
    while engine.scan_next().unwrap().scanned_blocks < 1 {}
    assert_eq!(engine.omitting_peers().unwrap(), vec![id]);
    Arc::new(engine)
}

fn omitting(root: &Path) -> Value {
    let liar = node(root, "l", Some(PUBLIC[1]));
    let honest = node(root, "h", Some(PUBLIC[2]));
    let a = node_on(omitting_archive(root, liar.id), Some("127.0.0.1"));
    let at = now() - 100;
    let entries = vec![
        manual_entry(Some(liar.id), &liar.listening(), (Some(at), 0, None)),
        manual_entry(Some(honest.id), &honest.listening(), (Some(at), 0, None)),
    ];
    let book = write_book(&root.join("a").join("peers.json"), a.genesis(), entries);
    let (discovery, _) = discover(root, "a", &a, book);
    stage(root, "A dials only the honest verified peer");
    rounds(&discovery, &a, 3);
    assert!(a.connected().contains(&honest.id));
    assert!(!a.connected().contains(&liar.id) && liar.connected().is_empty());
    let omitting = a.engine.omitting_peers().unwrap();
    let synced: Vec<PeerId> = discovery
        .book()
        .lock()
        .unwrap()
        .sync_addresses(&omitting)
        .iter()
        .map(PeerAddress::peer_id)
        .collect();
    assert_eq!(synced, vec![honest.id]);
    stage(root, "A's Peers answer leaves the omitting peer out");
    let client = RawPeer::start(None);
    let to = PeerAddress::new(a.id, a.listening()).unwrap();
    let Reply::Peers(listed) = client.call(&to, VERSION, Kind::Peers { limit: 32 }) else {
        panic!("Peers refused");
    };
    let ids: Vec<PeerId> = listed.iter().map(|peer| peer.peer_id).collect();
    assert_eq!(ids, vec![honest.id]);
    json!({"gossiped":ids.len(),"liar_dialed":false})
}

fn seeds(root: &Path) -> Value {
    let seed = Sink::start();
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(seed.address.clone(), Origin::Seed).unwrap();
    let (discovery, _) = discover(root, "a", &a, book);
    stage(root, "seeds at startup, then every 600 rounds under target");
    rounds(&discovery, &a, 1);
    assert_eq!(seed.count(), 1);
    assert!(discovery.status().unwrap()["last_seed_round_error"].is_string());
    rounds(&discovery, &a, Discovery::SEED_EVERY - 1);
    assert_eq!(seed.count(), 1, "seeds idle between passes");
    rounds(&discovery, &a, 1);
    assert_eq!(seed.count(), 2, "seeds re-queried while under target");
    stage(root, "four verified entries skip the startup seed pass");
    let late = Sink::start();
    let b = node(root, "b", None);
    let mut entries: Vec<Value> = (0..4)
        .map(|_| {
            let id = Keypair::generate_ed25519().public().to_peer_id();
            manual_entry(Some(id), &closed_port(), (Some(now() - 10), 0, None))
        })
        .collect();
    entries.push(
        json!({"peer_id":null,"addrs":[late.address.to_string()],"origin":"seed",
        "last_success":null,"failures":0,"banned_until":null}),
    );
    let book = write_book(&root.join("b").join("peers.json"), b.genesis(), entries);
    let (discovery, _) = discover(root, "b", &b, book);
    rounds(&discovery, &b, 1);
    assert_eq!(late.count(), 0);
    json!({"seed_passes":seed.count(),"bootstrap_skipped":true})
}

fn budget(root: &Path) -> Value {
    let seeds = [Sink::start(), Sink::start()];
    let manual: Vec<Sink> = (0..4).map(|_| Sink::start()).collect();
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    for sink in &seeds {
        book.add(sink.address.clone(), Origin::Seed).unwrap();
    }
    for sink in &manual {
        let id = Keypair::generate_ed25519().public().to_peer_id();
        book.add(sink.address.clone().with(Protocol::P2p(id)), Origin::Manual)
            .unwrap();
    }
    let (discovery, _) = discover(root, "a", &a, book);
    let dialed = |sinks: &[Sink]| sinks.iter().map(Sink::count).sum::<usize>();
    stage(root, "one round performs at most three network operations");
    rounds(&discovery, &a, 1);
    let first = (dialed(&seeds), dialed(&manual));
    assert_eq!(
        first.0 + first.1,
        Discovery::OPERATIONS_PER_ROUND,
        "{first:?}"
    );
    assert!(first.1 <= Discovery::DIALS_PER_ROUND, "{first:?}");
    rounds(&discovery, &a, 1);
    assert_eq!(dialed(&seeds), first.0, "no seed pass in round 1");
    assert_eq!(dialed(&manual), first.1 + Discovery::DIALS_PER_ROUND);
    json!({"first_round":first.0 + first.1,"dials":Discovery::DIALS_PER_ROUND})
}

fn http(address: SocketAddr, path: &str) -> io::Result<Value> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.take(4 * 1024 * 1024).read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("no header end"))?;
    if !raw.starts_with(b"HTTP/1.1 200") {
        return Err(io::Error::other(String::from_utf8_lossy(&raw).into_owned()));
    }
    serde_json::from_slice(&raw[split + 4..]).map_err(io::Error::other)
}

fn service(root: &Path) -> Value {
    let seed = Sink::start();
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(seed.address.clone(), Origin::Seed).unwrap();
    let (discovery, _) = discover(root, "a", &a, book);
    let service = Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.into(),
        a.engine.clone(),
    )
    .unwrap()
    .with_discovery(discovery)
    .unwrap();
    let address = service.address().unwrap();
    let handle = service.shutdown_handle();
    let worker = thread::spawn(move || service.run(true));
    stage(root, "Service reports discovery and serves the book");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        let status = http(address, "/v1/status").unwrap();
        if status["overlay"]["discovery"]["last_seed_round_error"].is_string() {
            break status;
        }
        assert!(Instant::now() < deadline, "{status}");
        thread::sleep(Duration::from_millis(200));
    };
    let block = status["overlay"]["discovery"].clone();
    let typed: urma_node_client::model::DiscoveryStatus =
        serde_json::from_value(block.clone()).unwrap();
    assert_eq!(
        (typed.seeds, typed.book, typed.verified, typed.gossip),
        (1, 1, 0, 0)
    );
    assert!(typed.last_gossip_error.is_none());
    let body = http(address, "/v1/overlay/book").unwrap();
    let entries = body
        .as_array()
        .or(body["entries"].as_array())
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 1, "{body}");
    assert_eq!(entries[0]["origin"], "seed");
    assert_eq!(entries[0]["failures"], 1);
    assert!(entries[0]["banned_until"].is_u64());
    handle.request();
    assert!(worker.join().unwrap().is_ok());
    json!({"status":block,"book":entries.len()})
}

#[test]
#[ignore = "owned namespaced subprocess host, invoked only by the discovery cases"]
fn peer_discovery_host() {
    let root = PathBuf::from(std::env::var_os("PEER_DISCOVERY_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("PEER_DISCOVERY_SCENARIO").unwrap();
    let checks = match scenario.as_str() {
        "discovers" => discovers(&root),
        "private" => private(&root),
        "backoff" => backoff(&root),
        "omitting" => omitting(&root),
        "seeds" => seeds(&root),
        "budget" => budget(&root),
        "service" => service(&root),
        _ => panic!("unknown owned scenario"),
    };
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
                    eprintln!("discovery host reap exceeded bound: {other:?}");
                    return;
                }
            }
        }
    }
}

// unshare execs the shell, which execs the test binary: the child PID is
// the host itself, so kill reaches it directly.
fn spawn(scenario: &str, path: &Path) -> Child {
    let addresses: String = PUBLIC
        .iter()
        .map(|ip| format!(" && ip addr add {ip}/32 dev lo"))
        .collect();
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "sh", "-c"])
        .arg(format!("ip link set lo up{addresses} && exec \"$@\""))
        .arg("peer-discovery-netns")
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "peer_discovery_host"])
        .args(["--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PEER_DISCOVERY_TEMP", path)
        .env("PEER_DISCOVERY_SCENARIO", scenario)
        .env("TMPDIR", path)
        .stdin(Stdio::null())
        .stdout(File::create(path.join("stdout.log")).unwrap())
        .stderr(File::create(path.join("stderr.log")).unwrap())
        .spawn()
        .unwrap()
}

fn run(scenario: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let mut owned = OwnedChild {
        child: Some(spawn(scenario, path)),
        directory: path.to_owned(),
    };
    let deadline = Instant::now() + CASE_TIMEOUT;
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
fn fresh_node_with_a_loopback_seed_learns_and_connects_a_gossiped_peer() {
    let checks = run("discovers");
    assert_eq!(checks["connected"], 2);
}

#[test]
fn gossiped_private_loopback_named_and_local_addresses_are_never_stored() {
    let checks = run("private");
    assert_eq!(checks["stored"], 2);
}

#[test]
fn failed_dials_back_off_and_an_expired_backoff_resets_on_success() {
    let checks = run("backoff");
    assert_eq!(checks["backoff"], 1);
    assert_eq!(checks["reset"], true);
}

#[test]
fn an_omitting_peer_is_neither_dialed_nor_synced_nor_gossiped() {
    let checks = run("omitting");
    assert_eq!(checks["gossiped"], 1);
}

#[test]
fn seeds_are_dialed_at_startup_and_requeried_every_600_rounds_under_target() {
    let checks = run("seeds");
    assert_eq!(checks["seed_passes"], 2);
}

#[test]
fn one_round_spends_at_most_three_operations_and_two_dials() {
    let checks = run("budget");
    assert_eq!(checks["first_round"], 3);
}

#[test]
fn service_status_reports_discovery_and_serves_the_peer_book() {
    let checks = run("service");
    assert_eq!(checks["book"], 1);
}
