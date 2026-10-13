//! Automatic peer discovery between real TCP/Noise/Yamux PeerNetworks in a
//! private namespace (see common/discovery_host.rs). Seeds and manual entries
//! may be loopback; gossip carries only public literals. Rounds are driven
//! through `Discovery::step`, except the Service case which checks status and
//! the book endpoint over the control API. Counting sinks accept and drop TCP
//! connections to observe dial attempts.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
#[path = "common/discovery_host.rs"]
mod discovery_host;
#[allow(dead_code)]
#[path = "common/inventory_peer.rs"]
mod inventory_peer;
use bitcoin::BlockHash;
use common::{FIRST_HEIGHT, MemorySource, config, profile, witness_block};
use discovery_host::{
    Node, PUBLIC, bare, discover, entry_of, host, node, node_on, now, report, rounds, run,
    saved_book, stage,
};
use inventory_peer::RawPeer;
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_node::{
    engine::Engine,
    model::Retention,
    peer_discovery::Discovery,
    peer_protocol::{GossipPeer, Kind, Reply, VERSION},
    peer_sync::{OverlayInfo, PeerSync},
    peerbook::{Origin, PeerAddress, PeerBook},
    service::Service,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HOST: &str = "peer_discovery_host";
const BACKOFF_FIRST: u64 = 60;

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

fn fresh_id() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
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
    stage(root, "B verifies C from a manual entry, then publishes it");
    let mut book = PeerBook::empty(b.genesis());
    book.add(c.listening(), Origin::Manual).unwrap();
    let (b_discovery, _) = discover(root, "b", &b, book);
    rounds(&b_discovery, &b, 2);
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
    let saved = saved_book(&path, &a);
    let learned = entry_of(&saved, c.id);
    assert_eq!(learned.origin, Origin::Gossip);
    assert_eq!(learned.addrs, vec![bare(&c.listening())]);
    assert!(learned.last_success.is_some());
    assert_eq!(
        entry_of(&saved, b.id).origin,
        Origin::Seed,
        "seed identified"
    );
    let status = a_discovery.status().unwrap();
    let counts = (
        status.seeds,
        status.book,
        status.reached,
        status.reached_ever,
        status.gossip,
    );
    assert_eq!(counts, (1, 2, 2, 2, 1));
    assert!(status.last_seed_round_error.is_none(), "{status:?}");
    assert!(status.last_gossip_error.is_none(), "{status:?}");
    json!({"connected":connected.len(),"learned":c.id.to_string()})
}

fn gossip_hint(addrs: &[&str]) -> GossipPeer {
    GossipPeer {
        peer_id: fresh_id(),
        addrs: addrs.iter().map(|text| text.parse().unwrap()).collect(),
        last_seen: now(),
    }
}

fn private(root: &Path) -> Value {
    let d = node(root, "d", Some(PUBLIC[2]));
    let a = node(root, "a", Some(PUBLIC[0]));
    let own = |node: &Node| GossipPeer {
        peer_id: node.id,
        addrs: vec![bare(&node.listening())],
        last_seen: now(),
    };
    let listed = vec![
        own(&d),
        gossip_hint(&[
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/10.0.0.1/tcp/1",
            "/ip4/192.168.0.1/tcp/1",
            "/ip4/169.254.1.1/tcp/1",
        ]),
        gossip_hint(&["/ip6/::1/tcp/1", "/ip6/fd00::1/tcp/1", "/ip6/fe80::1/tcp/1"]),
        // Mapped and reserved literals pass the wire check; the book drops them.
        gossip_hint(&["/ip6/::ffff:10.0.0.1/tcp/1", "/ip4/240.0.0.1/tcp/1"]),
        own(&a),
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
    let expected = vec![Kind::Peers { limit: 0 }, Kind::Peers { limit: 32 }];
    assert_eq!(asked, expected);
    assert!(
        g.requests()
            .iter()
            .all(|request| request.version == VERSION)
    );
    let saved = saved_book(&path, &a);
    assert_eq!(saved.entries().len(), 2, "{:?}", saved.entries());
    assert_eq!(entry_of(&saved, d.id).origin, Origin::Gossip);
    let manual = entry_of(&saved, g.address().peer_id());
    assert_eq!(manual.origin, Origin::Manual);
    assert!(a.connected().contains(&d.id));
    let named = named_reply(root, &d);
    json!({"stored":saved.entries().len(),"named_reply_stored":named})
}

/// Names come only from operators: one named hint rejects the whole reply,
/// including the valid public peer beside it, and records a gossip error.
fn named_reply(root: &Path, d: &Node) -> usize {
    let listed = vec![
        GossipPeer {
            peer_id: d.id,
            addrs: vec![bare(&d.listening())],
            last_seen: now(),
        },
        gossip_hint(&["/dns4/peer.example/tcp/1"]),
    ];
    let g = RawPeer::gossiping(listed);
    stage(root, "a reply carrying a DNS name is refused whole");
    let a = node(root, "a2", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(g.address().address().clone(), Origin::Manual)
        .unwrap();
    let (discovery, path) = discover(root, "a2", &a, book);
    rounds(&discovery, &a, Discovery::GOSSIP_EVERY + 1);
    assert_eq!(g.requests().len(), 2, "probe and one gossip request");
    let error = discovery.status().unwrap().last_gossip_error;
    assert!(error.is_some_and(|text| text.contains("IP literals")));
    let saved = saved_book(&path, &a);
    assert!(!a.connected().contains(&d.id));
    saved.entries().len() - 1
}

fn backoff_once(root: &Path) -> u32 {
    let sink = Sink::start();
    let a = node(root, "a", None);
    let ghost = fresh_id();
    let mut book = PeerBook::empty(a.genesis());
    let address = sink.address.clone().with(Protocol::P2p(ghost));
    book.add(address, Origin::Manual).unwrap();
    let (discovery, path) = discover(root, "a", &a, book);
    stage(root, "a failed dial backs off and is not retried");
    let before = now();
    rounds(&discovery, &a, 5);
    let after = now();
    assert_eq!(sink.count(), 1, "one dial, then backoff");
    let failed = entry_of(&saved_book(&path, &a), ghost);
    assert_eq!((failed.failures, failed.last_success), (1, None));
    let until = failed.banned_until.unwrap();
    let window = before + BACKOFF_FIRST..=after + BACKOFF_FIRST;
    assert!(window.contains(&until), "{until} outside {window:?}");
    failed.failures
}

fn backoff(root: &Path) -> Value {
    let failures = backoff_once(root);
    stage(root, "an expired backoff is dialed and reset on success");
    let x = node(root, "x", Some("127.0.0.1"));
    let y = node(root, "y", Some("127.0.0.1"));
    let a = node(root, "a2", None);
    let entries = vec![
        manual_entry(Some(x.id), &x.listening(), (None, 3, Some(now() - 1))),
        manual_entry(Some(y.id), &y.listening(), (None, 2, Some(now() + 3600))),
    ];
    let book = write_book(&root.join("a2").join("peers.json"), a.genesis(), entries);
    let (discovery, path) = discover(root, "a2", &a, book);
    let started = now();
    rounds(&discovery, &a, 3);
    assert!(a.connected().contains(&x.id));
    assert!(!a.connected().contains(&y.id) && y.connected().is_empty());
    let reloaded = saved_book(&path, &a);
    let reset = entry_of(&reloaded, x.id);
    assert_eq!((reset.failures, reset.banned_until), (0, None));
    assert!(reset.last_success.is_some_and(|at| at >= started));
    assert_eq!(entry_of(&reloaded, y.id).failures, 2);
    json!({"backoff":failures,"reset":true})
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
    let synced: Vec<String> = discovery
        .sync_sources(&omitting)
        .unwrap()
        .into_iter()
        .map(|(label, _)| label)
        .collect();
    assert_eq!(synced, vec![honest.id.to_string()]);
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

fn seed_entry(address: &Multiaddr, failures: u32, banned_until: Option<u64>) -> Value {
    json!({"peer_id":null,"addrs":[address.to_string()],"origin":"seed",
        "last_success":null,"failures":failures,"banned_until":banned_until})
}

/// The startup pass ignores persisted backoff; afterwards an isolated node
/// retries each seed every round once that seed's own backoff has expired.
fn isolated_seeds(root: &Path) -> Value {
    let (stale, fresh) = (Sink::start(), Sink::start());
    let a = node(root, "a", None);
    let entries = vec![
        seed_entry(&stale.address, 2, Some(now() + 3600)),
        seed_entry(&fresh.address, 0, None),
    ];
    let book = write_book(&root.join("a").join("peers.json"), a.genesis(), entries);
    let (discovery, _) = discover(root, "a", &a, book);
    stage(
        root,
        "startup pass dials both seeds despite a persisted backoff",
    );
    let started = Instant::now();
    rounds(&discovery, &a, 1);
    assert_eq!((stale.count(), fresh.count()), (1, 1));
    let status = discovery.status().unwrap();
    assert!(status.last_seed_round_error.is_some() && status.last_seed_round_error_at.is_some());
    rounds(&discovery, &a, 20);
    assert_eq!((stale.count(), fresh.count()), (1, 1), "backoff holds");
    stage(root, "an isolated node redials the fresh seed after 60 s");
    let retried = discovery_host::until(Duration::from_secs(80), || {
        rounds(&discovery, &a, 1);
        fresh.count() == 2
    });
    let waited = started.elapsed();
    assert!(retried && waited >= Duration::from_secs(59), "{waited:?}");
    assert_eq!(stale.count(), 1, "the stale seed still backs off");
    json!({"retried_after":waited.as_secs() >= 59})
}

/// A connected node below target asks seeds only every SEED_EVERY rounds.
fn connected_seeds(root: &Path) -> Value {
    let live = node(root, "l", Some("127.0.0.1"));
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(live.listening(), Origin::Manual).unwrap();
    let (discovery, _, shared) = discovery_host::discover_shared(root, "a", &a, book);
    rounds(&discovery, &a, 1);
    assert_eq!(a.connected(), vec![live.id]);
    let seed = Sink::start();
    shared
        .lock()
        .unwrap()
        .add(seed.address.clone(), Origin::Seed)
        .unwrap();
    stage(root, "connected under target: seeds every 600 rounds");
    rounds(&discovery, &a, Discovery::SEED_EVERY - 1);
    assert_eq!(seed.count(), 0, "no seed pass between periods");
    rounds(&discovery, &a, 1);
    assert_eq!(seed.count(), 1, "seed pass at round 600");
    json!({"seed_passes":seed.count()})
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
        let address = sink.address.clone().with(Protocol::P2p(fresh_id()));
        book.add(address, Origin::Manual).unwrap();
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

// Overlay status needs the inventory scheduler; discovery refreshes its peers.
fn overlay_service(a: &Node, discovery: Discovery) -> Service {
    let info = OverlayInfo {
        peer_id: a.id.to_string(),
        listen: None,
        peer_book: 1,
        connected: Arc::new(|| 0),
    };
    let sync = PeerSync {
        peers: Vec::new(),
        info,
    };
    Service::bind(
        "127.0.0.1:0".parse().unwrap(),
        TOKEN.into(),
        a.engine.clone(),
    )
    .unwrap()
    .with_peer_sync(sync)
    .unwrap()
    .with_discovery(discovery)
    .unwrap()
}

fn service(root: &Path) -> Value {
    let seed = Sink::start();
    let a = node(root, "a", None);
    let mut book = PeerBook::empty(a.genesis());
    book.add(seed.address.clone(), Origin::Seed).unwrap();
    let (discovery, _) = discover(root, "a", &a, book);
    let service = overlay_service(&a, discovery);
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
    let typed: urma_node_client::model::ServiceStatus = serde_json::from_value(status).unwrap();
    let discovery = typed.overlay.unwrap().discovery.unwrap();
    let counts = (
        discovery.seeds,
        discovery.book,
        discovery.reached,
        discovery.reached_ever,
        discovery.gossip,
    );
    assert_eq!(counts, (1, 1, 0, 0, 0));
    assert!(discovery.last_seed_round_error_at.is_some());
    assert!(discovery.last_gossip_error.is_none());
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
    json!({"book":entries.len()})
}

#[test]
#[ignore = "owned namespaced subprocess host, invoked only by the discovery cases"]
fn peer_discovery_host() {
    let (root, scenario) = host();
    let checks = match scenario.as_str() {
        "discovers" => discovers(&root),
        "private" => private(&root),
        "backoff" => backoff(&root),
        "omitting" => omitting(&root),
        "isolated_seeds" => isolated_seeds(&root),
        "connected_seeds" => connected_seeds(&root),
        "budget" => budget(&root),
        "service" => service(&root),
        _ => panic!("unknown owned scenario"),
    };
    report(&root, &scenario, checks);
}

#[test]
fn fresh_node_with_a_loopback_seed_learns_and_connects_a_gossiped_peer() {
    let checks = run(HOST, "discovers");
    assert_eq!(checks["connected"], 2);
}

#[test]
fn gossiped_private_mapped_reserved_named_and_own_addresses_are_never_stored() {
    let checks = run(HOST, "private");
    assert_eq!(checks["stored"], 2);
    assert_eq!(checks["named_reply_stored"], 0);
}

#[test]
fn failed_dials_back_off_and_an_expired_backoff_resets_on_success() {
    let checks = run(HOST, "backoff");
    assert_eq!(checks["backoff"], 1);
    assert_eq!(checks["reset"], true);
}

#[test]
fn an_omitting_peer_is_neither_dialed_nor_synced_nor_gossiped() {
    let checks = run(HOST, "omitting");
    assert_eq!(checks["gossiped"], 1);
}

#[test]
fn startup_ignores_persisted_seed_backoff_and_isolated_nodes_retry_after_it() {
    let checks = run(HOST, "isolated_seeds");
    assert_eq!(checks["retried_after"], true);
}

#[test]
fn a_connected_node_under_target_queries_seeds_every_600_rounds() {
    let checks = run(HOST, "connected_seeds");
    assert_eq!(checks["seed_passes"], 1);
}

#[test]
fn one_round_spends_at_most_three_operations_and_two_dials() {
    let checks = run(HOST, "budget");
    assert_eq!(checks["first_round"], 3);
}

#[test]
fn service_status_reports_discovery_and_serves_the_peer_book() {
    let checks = run(HOST, "service");
    assert_eq!(checks["book"], 1);
}
