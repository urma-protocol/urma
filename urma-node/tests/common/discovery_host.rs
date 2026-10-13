//! Shared harness for peer_discovery.rs and peer_identify.rs. Each case runs
//! as a re-executed test host inside a private user and network namespace
//! whose loopback also owns three public-looking addresses, since gossip and
//! observed addresses carry only public literals; nothing leaves that
//! namespace. Killing the host is cleanup only. Loaded with #[path] next to
//! `mod common`; it is not part of the shared common module.
use crate::common::{config, witness_block};
use bitcoin::BlockHash;
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, atomic::AtomicBool},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use urma_node::{
    engine::Engine,
    model::Retention,
    peer::PeerNetwork,
    peer_discovery::Discovery,
    peerbook::{BookEntry, PeerBook},
};

pub const PUBLIC: [&str; 3] = ["11.0.0.2", "12.0.0.3", "13.0.0.4"];
const CASE_TIMEOUT: Duration = Duration::from_secs(150);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub fn stage(root: &Path, text: &str) {
    fs::write(root.join("stage"), text).unwrap();
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn bare(address: &Multiaddr) -> Multiaddr {
    address
        .iter()
        .filter(|part| !matches!(part, Protocol::P2p(_)))
        .collect()
}

/// Poll `ready` every 50 ms until it holds or `bound` passes.
pub fn until(bound: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    ready()
}

pub struct Node {
    pub engine: Arc<Engine>,
    pub network: Arc<PeerNetwork>,
    pub id: PeerId,
    pub address: Option<Multiaddr>,
}

impl Node {
    pub fn listening(&self) -> Multiaddr {
        self.address.clone().expect("node listens")
    }

    pub fn connected(&self) -> Vec<PeerId> {
        self.network.connected_peer_ids()
    }

    pub fn genesis(&self) -> BlockHash {
        self.engine.status().unwrap().chain_genesis
    }

    /// One explicit dial with the Peers chain probe, bounded at 10 s.
    pub fn dial(&self, address: Multiaddr) -> PeerId {
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(10);
        self.network.dial(address, &cancelled, deadline).unwrap()
    }
}

pub fn offline(root: &Path, name: &str) -> Arc<Engine> {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    let block = witness_block(&[], None, 1);
    let config = config(&block, Retention::Unpruned);
    Arc::new(Engine::open(&directory, config, None).unwrap())
}

pub fn node_on(engine: Arc<Engine>, ip: Option<&str>) -> Node {
    let listen = ip.map(|ip| format!("/ip4/{ip}/tcp/0").parse().unwrap());
    start(engine, listen, Vec::new())
}

fn start(engine: Arc<Engine>, listen: Option<Multiaddr>, announce: Vec<Multiaddr>) -> Node {
    let key = Keypair::generate_ed25519();
    let id = key.public().to_peer_id();
    let network = PeerNetwork::start(engine.clone(), key, listen, announce).unwrap();
    let network = Arc::new(network);
    let address = network.listen_address();
    Node {
        engine,
        network,
        id,
        address,
    }
}

pub fn node(root: &Path, name: &str, ip: Option<&str>) -> Node {
    node_on(offline(root, name), ip)
}

/// A node listening on a free port of `ip` that announces that address.
pub fn announcing_node(root: &Path, name: &str, ip: &str) -> Node {
    let port = std::net::TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen: Multiaddr = format!("/ip4/{ip}/tcp/{port}").parse().unwrap();
    start(offline(root, name), Some(listen.clone()), vec![listen])
}

/// Discovery over `book`, saved at `<root>/<name>/peers.json`. Each step
/// hands the network its gossip snapshot from the book.
pub fn discover(root: &Path, name: &str, node: &Node, book: PeerBook) -> (Discovery, PathBuf) {
    let (discovery, path, _) = discover_shared(root, name, node, book);
    (discovery, path)
}

/// As `discover`, also returning the book the Discovery works on.
pub fn discover_shared(
    root: &Path,
    name: &str,
    node: &Node,
    book: PeerBook,
) -> (Discovery, PathBuf, Arc<Mutex<PeerBook>>) {
    let path = root.join(name).join("peers.json");
    let book = Arc::new(Mutex::new(book));
    let discovery = Discovery::new(node.network.clone(), book.clone(), path.clone());
    (discovery, path, book)
}

pub fn rounds(discovery: &Discovery, node: &Node, count: u64) {
    let stop = AtomicBool::new(false);
    for _ in 0..count {
        discovery.step(&node.engine, &stop).unwrap();
    }
}

pub fn saved_book(path: &Path, node: &Node) -> PeerBook {
    PeerBook::load(path, node.genesis()).unwrap()
}

pub fn entry_of(book: &PeerBook, id: PeerId) -> BookEntry {
    book.entries()
        .iter()
        .find(|entry| entry.peer_id == Some(id))
        .unwrap_or_else(|| panic!("{id} not in book"))
        .clone()
}

/// The owned temporary root and scenario of this host process.
pub fn host() -> (PathBuf, String) {
    let root = std::env::var_os("DISCOVERY_HOST_TEMP").expect("owned TEMP");
    let scenario = std::env::var("DISCOVERY_HOST_SCENARIO").unwrap();
    (PathBuf::from(root), scenario)
}

pub fn report(root: &Path, scenario: &str, checks: Value) {
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

// Local routes default to the destination itself as source address. Pin the
// source of traffic to PUBLIC[1..] on PUBLIC[0], so peers there observe the
// same address for a node on PUBLIC[0], as distinct hosts would.
fn namespace_setup() -> String {
    let mut script = String::from("ip link set lo up");
    for ip in PUBLIC {
        script.push_str(&format!(" && ip addr add {ip}/32 dev lo"));
    }
    for ip in &PUBLIC[1..] {
        script.push_str(&format!(
            " && ip route replace local {ip} dev lo table local proto kernel scope host src {}",
            PUBLIC[0]
        ));
    }
    script
}

// unshare execs the shell, which execs the test binary: the child PID is
// the host itself, so kill reaches it directly.
fn spawn(host: &str, scenario: &str, path: &Path) -> Child {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "sh", "-c"])
        .arg(format!("{} && exec \"$@\"", namespace_setup()))
        .arg("discovery-netns")
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", host])
        .args(["--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DISCOVERY_HOST_TEMP", path)
        .env("DISCOVERY_HOST_SCENARIO", scenario)
        .env("TMPDIR", path)
        .stdin(Stdio::null())
        .stdout(File::create(path.join("stdout.log")).unwrap())
        .stderr(File::create(path.join("stderr.log")).unwrap())
        .spawn()
        .unwrap()
}

/// Run `scenario` in the namespaced `host` test and return its checks.
pub fn run(host: &str, scenario: &str) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let mut owned = OwnedChild {
        child: Some(spawn(host, scenario, path)),
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
