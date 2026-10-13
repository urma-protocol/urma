//! Test-side nodes for peer_inventory.rs: server B (headers and its own scans,
//! serving through a real PeerNetwork), client A's archive, and A's running
//! Service with an authenticated loopback status endpoint.
//! Loaded with #[path]; it is not part of the shared common module.
use crate::common::{FIRST_HEIGHT, MemorySource, config};
use bitcoin::Block;
use libp2p::{PeerId, identity::Keypair};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_node::{
    engine::Engine,
    model::{ArchiveConfig, Retention},
    peer::PeerNetwork,
    peer_sync::{OverlayInfo, PeerSync},
    peerbook::PeerAddress,
    service::{Service, ShutdownHandle},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SYNC_TIMEOUT: Duration = Duration::from_secs(90);

// Contract values may be a bare height or a chain point; compare heights.
pub fn height(value: &Value) -> Option<u64> {
    match value {
        Value::Null => None,
        Value::Number(number) => number.as_u64(),
        Value::Object(map) => map.get("height").and_then(Value::as_u64),
        other => panic!("unexpected height shape: {other}"),
    }
}

pub fn tip(blocks: &[Block]) -> u64 {
    FIRST_HEIGHT + u64::try_from(blocks.len()).unwrap() - 1
}

pub struct Server {
    pub engine: Arc<Engine>,
    pub chain: Arc<MemorySource>,
    pub network: PeerNetwork,
    pub address: PeerAddress,
}

// Node B: headers to the tip, then `scanned` full-block scans of its own.
pub fn server(root: &Path, blocks: &[Block], scanned: usize) -> Server {
    let directory = root.join("b");
    fs::create_dir_all(&directory).unwrap();
    let chain = Arc::new(MemorySource::new(blocks));
    let config = config(&blocks[0], Retention::Unpruned);
    let engine = Arc::new(Engine::open(&directory, config, Some(chain.clone())).unwrap());
    engine.synchronize_headers().unwrap();
    for _ in 0..scanned {
        engine.scan_next().unwrap();
    }
    let key = Keypair::generate_ed25519();
    let id = key.public().to_peer_id();
    let listen = Some("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    let network = PeerNetwork::start(engine.clone(), key, listen, Vec::new()).unwrap();
    let address = PeerAddress::new(id, network.listen_address().unwrap()).unwrap();
    Server {
        engine,
        chain,
        network,
        address,
    }
}

impl Server {
    // B follows a new branch with its own verifier and scans to the tip.
    pub fn follow(&self, blocks: &[Block]) {
        self.chain.replace_branch(blocks);
        self.engine.synchronize_headers().unwrap();
        while self.engine.status().unwrap().scanned_blocks < u64::try_from(blocks.len()).unwrap() {
            self.engine.scan_next().unwrap();
        }
    }
}

pub struct Client {
    directory: PathBuf,
    config: ArchiveConfig,
}

impl Client {
    // Same chain and application start as B; headers only, never a scan.
    pub fn new(root: &Path, blocks: &[Block]) -> Self {
        let directory = root.join("a");
        fs::create_dir_all(&directory).unwrap();
        let client = Self {
            directory,
            config: config(&blocks[0], Retention::Unpruned),
        };
        client.select(blocks);
        client
    }

    pub fn select(&self, blocks: &[Block]) {
        let source = Arc::new(MemorySource::new(blocks));
        let engine = Engine::open(&self.directory, self.config.clone(), Some(source)).unwrap();
        let status = engine.synchronize_headers().unwrap();
        assert_eq!(height(&json!(status.selected_tip)), Some(tip(blocks)));
    }

    pub fn offline(&self) -> Arc<Engine> {
        Arc::new(Engine::open(&self.directory, self.config.clone(), None).unwrap())
    }

    pub fn scan_all(&self, blocks: &[Block]) -> Engine {
        let source = Arc::new(MemorySource::new(blocks));
        let engine = Engine::open(&self.directory, self.config.clone(), Some(source)).unwrap();
        while engine.scan_next().unwrap().scanned_blocks < u64::try_from(blocks.len()).unwrap() {}
        engine
    }
}

fn http_status(address: SocketAddr, path: &str) -> io::Result<Value> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
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

// The client network outlives the Service: PeerSource handles do not keep it
// alive, so it is dropped only after the Service has joined.
pub struct Running {
    address: SocketAddr,
    handle: ShutdownHandle,
    worker: Option<JoinHandle<Result<(), urma_node::Error>>>,
    network: Option<PeerNetwork>,
}

impl Running {
    // A's Service with its own client network and the given inventory peers.
    pub fn start(engine: Arc<Engine>, peers: Vec<PeerAddress>) -> Self {
        let network = PeerNetwork::start(
            engine.clone(),
            Keypair::generate_ed25519(),
            None,
            Vec::new(),
        )
        .unwrap();
        let peers = peers
            .into_iter()
            .map(|address| (address.peer_id().to_string(), network.source(address)))
            .collect();
        let info = OverlayInfo {
            peer_id: network.peer_id().to_string(),
            listen: None,
            peer_book: 0,
            connected: Arc::new(|| 0),
        };
        let service = Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine)
            .unwrap()
            .with_peer_sync(PeerSync { peers, info })
            .unwrap();
        let address = service.address().unwrap();
        let handle = service.shutdown_handle();
        let worker = Some(thread::spawn(move || service.run(true)));
        Self {
            address,
            handle,
            worker,
            network: Some(network),
        }
    }

    pub fn status(&self) -> Value {
        http_status(self.address, "/v1/status").unwrap()
    }

    // Poll until the predicate holds, keeping every observed status.
    pub fn until(&self, ready: impl Fn(&Value) -> bool) -> Vec<Value> {
        let deadline = Instant::now() + SYNC_TIMEOUT;
        let mut seen = Vec::new();
        loop {
            let status = self.status();
            let done = ready(&status);
            seen.push(status);
            if done {
                return seen;
            }
            assert!(Instant::now() < deadline, "sync bound: {:?}", seen.last());
            thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn stop(mut self) {
        self.join().unwrap();
    }

    pub fn connected(&self) -> Vec<PeerId> {
        self.network.as_ref().unwrap().connected_peer_ids()
    }

    // A step checks stop between requests; one in-flight peer call may still
    // take its own 10 s bound before the worker returns.
    fn join(&mut self) -> Result<(), String> {
        self.handle.request();
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !worker.is_finished() {
            if Instant::now() >= deadline {
                return Err("service join exceeded bound".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let joined = match worker.join() {
            Ok(Ok(())) => Ok(()),
            other => Err(format!("service ended abnormally: {other:?}")),
        };
        if let Some(network) = self.network.take() {
            network.shutdown().map_err(|error| error.to_string())?;
        }
        joined
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            eprintln!("{error}");
        }
    }
}
