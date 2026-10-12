//! Actual Linux CLI Git recovery/clone from an owned authenticated Node Service.
//! A local Git PACK is encoded and signed with pure public publication APIs.
//! Mock-selected blocks establish fixture-local membership only: no PoW, UTXO,
//! confirmed chain or portable inclusion claim. CLI reports not_checked.
//! Private staging refusal is tested, not crash/power-loss or all-I/O atomicity.
//! A transparent owned HTTP proxy pauses real Service bytes for observation;
//! it never constructs records, receipts, inclusion proofs or Node callbacks.
#![cfg(target_os = "linux")]
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::{observation::Chain, validation::validate_block_integrity};
use urma_core::multipart::{
    DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest, VerifiedRecord,
};
use urma_git::{descriptor::Descriptor, inventory::Limits, snapshot};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    retrieval,
    service::Service,
    source::ChainSource,
};
use urma_runtime::{multipart::RecoveryLimits, publication::prepare_multipart};
use urma_wallet::funding::Funding;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FIRST_HEIGHT: u64 = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_TIMEOUT: Duration = Duration::from_secs(15);
const HOST_TIMEOUT: Duration = Duration::from_secs(90);
const PAUSE_TIMEOUT: Duration = Duration::from_secs(2);
fn point(height: u64, block: &Block) -> ChainPoint {
    ChainPoint {
        height,
        hash: block.block_hash(),
    }
}
fn stage(control: &Path, text: &str) {
    fs::write(control.join("stage"), text).unwrap();
}
fn witness_block(transactions: &[Transaction], previous: Option<&Block>, nonce: u32) -> Block {
    let mut block = genesis_block(Network::Regtest);
    if let Some(previous) = previous {
        block.header.prev_blockhash = previous.block_hash();
    }
    block.header.nonce = nonce;
    block.header.bits = CompactTarget::from_consensus(0);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    block.txdata.extend_from_slice(transactions);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}
struct Response {
    code: u16,
    body: Vec<u8>,
    wire: Vec<u8>,
}
impl Response {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}
fn http(address: SocketAddr, raw: &str) -> io::Result<Response> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    let mut bytes = raw.as_bytes();
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let count = stream.write(bytes)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[count..];
    }
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Err(io::Error::other("header bound"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).map_err(io::Error::other)?;
    let code = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::other("status absent"))?
        .parse::<u16>()
        .map_err(io::Error::other)?;
    let headers: Vec<_> = text
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        .collect();
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() != 1 {
        return Err(io::Error::other("body length absent/duplicate"));
    }
    let length = lengths[0].1.parse::<usize>().map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("body bound"));
    }
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        stream.set_read_timeout(Some(remaining()?))?;
        let count = stream.read(&mut body[offset..])?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += count;
    }
    remaining()?;
    head.extend_from_slice(&body);
    Ok(Response {
        code,
        body,
        wire: head,
    })
}
fn request(method: &str, path: &str, host: &str, extra: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n")
}
struct Session {
    address: SocketAddr,
    worker: Option<JoinHandle<Result<(), Error>>>,
}
impl Session {
    fn start(engine: Arc<Engine>) -> Self {
        let service = Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine).unwrap();
        let address = service.address().unwrap();
        Self {
            address,
            worker: Some(thread::spawn(move || service.run(false))),
        }
    }
    fn cleanup(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let reply = http(
            self.address,
            &request(
                "POST",
                "/v1/shutdown",
                "loopback",
                &format!("Authorization: Bearer {TOKEN}\r\n"),
            ),
        );
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service join exceeded bound (host cleanup required)".into());
        }
        worker
            .join()
            .map_err(|_| "Service panicked".to_owned())?
            .map_err(|e| e.to_string())?;
        match reply {
            Ok(reply) if reply.code == 200 && reply.json() == json!({"stopping":true}) => Ok(()),
            _ => Err("Service shutdown not acknowledged".into()),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("Service cleanup: {e}");
        }
    }
}

// A process group belongs exclusively to this test host and its CLI/Git children.
// SIGKILL is abnormal host cleanup, never evidence of a graceful daemon join.
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
struct OwnedChild {
    child: Option<Child>,
    group: bool,
}
impl OwnedChild {
    fn terminate(&mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if self.group {
            let pid = i32::try_from(child.id()).map_err(|e| e.to_string())?;
            // SAFETY: process_group(0) was set when spawning this owned child;
            // no process outside this test was admitted to that group.
            unsafe {
                kill(-pid, 9);
            }
        } else {
            let _ = child.kill();
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                other => return Err(format!("owned child reap exceeded bound: {other:?}")),
            }
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(e) = self.terminate() {
            eprintln!("{e}");
        }
    }
}
fn bounded_text(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(file) = File::open(path) {
        file.take(1024 * 1024).read_to_string(&mut text).unwrap();
    }
    text
}

fn wait_child(owned: &mut OwnedChild, logs: &Path) -> ExitStatus {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(exit) = owned.child.as_mut().unwrap().try_wait().unwrap() {
            owned.child.take();
            return exit;
        }
        assert!(
            Instant::now() < deadline,
            "child deadline: {}",
            bounded_text(logs)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn git(directory: &Path, args: &[&str], control: &Path) -> String {
    let output = control.join("git-stdout");
    let errors = control.join("git-stderr");
    let child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", control)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Public fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@localhost")
        .env("GIT_COMMITTER_NAME", "Public fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@localhost")
        .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
        .current_dir(directory)
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(File::create(&output).unwrap())
        .stderr(File::create(&errors).unwrap())
        .spawn()
        .unwrap();
    let mut owned = OwnedChild {
        child: Some(child),
        group: false,
    };
    let exit = wait_child(&mut owned, &errors);
    assert!(
        exit.success(),
        "Git {args:?}: {exit}; {}",
        bounded_text(&errors)
    );
    bounded_text(&output)
}

struct Pack {
    payload: Vec<u8>,
    pack: Vec<u8>,
    descriptor: Descriptor,
    file: Vec<u8>,
}
impl Pack {
    fn new(control: &Path) -> Self {
        let repo = control.join("source-repo");
        fs::create_dir(&repo).unwrap();
        git(
            &repo,
            &["init", "--initial-branch=main", "--object-format=sha1", "."],
            control,
        );
        let file = b"Owned public signed Git archive fixture.\n".to_vec();
        fs::write(repo.join("README.md"), &file).unwrap();
        git(&repo, &["add", "README.md"], control);
        git(&repo, &["commit", "-m", "public fixture"], control);
        let output = control.join("prepared");
        let report =
            snapshot::prepare_named(&repo, &output, &Limits::default(), "archive-fixture").unwrap();
        let payload = fs::read(output.join("object.bin")).unwrap();
        let pack = fs::read(output.join("snapshot.pack")).unwrap();
        assert!(pack.starts_with(b"PACK"));
        assert_eq!(hex::encode(Sha256::digest(&payload)), report.payload_sha256);
        assert_eq!(
            git(&repo, &["rev-parse", "HEAD"], control).trim(),
            hex::encode(&report.descriptor.head)
        );
        let geometry = Geometry::new(payload.len() as u64).unwrap();
        assert_eq!(
            (geometry.parts(), geometry.leaves(), geometry.nodes()),
            (1, 1, 3)
        );
        Self {
            payload,
            pack,
            descriptor: report.descriptor,
            file,
        }
    }
}

struct Signed {
    record: VerifiedRecord,
    reveal: Transaction,
    commit: Transaction,
}
fn signed(record: MultipartRecord) -> Signed {
    // Public deterministic test identity only; no wallet/provider is involved.
    let key =
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[3; 32]).unwrap());
    let funding = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::from_bytes([vec![0, 20], vec![4; 20]].concat()),
        }],
    };
    let plan = prepare_multipart(
        &record,
        &key,
        Funding {
            raw_transaction: hex::encode(serialize(&funding)),
            vout: 0,
        },
        Chain::BitcoinRegtest,
        1,
    )
    .unwrap();
    let commit = deserialize(&hex::decode(plan.commit).unwrap()).unwrap();
    let reveal: Transaction = deserialize(&hex::decode(plan.reveal).unwrap()).unwrap();
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(verified.decode().unwrap(), record);
    Signed {
        record: verified,
        reveal,
        commit,
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Valid,
    MissingData,
    BadReference,
    BadGit,
}
struct Graph {
    records: Vec<Signed>, // data, leaf, root: actual signed public graph
    payload: Vec<u8>,
}
impl Graph {
    fn new(pack: &Pack, kind: Kind) -> Self {
        let mut payload = pack.payload.clone();
        if matches!(kind, Kind::BadGit) {
            // Keep the descriptor/PACK SHA inconsistent, while re-signing the
            // entire multipart graph and its actual final payload hash.
            *payload.last_mut().unwrap() ^= 1;
        }
        let data = signed(MultipartRecord::Data(DataPart {
            index: 0,
            payload: payload.clone(),
        }));
        let mut reference = data.record.reference();
        if matches!(kind, Kind::BadReference) {
            reference.record_hash[0] ^= 1;
        }
        let leaf = signed(MultipartRecord::Leaf(LeafManifest {
            index: 0,
            entries: vec![reference],
        }));
        let root = signed(MultipartRecord::Root(RootManifest {
            length: payload.len() as u64,
            payload_hash: Sha256::digest(&payload).into(),
            profile: pack.descriptor.profile(),
            entries: vec![leaf.record.reference()],
        }));
        Self {
            records: vec![data, leaf, root],
            payload,
        }
    }
    fn root(&self) -> Txid {
        self.records[2].record.txid()
    }
    fn data(&self) -> Txid {
        self.records[0].record.txid()
    }
    fn transactions(&self, kind: Kind) -> Vec<Transaction> {
        self.records
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 0 || !matches!(kind, Kind::MissingData))
            .flat_map(|(_, record)| [record.commit.clone(), record.reveal.clone()])
            .collect()
    }
    fn canonical(&self) -> BTreeMap<String, Vec<u8>> {
        self.records
            .iter()
            .flat_map(|r| [&r.reveal, &r.commit])
            .map(|tx| (format!("{}.bin", tx.compute_txid()), serialize(tx)))
            .collect()
    }
}

struct Source {
    block: Block,
    calls: Arc<AtomicUsize>,
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Chain::BitcoinRegtest.genesis().unwrap().0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(point(FIRST_HEIGHT, &self.block))
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if height == FIRST_HEIGHT {
            Ok(self.block.header)
        } else {
            Err(Error::Invalid("outside owned fixture".into()))
        }
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if height == FIRST_HEIGHT {
            Ok(serialize(&self.block))
        } else {
            Err(Error::Invalid("outside owned fixture".into()))
        }
    }
}
struct Fixture {
    engine: Arc<Engine>,
    directory: PathBuf,
    graph: Graph,
    calls: Arc<AtomicUsize>,
    baseline: Value,
    disk: BTreeMap<String, Vec<u8>>,
    source_calls: usize,
}
impl Fixture {
    fn new(control: &Path, pack: &Pack, kind: Kind) -> Self {
        let graph = Graph::new(pack, kind);
        let block = witness_block(&graph.transactions(kind), None, 901);
        let config = ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: point(FIRST_HEIGHT, &block),
            retention: Retention::Unpruned,
        };
        let directory = control.join("archive");
        let calls = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(Source {
            block,
            calls: Arc::clone(&calls),
        });
        let engine = Engine::open(&directory, config.clone(), Some(source)).unwrap();
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.unresolved_dependencies, 0);
        assert_eq!(status.indexed_through, Some(config.application_start));
        for (index, signed) in graph.records.iter().enumerate() {
            let record = engine.record(signed.record.txid()).unwrap();
            if index == 0 && matches!(kind, Kind::MissingData) {
                assert!(record.is_none());
            } else {
                let record = record.unwrap();
                assert_eq!(record.package.reveal.transaction, serialize(&signed.reveal));
                assert_eq!(record.package.commit, serialize(&signed.commit));
            }
        }
        let scratch = control.join("seed-recovery");
        fs::create_dir(&scratch).unwrap();
        let mut limits = RecoveryLimits::new(1024 * 1024, 3);
        limits.timeout = Duration::from_secs(5);
        limits.attempts = 1;
        let reconstructed = retrieval::recover(&engine, graph.root(), &[], limits, &scratch);
        if matches!(kind, Kind::Valid | Kind::BadGit) {
            let mut reconstructed = reconstructed.unwrap();
            let mut bytes = Vec::new();
            reconstructed.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, graph.payload);
            let payload = scratch.join("git-precondition.bin");
            fs::write(&payload, &bytes).unwrap();
            let validation = tempfile::tempdir_in(&scratch).unwrap();
            let verified = snapshot::validate(&payload, validation.path(), &Limits::default());
            if matches!(kind, Kind::Valid) {
                assert!(verified.is_ok());
            } else {
                assert!(
                    verified.is_err(),
                    "complete signed content must fail Git PACK validation"
                );
            }
        } else {
            assert!(reconstructed.is_err());
        }
        drop(engine);
        // Actual Service gets a persisted engine with no source at all.
        let engine = Arc::new(Engine::open(&directory, config, None).unwrap());
        let source_calls = calls.load(Ordering::SeqCst);
        let baseline = Self::view(&engine, &graph);
        let disk = Self::disk(&directory);
        Self {
            engine,
            directory,
            graph,
            calls,
            baseline,
            disk,
            source_calls,
        }
    }
    fn view(engine: &Engine, graph: &Graph) -> Value {
        json!({"status":engine.status().unwrap(),
            "object":engine.object_status(graph.root()).unwrap(),
            "records":graph.records.iter().map(|r| engine.record(r.record.txid()).unwrap()).collect::<Vec<_>>()})
    }
    fn disk(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        // SHM is lock coordination, not durable archive content. No SQL writer
        // or injection connection is opened by these consumer tests.
        ["archive.sqlite3", "archive.sqlite3-wal"]
            .into_iter()
            .filter_map(|name| match fs::read(directory.join(name)) {
                Ok(bytes) => Some((name.to_owned(), bytes)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => panic!("owned archive snapshot: {e}"),
            })
            .collect()
    }
    fn unchanged(&self) {
        assert_eq!(Self::view(&self.engine, &self.graph), self.baseline);
        assert_eq!(Self::disk(&self.directory), self.disk);
        assert_eq!(self.calls.load(Ordering::SeqCst), self.source_calls);
    }
}

#[derive(Default)]
struct Pause {
    target: Option<String>,
    reached: bool,
    released: bool,
}
struct Proxy {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    pause: Arc<(Mutex<Pause>, Condvar)>,
    requests: Arc<Mutex<Vec<(String, u16)>>>,
    worker: Option<JoinHandle<()>>,
}
impl Proxy {
    fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let pause = Arc::new((Mutex::new(Pause::default()), Condvar::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (thread_stop, thread_pause, thread_requests) =
            (Arc::clone(&stop), Arc::clone(&pause), Arc::clone(&requests));
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, peer)) => {
                        assert!(peer.ip().is_loopback());
                        stream
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("owned proxy accept: {e}"),
                };
                stream.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(HTTP_TIMEOUT)).unwrap();
                let mut raw = Vec::new();
                while !raw.ends_with(b"\r\n\r\n") {
                    assert!(raw.len() < 16 * 1024);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    raw.push(byte[0]);
                }
                let raw = String::from_utf8(raw).unwrap();
                let first = raw
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                assert_eq!(first[0], "GET");
                let path = first[1].to_owned();
                assert!(path.starts_with("/v1/records/"));
                let response = http(upstream, &raw).unwrap();
                thread_requests
                    .lock()
                    .unwrap()
                    .push((path.clone(), response.code));
                let (lock, wake) = &*thread_pause;
                let mut paused = lock.lock().unwrap();
                if paused.target.as_deref() == Some(&path) {
                    paused.reached = true;
                    wake.notify_all();
                    let deadline = Instant::now() + PAUSE_TIMEOUT;
                    while !paused.released && !thread_stop.load(Ordering::SeqCst) {
                        let remaining = deadline
                            .checked_duration_since(Instant::now())
                            .expect("owned final-child pause release exceeded bound");
                        paused = wake.wait_timeout(paused, remaining).unwrap().0;
                    }
                    paused.target = None;
                }
                drop(paused);
                // The actual Service's complete HTTP bytes are forwarded
                // unchanged, including its genuine proof/package or 404.
                stream.write_all(&response.wire).unwrap();
            }
        });
        Self {
            address,
            stop,
            pause,
            requests,
            worker: Some(worker),
        }
    }
    fn arm(&self, txid: Txid) {
        *self.pause.0.lock().unwrap() = Pause {
            target: Some(format!("/v1/records/{txid}")),
            reached: false,
            released: false,
        };
    }
    fn wait_paused(&self) {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        let mut paused = self.pause.0.lock().unwrap();
        while !paused.reached {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("CLI never reached actual final child");
            paused = self.pause.1.wait_timeout(paused, remaining).unwrap().0;
            if self.worker.as_ref().unwrap().is_finished() {
                panic!("proxy ended before pause");
            }
        }
    }
    fn release(&self) {
        self.pause.0.lock().unwrap().released = true;
        self.pause.1.notify_all();
    }
    fn log(&self) -> Vec<(String, u16)> {
        self.requests.lock().unwrap().clone()
    }
    fn cleanup(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        self.release();
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("owned proxy join exceeded bound".into());
        }
        worker.join().map_err(|_| "owned proxy panicked".into())
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("{e}");
        }
    }
}

struct RpcGuard {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl RpcGuard {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (thread_stop, thread_calls) = (Arc::clone(&stop), Arc::clone(&calls));
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        assert!(peer.ip().is_loopback());
                        thread_calls.fetch_add(1, Ordering::SeqCst);
                        drop(stream); // No RPC replies or fake Node provider.
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("owned RPC guard: {e}"),
                }
            }
        });
        Self {
            address,
            calls,
            stop,
            worker: Some(worker),
        }
    }
    fn unchanged(&self) {
        assert_eq!(self.calls.load(Ordering::SeqCst), 0);
    }
    fn cleanup(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("owned RPC guard join exceeded bound".into());
        }
        worker
            .join()
            .map_err(|_| "owned RPC guard panicked".into())?;
        self.unchanged();
        Ok(())
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}
impl Drop for RpcGuard {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("{e}");
        }
    }
}

struct Cli {
    directory: PathBuf,
    destination: PathBuf,
    owned: OwnedChild,
}
struct Receipt {
    exit: ExitStatus,
    stdout: String,
    stderr: String,
}
impl Cli {
    fn spawn(
        control: &Path,
        name: &str,
        endpoint: SocketAddr,
        rpc: SocketAddr,
        root: Txid,
        verb: &str,
        verify: Option<&Path>,
    ) -> Self {
        let directory = control.join(name);
        fs::create_dir(&directory).unwrap();
        for name in ["home", "state", "data"] {
            fs::create_dir(directory.join(name)).unwrap();
        }
        let token = directory.join("token");
        fs::write(&token, TOKEN).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let config = directory.join("config.json");
        // Explicit local RPC with no cookie must refuse before I/O. Leaving
        // both options unset would select public P2P, forbidden in this test.
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "archive":{"endpoint":endpoint,"token_file":token},
                "rpc_url":format!("http://{rpc}/")
            }))
            .unwrap(),
        )
        .unwrap();
        let destination = directory.join("destination");
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("HOME", directory.join("home"))
            .env("TMPDIR", &directory)
            .env("XDG_STATE_HOME", directory.join("state"))
            .env("XDG_DATA_HOME", directory.join("data"))
            .env("URMA_CONFIG", config)
            .env("URMA_NETWORK", "bitcoin-regtest")
            .env("URMA_LOG_OUTPUT", "stderr")
            .env("URMA_OUTPUT", "json")
            .env("URMA_GIT_SCAN_WORKERS", "1")
            .current_dir(&directory)
            .args(["git", verb]);
        if let Some(snapshot) = verify {
            command.arg("--snapshot").arg(snapshot);
        } else {
            command.arg(root.to_string());
            if verb == "recover" {
                command.arg("--output");
            }
            command.arg(&destination);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(File::create(directory.join("stdout")).unwrap())
            .stderr(File::create(directory.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        Self {
            directory,
            destination,
            owned: OwnedChild {
                child: Some(child),
                group: false,
            },
        }
    }
    fn finish(&mut self) -> Receipt {
        let exit = wait_child(&mut self.owned, &self.directory.join("stderr"));
        Receipt {
            exit,
            stdout: bounded_text(&self.directory.join("stdout")),
            stderr: bounded_text(&self.directory.join("stderr")),
        }
    }
    fn stages(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".urma-archive-")
            })
            .collect()
    }
    fn private_before_final_child(&self, graph: &Graph) {
        assert!(self.owned.child.as_ref().is_some());
        assert!(
            !self.destination.try_exists().unwrap(),
            "destination published before acquisition finished"
        );
        assert!(bounded_text(&self.directory.join("stdout")).is_empty());
        let stages = self.stages();
        assert_eq!(stages.len(), 1);
        let staged = &stages[0];
        assert_eq!(
            fs::metadata(staged).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for record in &graph.records[1..] {
            assert_eq!(
                fs::read(
                    staged
                        .join("tx")
                        .join(format!("{}.bin", record.record.txid()))
                )
                .unwrap(),
                serialize(&record.reveal)
            );
        }
        assert!(
            !staged
                .join("tx")
                .join(format!("{}.bin", graph.data()))
                .try_exists()
                .unwrap()
        );
    }
}

fn files(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(directory)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            assert!(e.file_type().unwrap().is_file());
            (
                e.file_name().into_string().unwrap(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}
fn verify_receipt(receipt: &Receipt, fixture: &Fixture, pack: &Pack) -> Value {
    assert!(receipt.exit.success(), "{}", receipt.stderr);
    let report: Value = serde_json::from_str(&receipt.stdout).unwrap();
    assert_eq!(report["content"], "complete");
    assert_eq!(report["author_proof"], "verified");
    assert_eq!(report["git_profile"], "verified");
    assert_eq!(report["chain_inclusion"], "not_checked");
    assert_eq!(
        report["author"],
        hex::encode(fixture.graph.records[2].record.author().serialize())
    );
    assert_eq!(report["locator"]["root"], fixture.graph.root().to_string());
    assert_eq!(report["locator"]["chain"], "bitcoin-regtest");
    assert_eq!(
        report["locator"]["genesis"],
        Chain::BitcoinRegtest.genesis().unwrap().0.to_string()
    );
    assert_eq!(
        report["snapshot"]["descriptor"],
        serde_json::to_value(&pack.descriptor).unwrap()
    );
    assert_eq!(
        report["snapshot"]["payload_sha256"],
        hex::encode(Sha256::digest(&pack.payload))
    );
    report
}

fn no_listener(address: SocketAddr) {
    assert!(
        matches!(TcpStream::connect_timeout(&address, HTTP_TIMEOUT),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused),
        "owned listener remained after normal join"
    );
}
fn healthy(control: &Path) {
    stage(control, "G1: native PACK and genuine signatures");
    let pack = Pack::new(control);
    let fixture = Fixture::new(control, &pack, Kind::Valid);
    let session = Session::start(Arc::clone(&fixture.engine));
    let proxy = Proxy::start(session.address);
    let rpc = RpcGuard::start();
    let mut retained = Vec::new();
    for verb in ["recover", "clone"] {
        stage(
            control,
            &format!("G1: actual {verb}, final-child response paused"),
        );
        proxy.arm(fixture.graph.data());
        let before = proxy.log().len();
        let mut cli = Cli::spawn(
            control,
            verb,
            proxy.address,
            rpc.address,
            fixture.graph.root(),
            verb,
            None,
        );
        proxy.wait_paused();
        cli.private_before_final_child(&fixture.graph);
        fixture.unchanged();
        rpc.unchanged();
        proxy.release();
        let receipt = cli.finish();
        assert!(receipt.exit.success(), "{verb}: {}", receipt.stderr);
        assert!(receipt.stderr.contains("chain inclusion not checked"));
        assert!(!receipt.stderr.contains("using autonomous recovery"));
        assert!(cli.stages().is_empty());
        let path = if verb == "recover" {
            verify_receipt(&receipt, &fixture, &pack);
            assert_eq!(
                fs::read(cli.destination.join("snapshot.pack")).unwrap(),
                pack.pack
            );
            let persisted: Value =
                serde_json::from_slice(&fs::read(cli.destination.join("recovery.json")).unwrap())
                    .unwrap();
            assert_eq!(
                persisted,
                serde_json::from_str::<Value>(&receipt.stdout).unwrap()
            );
            cli.destination.clone()
        } else {
            assert!(receipt.stdout.trim().is_empty());
            assert_eq!(
                fs::read(cli.destination.join("README.md")).unwrap(),
                pack.file
            );
            assert_eq!(
                git(&cli.destination, &["rev-parse", "HEAD"], control).trim(),
                hex::encode(&pack.descriptor.head)
            );
            assert_eq!(
                git(&cli.destination, &["symbolic-ref", "HEAD"], control)
                    .trim()
                    .as_bytes(),
                &pack.descriptor.branch
            );
            assert!(
                git(
                    &cli.destination,
                    &["status", "--porcelain=v1", "--untracked-files=all"],
                    control
                )
                .is_empty()
            );
            git(&cli.destination, &["fsck", "--strict"], control);
            cli.destination.join(".git/urma")
        };
        assert_eq!(fs::read(path.join("object.bin")).unwrap(), pack.payload);
        assert_eq!(files(&path.join("tx")), fixture.graph.canonical());
        let locator: Value =
            serde_json::from_slice(&fs::read(path.join("locator.json")).unwrap()).unwrap();
        assert_eq!(locator["root"], fixture.graph.root().to_string());
        assert_eq!(locator["chain"], "bitcoin-regtest");
        assert_eq!(
            locator["genesis"],
            Chain::BitcoinRegtest.genesis().unwrap().0.to_string()
        );
        let log = proxy.log();
        assert_eq!(
            &log[before..],
            &[
                (format!("/v1/records/{}", fixture.graph.root()), 200),
                (
                    format!("/v1/records/{}", fixture.graph.records[1].record.txid()),
                    200
                ),
                (format!("/v1/records/{}", fixture.graph.data()), 200),
            ]
        );
        retained.push(path);
        fixture.unchanged();
        rpc.unchanged();
    }
    let proxy_address = proxy.address;
    let service_address = session.address;
    let request_log = Arc::clone(&proxy.requests);
    let requests_before_verify = proxy.log();
    proxy.finish();
    session.finish(); // Normal authenticated shutdown and thread join required.
    no_listener(proxy_address);
    no_listener(service_address);
    stage(
        control,
        "G1: actual offline CLI verify with archive listeners closed",
    );
    for (index, path) in retained.iter().enumerate() {
        let canonical = files(&path.join("tx"));
        let payload = fs::read(path.join("object.bin")).unwrap();
        let mut cli = Cli::spawn(
            control,
            &format!("verify-{index}"),
            proxy_address,
            rpc.address,
            fixture.graph.root(),
            "verify",
            Some(path),
        );
        let receipt = cli.finish();
        verify_receipt(&receipt, &fixture, &pack);
        assert!(!receipt.stderr.contains("using autonomous recovery"));
        assert_eq!(files(&path.join("tx")), canonical);
        assert_eq!(fs::read(path.join("object.bin")).unwrap(), payload);
    }
    assert_eq!(*request_log.lock().unwrap(), requests_before_verify);
    fixture.unchanged();
    rpc.unchanged();
    rpc.finish();
}

fn refused_attempts(control: &Path, pack: &Pack, kind: Kind) {
    let fixture = Fixture::new(control, pack, kind);
    let session = Session::start(Arc::clone(&fixture.engine));
    let proxy = Proxy::start(session.address);
    let rpc = RpcGuard::start();
    for verb in ["recover", "clone"] {
        stage(
            control,
            &format!("negative: actual {verb}, discard then local config refusal"),
        );
        let before = proxy.log().len();
        let mut cli = Cli::spawn(
            control,
            verb,
            proxy.address,
            rpc.address,
            fixture.graph.root(),
            verb,
            None,
        );
        let receipt = cli.finish();
        assert!(!receipt.exit.success());
        assert!(receipt.stdout.trim().is_empty());
        assert!(
            receipt
                .stderr
                .contains("optional Git archive unavailable; using autonomous recovery"),
            "{}",
            receipt.stderr
        );
        assert!(
            receipt.stderr.contains("needs node_auth_file in config"),
            "{}",
            receipt.stderr
        );
        assert!(!receipt.stderr.contains(TOKEN));
        assert!(!cli.destination.try_exists().unwrap());
        assert!(cli.stages().is_empty());
        assert!(
            fs::read_dir(cli.directory.join("data"))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(fs::read_dir(&cli.directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".urma-clone-")
        }));
        let log = proxy.log();
        let code = if matches!(kind, Kind::MissingData) {
            404
        } else {
            200
        };
        assert_eq!(
            &log[before..],
            &[
                (format!("/v1/records/{}", fixture.graph.root()), 200),
                (
                    format!("/v1/records/{}", fixture.graph.records[1].record.txid()),
                    200
                ),
                (format!("/v1/records/{}", fixture.graph.data()), code),
            ]
        );
        fixture.unchanged();
        rpc.unchanged();
    }
    let (proxy_address, service_address) = (proxy.address, session.address);
    proxy.finish();
    session.finish();
    no_listener(proxy_address);
    no_listener(service_address);
    fixture.unchanged();
    rpc.finish();
}
fn missing_and_bad_reference(control: &Path) {
    stage(
        control,
        "G2: native PACK, actual absent child and authentic wrong-reference graph",
    );
    let pack = Pack::new(control);
    for (name, kind) in [
        ("missing", Kind::MissingData),
        ("bad-reference", Kind::BadReference),
    ] {
        let directory = control.join(name);
        fs::create_dir(&directory).unwrap();
        refused_attempts(&directory, &pack, kind);
    }
}
fn complete_bad_git(control: &Path) {
    stage(
        control,
        "G3: complete authenticated multipart content, invalid native Git PACK",
    );
    let pack = Pack::new(control);
    refused_attempts(control, &pack, Kind::BadGit);
}

#[test]
#[ignore = "owned bounded Linux subprocess host, not a standalone Git archive case"]
fn git_archive_host() {
    let control = PathBuf::from(std::env::var_os("U4_GIT_ARCHIVE_TEMP").expect("owned TEMP"));
    let case = std::env::var("U4_GIT_ARCHIVE_CASE").unwrap();
    match case.as_str() {
        "healthy" => healthy(&control),
        "missing-reference" => missing_and_bad_reference(&control),
        "bad-git" => complete_bad_git(&control),
        _ => panic!("unknown owned case"),
    }
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({"case":case,"passed":true})).unwrap(),
    )
    .unwrap();
}
fn run_host(case: &str) {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "git_archive_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", directory.path())
        .env("TMPDIR", directory.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("URMA_GIT_SCAN_WORKERS", "1")
        .env("U4_GIT_ARCHIVE_TEMP", directory.path())
        .env("U4_GIT_ARCHIVE_CASE", case)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(directory.path().join("stdout")).unwrap())
        .stderr(File::create(directory.path().join("stderr")).unwrap())
        .spawn()
        .unwrap();
    let mut owned = OwnedChild {
        child: Some(child),
        group: true,
    };
    let deadline = Instant::now() + HOST_TIMEOUT;
    let logs = || {
        ["stage", "stdout", "stderr"]
            .map(|name| bounded_text(&directory.path().join(name)))
            .join("\n")
    };
    loop {
        if let Some(exit) = owned.child.as_mut().unwrap().try_wait().unwrap() {
            // Failed host still owns its group; Drop kills/reaps leftovers.
            assert!(
                exit.success(),
                "Git archive host {case}: {exit}; {}",
                logs()
            );
            owned.child.take();
            let report: Value =
                serde_json::from_slice(&fs::read(directory.path().join("result.json")).unwrap())
                    .unwrap();
            assert_eq!(report, json!({"case":case,"passed":true}));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Git archive host {case} exceeded90s; group kill/reap abnormal cleanup only; {}",
            logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn real_archive_recovers_and_clones_signed_git_then_verifies_offline() {
    run_host("healthy");
}
#[test]
fn actual_missing_child_and_signed_bad_reference_discard_before_fallback() {
    run_host("missing-reference");
}
#[test]
fn complete_signed_invalid_git_is_refused_before_publication() {
    run_host("bad-git");
}
