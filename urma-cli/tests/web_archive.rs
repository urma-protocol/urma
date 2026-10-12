//! Actual authenticated Service -> CLI Web recovery, then offline reads.
//! Every Data/Leaf/Root and pin is genuinely signed through pure publication.
//! Mock-selected blocks prove witness integrity, not PoW, scripts or UTXOs.
//! Small fixtures exercise publication boundaries, not acquisition-cap exhaustion.
#![cfg(target_os = "linux")]

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, WPubkeyHash, Witness,
    absolute::LockTime,
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
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::{observation::Chain, validation::validate_block_integrity};
use urma_core::multipart::{
    DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest, VerifiedRecord,
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    service::Service,
    source::ChainSource,
};
use urma_runtime::publication::prepare_multipart;
use urma_wallet::funding::Funding;
use urma_web::{
    package::{FileEntry, Package, PinnedEntry},
    store::{Pointer, Store},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NETWORK: &str = "bitcoin-regtest";
const HEIGHT: u64 = 100;
const FALLBACK: &str = "optional Web archive unavailable; using autonomous recovery";
const CLEANUP_TIME: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Signed {
    record: VerifiedRecord,
    commit: Transaction,
    reveal: Transaction,
}

fn signed(record: MultipartRecord, seed: &mut u8) -> Signed {
    *seed = seed.checked_add(1).unwrap();
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([*seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([*seed; 20])),
        }],
    };
    // Public deterministic fixture identity and local synthetic funding only.
    let key = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[23; 32]).unwrap(),
    );
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
    let commit: Transaction = deserialize(&hex::decode(plan.commit).unwrap()).unwrap();
    let reveal: Transaction = deserialize(&hex::decode(plan.reveal).unwrap()).unwrap();
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(verified.decode().unwrap(), record);
    Signed {
        record: verified,
        commit,
        reveal,
    }
}

#[derive(Clone)]
struct Graph {
    records: Vec<Signed>, // actual signed data, leaf, root, in this order
    payload: Vec<u8>,
}

impl Graph {
    fn new(payload: Vec<u8>, profile: [u8; 8], seed: &mut u8) -> Self {
        let mut records: Vec<_> = payload
            .chunks(Geometry::DATA_BYTES)
            .enumerate()
            .map(|(index, bytes)| {
                signed(
                    MultipartRecord::Data(DataPart {
                        index: u32::try_from(index).unwrap(),
                        payload: bytes.to_vec(),
                    }),
                    seed,
                )
            })
            .collect();
        assert!(!records.is_empty());
        let leaf = signed(
            MultipartRecord::Leaf(LeafManifest {
                index: 0,
                entries: records.iter().map(|pair| pair.record.reference()).collect(),
            }),
            seed,
        );
        let root = signed(
            MultipartRecord::Root(RootManifest {
                length: u64::try_from(payload.len()).unwrap(),
                payload_hash: Sha256::digest(&payload).into(),
                profile,
                entries: vec![leaf.record.reference()],
            }),
            seed,
        );
        records.extend([leaf, root]);
        Self { records, payload }
    }
    fn root(&self) -> &Signed {
        self.records.last().unwrap()
    }
    fn id(&self) -> Txid {
        self.root().record.txid()
    }
    fn hash(&self) -> String {
        hex::encode(Sha256::digest(&self.payload))
    }
}

#[derive(Clone, Copy)]
enum Variant {
    Healthy,
    MissingPinPart,
    WrongPinHash,
    InvalidWeb,
}

#[derive(Clone)]
struct Fixture {
    web: Graph,
    pin: Graph,
    package: Package,
}

impl Fixture {
    fn new(variant: Variant) -> Self {
        let mut seed = 0;
        let pin = Graph::new(
            b"public pinned resource\0with exact bytes\n".repeat(71),
            *b"RAWPIN01",
            &mut seed,
        );
        let mut hash: [u8; 32] = Sha256::digest(&pin.payload).into();
        if matches!(variant, Variant::WrongPinHash) {
            hash[0] ^= 1;
        }
        let package = Package::build(
            "owned-web",
            "index.html",
            vec![
                FileEntry::new(
                    "index.html",
                    "text/html",
                    b"<!doctype html><p>owned public Web fixture</p>\n".to_vec(),
                ),
                FileEntry::new(
                    "asset.bin",
                    "application/octet-stream",
                    (0..270_001).map(|i| (i % 251) as u8).collect(),
                ),
            ],
            vec![PinnedEntry {
                path: "dl/pin.bin".into(),
                mime: "application/octet-stream".into(),
                root_txid: pin.id(),
                payload_sha256: hash,
            }],
        )
        .unwrap();
        let mut payload = package.encode().unwrap();
        if matches!(variant, Variant::InvalidWeb) {
            payload[0] ^= 0xff;
            assert!(Package::decode(&payload).is_err());
        }
        let web = Graph::new(payload, Package::PROFILE, &mut seed);
        assert_eq!(web.records.len(), 4, "two actual data parts plus leaf/root");
        assert_eq!(pin.records.len(), 3, "one actual data part plus leaf/root");
        Self { web, pin, package }
    }
    fn pairs(&self) -> impl Iterator<Item = &Signed> {
        self.web.records.iter().chain(&self.pin.records)
    }

    // Seed a genuine readable previous publication through public Store APIs.
    // Its explicit synthetic legacy observation differs from the new operator
    // metadata, so a premature pointer replacement cannot pass byte comparison.
    fn seed_previous(&self, directory: &Path) {
        let store = Store::open(directory).unwrap();
        for bytes in self
            .package
            .files
            .iter()
            .map(|file| file.bytes.as_slice())
            .chain([self.web.payload.as_slice(), self.pin.payload.as_slice()])
        {
            store.put_object_immutable(bytes).unwrap();
        }
        for transaction in [&self.web.root().commit, &self.web.root().reveal] {
            store.put_transaction(transaction).unwrap();
        }
        store
            .put_pointer(&Pointer {
                format: Store::FORMAT.into(),
                network: NETWORK.into(),
                root: self.web.id().to_string(),
                commit: self.web.root().commit.compute_txid().to_string(),
                source: None,
                tip_height: Some(7),
                tip_hash: Some("33".repeat(32)),
            })
            .unwrap();
        store
            .publication(NETWORK, &self.web.id().to_string(), 2 * 1024 * 1024)
            .unwrap();
    }
}

fn point(block: &Block) -> ChainPoint {
    ChainPoint {
        height: HEIGHT,
        hash: block.block_hash(),
    }
}

fn witness_block(transactions: &[Transaction]) -> Block {
    let mut block = genesis_block(Network::Regtest);
    block.header.nonce = 927;
    block.header.bits = CompactTarget::from_consensus(0);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    block.txdata.extend_from_slice(transactions);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

struct Source {
    block: Block,
    calls: AtomicUsize,
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Chain::BitcoinRegtest.genesis().unwrap().0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(point(&self.block))
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if height == HEIGHT {
            Ok(self.block.header)
        } else {
            Err(Error::Invalid("outside owned block".into()))
        }
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if height == HEIGHT {
            Ok(serialize(&self.block))
        } else {
            Err(Error::Invalid("outside owned block".into()))
        }
    }
}

struct Archive {
    engine: Arc<Engine>,
    source: Arc<Source>,
    config: ArchiveConfig,
    directory: PathBuf,
    status: Value,
    calls: usize,
}
impl Archive {
    fn new(control: &Path, fixture: &Fixture, variant: Variant) -> Self {
        let missing = matches!(variant, Variant::MissingPinPart)
            .then(|| fixture.pin.records[0].record.txid());
        let transactions: Vec<_> = fixture
            .pairs()
            .filter(|pair| Some(pair.record.txid()) != missing)
            .flat_map(|pair| [pair.commit.clone(), pair.reveal.clone()])
            .collect();
        let block = witness_block(&transactions);
        let config = ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: point(&block),
            retention: Retention::Unpruned,
        };
        let source = Arc::new(Source {
            block,
            calls: AtomicUsize::new(0),
        });
        let directory = control.join("archive");
        let engine =
            Arc::new(Engine::open(&directory, config.clone(), Some(source.clone())).unwrap());
        engine.synchronize_headers().unwrap();
        let status = engine.scan_next().unwrap();
        assert_eq!(status.scanned_blocks, 1);
        assert_eq!(status.unresolved_dependencies, 0);
        for pair in fixture.pairs() {
            let archived = engine.record(pair.record.txid()).unwrap();
            if Some(pair.record.txid()) == missing {
                assert!(archived.is_none());
            } else {
                let archived = archived.unwrap();
                assert_eq!(archived.package.commit, serialize(&pair.commit));
                assert_eq!(archived.package.reveal.transaction, serialize(&pair.reveal));
            }
        }
        let status = serde_json::to_value(engine.status().unwrap()).unwrap();
        let calls = source.calls.load(Ordering::SeqCst);
        Self {
            engine,
            source,
            config,
            directory,
            status,
            calls,
        }
    }
    fn unchanged(&self) {
        assert_eq!(
            serde_json::to_value(self.engine.status().unwrap()).unwrap(),
            self.status
        );
        assert_eq!(
            self.source.calls.load(Ordering::SeqCst),
            self.calls,
            "archive reads started source acquisition"
        );
    }
    fn finish(self) {
        self.unchanged();
        drop(self.engine);
        let reopened = Engine::open(&self.directory, self.config, None).unwrap();
        assert_eq!(
            serde_json::to_value(reopened.status().unwrap()).unwrap(),
            self.status
        );
    }
}

// One small harness HTTP operation, only authenticated shutdown, with an
// absolute deadline spanning connect/write/read and bounded framing.
fn shutdown(address: SocketAddr) -> io::Result<(u16, Value)> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + Duration::from_secs(2);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    let request = format!(
        "POST /v1/shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut pending = request.as_bytes();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let count = stream.write(pending)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[count..];
    }
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == 8192 {
            return Err(io::Error::other("harness header bound"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(io::Error::other)?;
    let code = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| io::Error::other("harness status"))?
        .parse()
        .map_err(io::Error::other)?;
    let lengths: Vec<_> = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() != 1 {
        return Err(io::Error::other("harness response length"));
    }
    let length: usize = lengths[0].1.trim().parse().map_err(io::Error::other)?;
    if length > 4096 {
        return Err(io::Error::other("harness body bound"));
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
    Ok((
        code,
        serde_json::from_slice(&body).map_err(io::Error::other)?,
    ))
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
        let response = shutdown(self.address);
        let deadline = Instant::now() + CLEANUP_TIME;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service join deadline; outer host cleanup required".into());
        }
        worker
            .join()
            .map_err(|_| "Service panic".to_owned())?
            .map_err(|e| e.to_string())?;
        match response {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            other => Err(format!(
                "authenticated shutdown not acknowledged: {other:?}"
            )),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Service cleanup: {error}");
        }
    }
}

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
struct OwnedChild {
    child: Option<Child>,
    group: Option<i32>,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Only the process_group(0) explicitly owned by this host is signalled.
        // It also contains any CLI descendants left by abnormal host exit.
        if let Some(group) = self.group.take() {
            unsafe {
                kill(-group, 9);
            }
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let deadline = Instant::now() + CLEANUP_TIME;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    other => {
                        eprintln!("owned child cleanup/reap failed: {other:?}");
                        break;
                    }
                }
            }
        }
    }
}
fn bounded_text(path: &Path) -> String {
    let file = File::open(path).unwrap();
    assert!(
        file.metadata().unwrap().len() <= 1024 * 1024,
        "harness log bound"
    );
    let mut text = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .unwrap();
    text
}
fn wait(owned: &mut OwnedChild, timeout: Duration, diagnostics: &Path) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(exit) = owned.child.as_mut().unwrap().try_wait().unwrap() {
            owned.child.take();
            return exit;
        }
        assert!(
            Instant::now() < deadline,
            "owned child deadline: {}",
            bounded_text(diagnostics)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

struct Lab {
    control: PathBuf,
    store: PathBuf,
    rpc: TcpListener,
}
struct CliResult {
    exit: ExitStatus,
    stdout: String,
    stderr: String,
}
impl CliResult {
    fn success(&self) -> Value {
        assert!(
            self.exit.success(),
            "CLI failed: {}; {}",
            self.exit,
            self.stderr
        );
        serde_json::from_str(&self.stdout).unwrap()
    }
    fn failure(&self, fallback: bool) {
        assert!(
            !self.exit.success(),
            "unexpected CLI success: {}",
            self.stdout
        );
        assert!(
            self.stdout.is_empty(),
            "failed attempt published success output"
        );
        assert_eq!(self.stderr.contains(FALLBACK), fallback, "{}", self.stderr);
        if fallback {
            assert!(
                self.stderr.contains("No such file or directory"),
                "missing-cookie fallback refusal: {}",
                self.stderr
            );
        }
    }
}
impl Lab {
    fn new(control: &Path, endpoint: SocketAddr) -> Self {
        for directory in [
            control.to_path_buf(),
            control.join("home"),
            control.join("tmp"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let token = control.join("token");
        fs::write(&token, TOKEN).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            control.join("config.json"),
            serde_json::to_vec(&json!({"archive":{
            "endpoint":endpoint,"token_file":token}}))
            .unwrap(),
        )
        .unwrap();
        let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
        rpc.set_nonblocking(true).unwrap();
        let store = control.join("live-store");
        Self {
            control: control.to_owned(),
            store,
            rpc,
        }
    }
    fn invoke(&self, operation: &str, root: Txid, extra: &[&str]) -> CliResult {
        let out = self.control.join("cli-stdout");
        let err = self.control.join("cli-stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_urma"))
            .env_clear()
            .current_dir(&self.control)
            .env("HOME", self.control.join("home"))
            .env("TMPDIR", self.control.join("tmp"))
            .env("URMA_CONFIG", self.control.join("config.json"))
            .env("URMA_NETWORK", NETWORK)
            .env("URMA_OUTPUT", "json")
            .env("URMA_LOG_OUTPUT", "stderr")
            .env(
                "URMA_RPC_URL",
                format!("http://{}/", self.rpc.local_addr().unwrap()),
            )
            .env("URMA_NODE_AUTH_FILE", self.control.join("missing-cookie"))
            .args(["web", operation, "--root"])
            .arg(root.to_string())
            .arg("--store")
            .arg(&self.store)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(File::create(&out).unwrap())
            .stderr(File::create(&err).unwrap())
            .spawn()
            .unwrap();
        let mut owned = OwnedChild {
            child: Some(child),
            group: None,
        };
        let exit = wait(&mut owned, Duration::from_secs(45), &err);
        let stdout = bounded_text(&out);
        let stderr = bounded_text(&err);
        assert!(
            !stdout.contains(TOKEN) && !stderr.contains(TOKEN),
            "fixture bearer leaked"
        );
        assert!(!self.control.join("missing-cookie").exists());
        assert!(
            matches!(self.rpc.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "unexpected RPC connection"
        );
        assert!(
            !fs::read_dir(self.control.join("tmp"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".urma-archive-")),
            "private attempt leaked staging"
        );
        CliResult {
            exit,
            stdout,
            stderr,
        }
    }
}

fn files(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, entries: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                walk(root, &path, entries);
            } else {
                assert!(kind.is_file());
                entries.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut entries = BTreeMap::new();
    walk(directory, directory, &mut entries);
    entries
}
fn pointer_path(root: Txid) -> PathBuf {
    PathBuf::from("publications")
        .join(NETWORK)
        .join(format!("{root}.json"))
}
fn metadata(value: &Value, fixture: &Fixture) {
    assert_eq!(value["format"], "URMA-WEB-STORE-3");
    assert_eq!(value["source"], json!({"kind":"local-node-operator"}));
    for field in [
        "tip_height",
        "tip_hash",
        "chain_inclusion",
        "confirmed_at_observation",
    ] {
        assert!(value.get(field).is_none(), "invented {field}");
    }
    assert_eq!(value["network"], NETWORK);
    assert_eq!(value["root"], fixture.web.id().to_string());
    assert_eq!(
        value["commit"],
        fixture.web.root().commit.compute_txid().to_string()
    );
    assert_eq!(
        value["author"],
        fixture.web.root().record.author().to_string()
    );
    assert_eq!(value["payload_sha256"], fixture.web.hash());
    assert_eq!(value["payload_length"], fixture.web.payload.len());
    assert_eq!(value["label"], fixture.package.label);
    assert_eq!(value["entry"], "index.html");
    let expected_files: Vec<_> = fixture.package.files.iter().map(|file| json!({
        "path":file.path,"mime":file.mime,"sha256":hex::encode(file.sha256),"length":file.bytes.len(),
    })).collect();
    assert_eq!(value["files"], json!(expected_files));
    assert_eq!(
        value["pinned"],
        json!([{
            "path":"dl/pin.bin","mime":"application/octet-stream",
            "root_txid":fixture.pin.id().to_string(),"sha256":fixture.pin.hash(),"length":fixture.pin.payload.len(),
        }])
    );
}

fn healthy(control: &Path) {
    let fixture = Fixture::new(Variant::Healthy);
    let archive = Archive::new(control, &fixture, Variant::Healthy);
    let session = Session::start(archive.engine.clone());
    let lab = Lab::new(control, session.address);
    assert!(
        !lab.store.exists(),
        "healthy fetch starts with no live cache"
    );
    let fetched = lab.invoke("fetch", fixture.web.id(), &[]);
    let fetched = fetched.success();
    assert_eq!(fetched["status"], "stored");
    metadata(&fetched["publication"], &fixture);
    let pointer: Value =
        serde_json::from_slice(&fs::read(lab.store.join(pointer_path(fixture.web.id()))).unwrap())
            .unwrap();
    assert_eq!(pointer["format"], "URMA-WEB-STORE-3");
    assert_eq!(pointer["source"], json!({"kind":"local-node-operator"}));
    assert!(pointer.get("tip_height").is_none() && pointer.get("tip_hash").is_none());
    for bytes in fixture
        .package
        .files
        .iter()
        .map(|file| &file.bytes)
        .chain([&fixture.web.payload, &fixture.pin.payload])
    {
        assert_eq!(
            fs::read(
                lab.store
                    .join("objects")
                    .join(hex::encode(Sha256::digest(bytes)))
            )
            .unwrap(),
            *bytes
        );
    }
    for transaction in [&fixture.web.root().commit, &fixture.web.root().reveal] {
        assert_eq!(
            fs::read(
                lab.store
                    .join("tx")
                    .join(format!("{}.bin", transaction.compute_txid()))
            )
            .unwrap(),
            serialize(transaction)
        );
    }
    archive.unchanged();
    session.finish();
    let before = files(&lab.store);
    let manifest = lab
        .invoke("manifest", fixture.web.id(), &["--network", NETWORK])
        .success();
    metadata(&manifest, &fixture);
    assert_eq!(manifest, fetched["publication"]);
    for (path, bytes, mime, name) in [
        (
            "/",
            &fixture
                .package
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .unwrap()
                .bytes,
            "text/html",
            "html-out",
        ),
        (
            "/dl/pin.bin",
            &fixture.pin.payload,
            "application/octet-stream",
            "pin-out",
        ),
    ] {
        let output = control.join(name);
        let served = lab
            .invoke(
                "get",
                fixture.web.id(),
                &[
                    "--network",
                    NETWORK,
                    "--path",
                    path,
                    "--output",
                    output.to_str().unwrap(),
                ],
            )
            .success();
        assert_eq!(served["status"], "served");
        assert_eq!(served["mime"], mime);
        assert_eq!(served["sha256"], hex::encode(Sha256::digest(bytes)));
        assert_eq!(served["length"], bytes.len());
        assert_eq!(fs::read(output).unwrap(), *bytes);
    }
    assert_eq!(files(&lab.store), before, "offline reads mutated store");
    archive.finish();
}

fn discarded(control: &Path) {
    for (name, variant) in [
        ("missing-pin-part", Variant::MissingPinPart),
        ("wrong-pin-hash", Variant::WrongPinHash),
        ("invalid-web", Variant::InvalidWeb),
    ] {
        let case = control.join(name);
        fs::create_dir(&case).unwrap();
        let previous = Fixture::new(Variant::Healthy);
        let fixture = if matches!(variant, Variant::MissingPinPart) {
            previous.clone()
        } else {
            Fixture::new(variant)
        };
        let archive = Archive::new(&case, &fixture, variant);
        let session = Session::start(archive.engine.clone());
        let lab = Lab::new(&case, session.address);
        previous.seed_previous(&lab.store);
        // This cache really contains the missing pin's correct bytes. The
        // private reader must nevertheless acquire its complete signed graph.
        assert_eq!(
            fs::read(lab.store.join("objects").join(previous.pin.hash())).unwrap(),
            previous.pin.payload
        );
        let before = files(&lab.store);
        lab.invoke("fetch", fixture.web.id(), &[]).failure(true);
        assert_eq!(
            files(&lab.store),
            before,
            "failed private attempt wrote live members or pointer"
        );
        session.finish();
        archive.finish();
    }
}

fn conflicts(control: &Path) {
    for kind in ["object", "transaction"] {
        let case = control.join(kind);
        fs::create_dir(&case).unwrap();
        let fixture = Fixture::new(Variant::Healthy);
        let archive = Archive::new(&case, &fixture, Variant::Healthy);
        let session = Session::start(archive.engine.clone());
        let lab = Lab::new(&case, session.address);
        fixture.seed_previous(&lab.store);
        let poisoned = if kind == "object" {
            let file = fixture
                .package
                .files
                .iter()
                .find(|file| file.path == "asset.bin")
                .unwrap();
            let path = lab.store.join("objects").join(hex::encode(file.sha256));
            let mut bytes = file.bytes.clone();
            bytes[0] ^= 1;
            fs::write(&path, bytes).unwrap();
            path
        } else {
            let mut reveal = fixture.web.root().reveal.clone();
            let mut witness = reveal.input[0].witness.to_vec();
            witness[0][0] ^= 1;
            reveal.input[0].witness = Witness::from_slice(&witness);
            assert_eq!(
                reveal.compute_txid(),
                fixture.web.id(),
                "only witness changed"
            );
            let path = lab
                .store
                .join("tx")
                .join(format!("{}.bin", fixture.web.id()));
            fs::write(&path, serialize(&reveal)).unwrap();
            path
        };
        let poisoned_bytes = fs::read(&poisoned).unwrap();
        let before = files(&lab.store);
        let receipt = lab.invoke("fetch", fixture.web.id(), &[]);
        receipt.failure(false);
        assert!(
            receipt.stderr.contains("disagrees"),
            "final immutable failure not reached: {}",
            receipt.stderr
        );
        assert_eq!(
            fs::read(poisoned).unwrap(),
            poisoned_bytes,
            "conflict was overwritten"
        );
        let after = files(&lab.store);
        for (path, bytes) in &before {
            assert_eq!(
                after.get(path),
                Some(bytes),
                "existing cache/pointer changed: {path:?}"
            );
        }
        assert_eq!(
            after.get(&pointer_path(fixture.web.id())),
            before.get(&pointer_path(fixture.web.id()))
        );
        // Publication may leave immutable siblings on failure; this case does
        // not demand rollback or an orphan-free cache.
        session.finish();
        archive.finish();
    }
}

#[test]
#[ignore = "owned bounded subprocess host for actual Service and CLI"]
fn web_archive_host() {
    let control = PathBuf::from(std::env::var_os("U2_WEB_ARCHIVE_TEMP").expect("owned host TEMP"));
    let case = std::env::var("U2_WEB_ARCHIVE_CASE").expect("owned host case");
    match case.as_str() {
        "healthy" => healthy(&control),
        "discarded" => discarded(&control),
        "conflicts" => conflicts(&control),
        _ => panic!("unknown owned case"),
    }
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({"case":case,"normal_service_joins":true})).unwrap(),
    )
    .unwrap();
}

fn run_host(case: &str) {
    let lab = tempfile::tempdir().unwrap();
    let out = lab.path().join("host-stdout");
    let err = lab.path().join("host-stderr");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "web_archive_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U2_WEB_ARCHIVE_TEMP", lab.path())
        .env("U2_WEB_ARCHIVE_CASE", case)
        .env("TMPDIR", lab.path())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(File::create(&out).unwrap())
        .stderr(File::create(&err).unwrap())
        .spawn()
        .unwrap();
    let group = i32::try_from(child.id()).unwrap();
    let mut owned = OwnedChild {
        child: Some(child),
        group: Some(group),
    };
    let exit = wait(&mut owned, Duration::from_secs(90), &err);
    assert!(
        exit.success(),
        "owned host failed: {exit}; {}\n{}",
        bounded_text(&out),
        bounded_text(&err)
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(lab.path().join("result.json")).unwrap()).unwrap();
    assert_eq!(receipt, json!({"case":case,"normal_service_joins":true}));
}

#[test]
fn real_service_web_fetch_then_offline_manifest_and_pin_get() {
    run_host("healthy");
}
#[test]
fn private_missing_pin_hash_mismatch_and_invalid_web_discard_before_fallback() {
    run_host("discarded");
}
#[test]
fn live_immutable_object_and_transaction_conflicts_refuse_without_fallback_or_pointer_change() {
    run_host("conflicts");
}
