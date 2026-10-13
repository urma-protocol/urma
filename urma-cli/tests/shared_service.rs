//! V6: one actual URMA Node Service feeds two consumers of common data, the
//! CLI Wire reader and the Names gateway. Neither consumer scans or steps; both
//! label the operator source; when the Service stops each falls back to its
//! own local data with an autonomous label and the archive is left unchanged.
//! Public signed records inhabit witness-integrity-valid mock-selected
//! BitcoinTestnet4 blocks: no PoW, script, UTXO or consensus claim.
#![cfg(all(unix, not(target_arch = "wasm32")))]
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, absolute,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::serialize,
    hashes::{Hash, sha256},
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::{observation::Chain, validation::validate_block_integrity};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{
    engine::Registry,
    index::{Checkpoint, NamesIndex},
    name::Name,
    payload::{Approval, Genesis, Payload},
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    service::Service,
    source::ChainSource,
};
use urma_wire::index::{Entry, Index, entry_from_record};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NETWORK: &str = "bitcoin-testnet4";
const FIRST_HEIGHT: u64 = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATOR: &str = "local-node-operator";
const AUTONOMOUS: &str = "autonomous-local";

fn point(height: u64, block: &Block) -> ChainPoint {
    ChainPoint {
        height,
        hash: block.block_hash(),
    }
}

struct Signed {
    commit: Transaction,
    reveal: Transaction,
    bytes: Vec<u8>,
}
impl Signed {
    fn id(&self) -> Txid {
        self.reveal.compute_txid()
    }
    fn transactions(&self) -> Vec<Transaction> {
        vec![self.commit.clone(), self.reveal.clone()]
    }
}

fn author_of(secret: [u8; 32]) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &secret).unwrap()
}

fn commit_for(info_key: bitcoin::key::TweakedPublicKey, tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([tag; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(3000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info_key),
            },
        ],
    }
}

fn signed_record(bytes: &[u8], secret: [u8; 32], tag: u8) -> Signed {
    let secp = Secp256k1::new();
    let signer = author_of(secret);
    let author = signer.x_only_public_key().0;
    let mut builder = Builder::new()
        .push_x_only_key(&author)
        .push_opcode(OP_CHECKSIG)
        .push_int(0)
        .push_opcode(OP_IF)
        .push_slice(Urma::MAGIC);
    for chunk in bytes.chunks(520) {
        builder = match chunk {
            [value @ 1..=16] => builder.push_int(i64::from(*value)),
            [0x81] => builder.push_int(-1),
            bytes => builder.push_slice(PushBytesBuf::try_from(bytes.to_vec()).unwrap()),
        };
    }
    let script = builder.push_opcode(OP_ENDIF).into_script();
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, author)
        .unwrap();
    let commit = commit_for(info.output_key(), tag);
    let mut reveal = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit.compute_txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1500),
            script_pubkey: ScriptBuf::from_bytes([vec![0, 20], vec![4; 20]].concat()),
        }],
    };
    let hash = SighashCache::new(&reveal)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&commit.output[1])),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &signer);
    reveal.input[0].witness = envelope::witness(signature.as_ref(), &script, &info).unwrap();
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
    assert_eq!(verified.record_bytes(), bytes);
    Signed {
        commit,
        reveal,
        bytes: bytes.to_vec(),
    }
}

fn witness_block(transactions: &[Transaction], previous: Option<&Block>, nonce: u32) -> Block {
    let mut block = genesis_block(Network::Testnet4);
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
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

/// Counts every chain-source call: a consumer that triggered a scan, header
/// sync or dependency fetch through the Service would move this counter.
struct Source {
    branch: Mutex<Vec<Block>>,
    calls: AtomicUsize,
}
impl Source {
    fn at(&self, height: u64) -> Result<Block, Error> {
        let offset = height
            .checked_sub(FIRST_HEIGHT)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| Error::Invalid("fixture height below start".into()))?;
        self.branch
            .lock()
            .unwrap()
            .get(offset)
            .cloned()
            .ok_or_else(|| Error::Invalid("fixture height unavailable".into()))
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Chain::BitcoinTestnet4.genesis().unwrap().0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let blocks = self.branch.lock().unwrap();
        let last = u64::try_from(blocks.len()).unwrap() - 1;
        Ok(point(FIRST_HEIGHT + last, blocks.last().unwrap()))
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.at(height)?.header)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(serialize(&self.at(height)?))
    }
}

fn names_records(genesis: &Signed, rules: &Genesis) -> (Vec<Signed>, Vec<Signed>) {
    let Payload::Claim(template) = Payload::from_record(
        &PublicRecord::decode(include_bytes!("../../tests/vectors/names/claim.record")).unwrap(),
    )
    .unwrap() else {
        panic!("public Claim")
    };
    let claims: Vec<Signed> = ["alpha", "bravo"]
        .into_iter()
        .zip([11, 12])
        .map(|(name, tag)| {
            let mut claim = template.clone();
            claim.registry = genesis.id();
            claim.name = Name::parse(name).unwrap();
            let bytes = Payload::Claim(claim).to_record().unwrap().encode().unwrap();
            signed_record(&bytes, [5; 32], tag)
        })
        .collect();
    let approval = Payload::Approve(Approval {
        registry: genesis.id(),
        record_txid: claims[0].id(),
        record_sha256: sha256::Hash::hash(&claims[0].bytes).to_byte_array(),
    })
    .to_record()
    .unwrap()
    .encode()
    .unwrap();
    let approvals = [11u8, 12]
        .into_iter()
        .map(|key| {
            let mut secret = [0; 32];
            secret[31] = key;
            assert!(rules.is_approver(&author_of(secret).x_only_public_key().0));
            signed_record(&approval, secret, key + 20)
        })
        .collect();
    (claims, approvals)
}

struct Fixture {
    genesis: Txid,
    post: Signed,
    blocks: Vec<Block>,
    source: Arc<Source>,
    config: ArchiveConfig,
    names_index: NamesIndex,
}
impl Fixture {
    fn new() -> Self {
        let bytes = include_bytes!("../../tests/vectors/names/genesis-administered.record");
        let genesis = signed_record(bytes, [4; 32], 8);
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(bytes).unwrap()).unwrap()
        else {
            panic!("public Genesis")
        };
        let (claims, approvals) = names_records(&genesis, &rules);
        let post_bytes = PublicRecord::Post("shared operator data".into())
            .encode()
            .unwrap();
        let post = signed_record(&post_bytes, [9; 32], 40);
        let commits = |set: &[Signed]| set.iter().map(|r| r.commit.clone()).collect::<Vec<_>>();
        let reveals = |set: &[Signed]| set.iter().map(|r| r.reveal.clone()).collect::<Vec<_>>();
        let bodies = [
            genesis.transactions(),
            commits(&claims),
            reveals(&claims),
            commits(&approvals),
            reveals(&approvals),
            post.transactions(),
            vec![],
        ];
        let mut blocks = Vec::new();
        for (nonce, body) in (26100u32..).zip(bodies.iter()) {
            blocks.push(witness_block(body, blocks.last(), nonce));
        }
        let config = ArchiveConfig {
            chain: Chain::BitcoinTestnet4,
            application_start: point(FIRST_HEIGHT, &blocks[0]),
            retention: Retention::Unpruned,
        };
        let mut names_index = NamesIndex::new(
            NETWORK,
            config.chain.genesis().unwrap().0.to_string(),
            blocks[0].block_hash().to_string(),
            Registry::new(genesis.id(), FIRST_HEIGHT, rules).unwrap(),
        );
        names_index.blocks.push(Checkpoint {
            height: FIRST_HEIGHT,
            hash: blocks[0].block_hash().to_string(),
        });
        let source = Arc::new(Source {
            branch: Mutex::new(blocks.clone()),
            calls: AtomicUsize::new(0),
        });
        Self {
            genesis: genesis.id(),
            post,
            blocks,
            source,
            config,
            names_index,
        }
    }

    fn seed(&self, path: &Path) -> Arc<Engine> {
        let engine =
            Arc::new(Engine::open(path, self.config.clone(), Some(self.source.clone())).unwrap());
        engine.synchronize_headers().unwrap();
        for _ in &self.blocks {
            engine.scan_next().unwrap();
        }
        let status = engine.status().unwrap();
        assert_eq!(
            status.scanned_blocks,
            u64::try_from(self.blocks.len()).unwrap()
        );
        assert_eq!(status.unresolved_dependencies, 0);
        engine
            .register_names(self.genesis, self.config.application_start)
            .unwrap();
        for _ in &self.blocks {
            if engine.names_step(self.genesis).unwrap().applied.is_none() {
                break;
            }
        }
        engine
    }

    fn post_entry(&self) -> Entry {
        let author = author_of([9; 32]).x_only_public_key().0;
        entry_from_record(
            &self.post.bytes,
            self.post.id(),
            author,
            Some(self.post.reveal.output[0].script_pubkey.as_script()),
            FIRST_HEIGHT + 5,
            2,
        )
        .unwrap()
        .unwrap()
    }

    /// The consumer's own Wire data: a local index holding the same post.
    fn local_wire_index(&self, path: &Path) {
        let blocks = self
            .blocks
            .iter()
            .zip(FIRST_HEIGHT..)
            .map(|(block, height)| urma_wire::index::Checkpoint {
                height,
                hash: block.block_hash().to_string(),
            })
            .collect();
        let index = Index {
            format: Index::FORMAT.into(),
            genesis: self.config.chain.genesis().unwrap().0.to_string(),
            start: FIRST_HEIGHT,
            blocks,
            entries: vec![self.post_entry()],
        };
        index.persist(path).unwrap();
    }
}

fn archive_state(engine: &Engine) -> Value {
    json!({"archive":engine.status().unwrap(),"wire":engine.wire_page(None, 1).unwrap().snapshot})
}

fn http(address: SocketAddr, request: &str) -> io::Result<(u16, Value)> {
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    stream.set_write_timeout(Some(remaining()?))?;
    stream.write_all(request.as_bytes())?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 16 * 1024 {
            return Err(io::Error::other("response header limit"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).map_err(io::Error::other)?;
    let code = head
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("missing status"))?
        .parse()
        .map_err(io::Error::other)?;
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| io::Error::other("missing response length"))?
        .1
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("test response body limit"));
    }
    let mut body = vec![0; length];
    stream.set_read_timeout(Some(remaining()?))?;
    stream.read_exact(&mut body)?;
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
    fn stop(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let request = format!(
            "POST /v1/shutdown HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        );
        let response = http(self.address, &request);
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service join exceeded cleanup bound".into());
        }
        worker
            .join()
            .map_err(|_| "Service panicked".to_owned())?
            .map_err(|e| e.to_string())?;
        match response {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            other => Err(format!("authenticated shutdown failed: {other:?}")),
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("Service cleanup: {error}");
        }
    }
}

fn private_file(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Archive endpoint plus an intentionally incomplete RPC setting: an
/// autonomous chain refresh is refused before any RPC request is made.
fn consumer_config(directory: &Path, endpoint: SocketAddr, rpc: SocketAddr) -> PathBuf {
    let token = directory.join("token");
    private_file(&token, TOKEN);
    let config = directory.join("config.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({"archive":{"endpoint":endpoint,"token_file":token},
            "rpc_url":format!("http://{rpc}/")}))
        .unwrap(),
    )
    .unwrap();
    config
}

fn wire_feed(directory: &Path, config: &Path, index: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env_clear()
        .current_dir(directory)
        .env("HOME", directory)
        .env("TMPDIR", directory)
        .env("URMA_CONFIG", config)
        .env("URMA_OUTPUT", "json")
        .env("URMA_LOG_OUTPUT", "stderr")
        .args(["wire", "read", "feed", "--index"])
        .arg(index)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "wire read failed: {stderr}");
    assert!(!stderr.contains(TOKEN), "bearer leaked to Wire CLI logs");
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Gateway {
    child: Option<Child>,
    directory: PathBuf,
    address: SocketAddr,
}
impl Gateway {
    fn start(directory: &Path, config: &Path, genesis: Txid) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env_clear()
            .current_dir(directory)
            .env("HOME", directory.join("home"))
            .env("TMPDIR", directory)
            .env("XDG_STATE_HOME", directory.join("state"))
            .env("XDG_DATA_HOME", directory.join("data"))
            .env("URMA_CONFIG", config)
            .env("URMA_LOG_OUTPUT", "stderr")
            .args(["gateway", "serve", "--domain", "localhost", "--registry"])
            .arg(format!("tbtc={genesis}"))
            .args(["--bind", "127.0.0.1:0", "--scheme", "http"])
            .args(["--workers", "1", "--rescan-seconds", "1", "--names-dir"])
            .arg(directory.join("names"))
            .arg("--store")
            .arg(directory.join("store"))
            .stdin(Stdio::null())
            .stdout(File::create(directory.join("stdout")).unwrap())
            .stderr(File::create(directory.join("stderr")).unwrap());
        let mut gateway = Self {
            child: Some(command.spawn().unwrap()),
            directory: directory.to_path_buf(),
            address: "127.0.0.1:0".parse().unwrap(),
        };
        gateway.address = gateway.poll("listen", |gateway| {
            gateway
                .logs()
                .split("listening on http://")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        });
        gateway
    }
    fn logs(&self) -> String {
        fs::read_to_string(self.directory.join("stderr")).unwrap_or_default()
    }
    fn poll<T>(&mut self, what: &str, mut probe: impl FnMut(&Self) -> Option<T>) -> T {
        let deadline = Instant::now() + POLL_TIMEOUT;
        loop {
            if let Some(found) = probe(self) {
                return found;
            }
            let exited = self.child.as_mut().unwrap().try_wait().unwrap();
            assert!(exited.is_none(), "gateway exited: {}", self.logs());
            assert!(Instant::now() < deadline, "gateway {what}: {}", self.logs());
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn names_source(&self) -> Option<Value> {
        let request =
            "GET /.well-known/urma/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (_, value) = http(self.address, request).ok()?;
        Some(value["networks"][0]["names_source"].clone())
    }
    fn refreshes(&self) -> usize {
        self.logs().matches("registry index refreshed").count()
    }
    fn finish(mut self) {
        assert!(
            !self.logs().contains(TOKEN),
            "bearer leaked to gateway logs"
        );
        self.reap();
    }
    fn reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "gateway reap bound");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.reap();
    }
}

fn rpc_trap() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_no_rpc(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "a consumer attempted chain RPC"
    );
}

fn consumer_dir(control: &Path, name: &str) -> PathBuf {
    let directory = control.join(name);
    for folder in ["home", "names", "state", "data"] {
        fs::create_dir_all(directory.join(folder)).unwrap();
    }
    directory
}

fn assert_operator_feed(feed: &Value, engine: &Engine, fixture: &Fixture) {
    let source = &feed["source"];
    assert_eq!(source["kind"], OPERATOR, "{feed}");
    let status = engine.status().unwrap();
    assert_eq!(source["indexed_through"], json!(status.indexed_through));
    assert_eq!(source["generation"], status.generation);
    assert_eq!(feed["records"].as_array().unwrap().len(), 1, "{feed}");
    assert_eq!(feed["records"][0]["txid"], fixture.post.id().to_string());
}

#[test]
fn wire_and_names_consumers_share_one_service_without_scans() {
    let temp = tempfile::tempdir().unwrap();
    let control = temp.path();
    let fixture = Fixture::new();
    let engine = fixture.seed(&control.join("archive"));
    let mut session = Session::start(engine.clone());
    let rpc = rpc_trap();
    let rpc_address = rpc.local_addr().unwrap();
    let before = archive_state(&engine);
    let calls = fixture.source.count();
    let wire_dir = consumer_dir(control, "wire");
    let wire_config = consumer_config(&wire_dir, session.address, rpc_address);
    let missing_index = wire_dir.join("never-created-wire-index.json");
    let gateway_dir = consumer_dir(control, "gateway");
    let gateway_config = consumer_config(&gateway_dir, session.address, rpc_address);
    let mut gateway = Gateway::start(&gateway_dir, &gateway_config, fixture.genesis);
    for round in 1..=2 {
        let feed = wire_feed(&wire_dir, &wire_config, &missing_index);
        assert_operator_feed(&feed, &engine, &fixture);
        let names = gateway.poll("operator refresh", |gateway| {
            let source = gateway.names_source()?;
            (gateway.refreshes() >= round && source["kind"] == OPERATOR).then_some(source)
        });
        assert_eq!(names["tip_basis"], "operator-reported");
        assert!(names["trust"].as_str().unwrap().contains("operator"));
        assert_eq!(
            archive_state(&engine),
            before,
            "round {round} changed the archive"
        );
        assert_eq!(
            fixture.source.count(),
            calls,
            "round {round} scanned the chain"
        );
        assert!(!missing_index.exists(), "Wire built a local index");
        assert_eq!(fs::read_dir(gateway_dir.join("names")).unwrap().count(), 0);
        assert_no_rpc(&rpc);
    }
    gateway.finish();
    session.stop().unwrap();
}

#[test]
fn stopped_service_sends_both_consumers_to_their_own_local_data() {
    let temp = tempfile::tempdir().unwrap();
    let control = temp.path();
    let fixture = Fixture::new();
    let archive = control.join("archive");
    let engine = fixture.seed(&archive);
    let mut session = Session::start(engine.clone());
    let rpc = rpc_trap();
    let rpc_address = rpc.local_addr().unwrap();
    let wire_dir = consumer_dir(control, "wire");
    let wire_config = consumer_config(&wire_dir, session.address, rpc_address);
    let local_wire = wire_dir.join("wire-index.json");
    fixture.local_wire_index(&local_wire);
    let local_bytes = fs::read(&local_wire).unwrap();
    assert_operator_feed(
        &wire_feed(&wire_dir, &wire_config, &local_wire),
        &engine,
        &fixture,
    );
    let before = archive_state(&engine);
    let calls = fixture.source.count();
    session.stop().unwrap();

    let feed = wire_feed(&wire_dir, &wire_config, &local_wire);
    assert_eq!(feed["source"], json!({"kind":AUTONOMOUS}), "{feed}");
    assert_eq!(feed["records"][0]["txid"], fixture.post.id().to_string());
    assert_eq!(
        fs::read(&local_wire).unwrap(),
        local_bytes,
        "fallback rewrote index"
    );

    let gateway_dir = consumer_dir(control, "gateway");
    let gateway_config = consumer_config(&gateway_dir, session.address, rpc_address);
    let names_index = gateway_dir
        .join("names")
        .join(NETWORK)
        .join(format!("{}.json", fixture.genesis));
    fs::create_dir_all(names_index.parent().unwrap()).unwrap();
    fixture.names_index.persist(&names_index).unwrap();
    let names_bytes = fs::read(&names_index).unwrap();
    let mut gateway = Gateway::start(&gateway_dir, &gateway_config, fixture.genesis);
    let names = gateway.poll("autonomous fallback", |gateway| {
        let source = gateway.names_source()?;
        let fell_back = gateway
            .logs()
            .contains("optional Names archive unavailable");
        (fell_back && source["kind"] == AUTONOMOUS).then_some(source)
    });
    assert_eq!(names["tip_basis"], "autonomous-chain-source");
    assert_eq!(
        fs::read(&names_index).unwrap(),
        names_bytes,
        "fallback rewrote index"
    );
    assert_no_rpc(&rpc);
    gateway.finish();

    assert_eq!(
        fixture.source.count(),
        calls,
        "fallback reached the chain source"
    );
    assert_eq!(
        archive_state(&engine),
        before,
        "fallback changed the archive"
    );
    drop(engine);
    let reopened = Engine::open(&archive, fixture.config.clone(), None).unwrap();
    assert_eq!(
        archive_state(&reopened)["archive"],
        before["archive"],
        "archive changed across reopen; the snapshot instance is per engine"
    );
}
