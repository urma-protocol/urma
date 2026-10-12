//! Actual gateway binary consuming an explicitly configured local operator.
//! Public signed Names records inhabit witness-integrity-valid mock-selected
//! BitcoinTestnet4 blocks: no PoW, script, UTXO or consensus claim.
//! No NamesIndex is manufactured. Operator acquisition age is not scan age.
//! The gateway has no shutdown API: its kill/reap is owned test-child cleanup;
//! the actual Node Service must acknowledge shutdown and join normally.
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
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    name::Name,
    payload::{Approval, Payload},
    state::Resolution,
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    names::{NamesEntry, NamesPage},
    service::Service,
    source::ChainSource,
};
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NETWORK: &str = "bitcoin-testnet4";
const FIRST_HEIGHT: u64 = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_TIMEOUT: Duration = Duration::from_secs(8);
const TRUST: &str = "local operator projection; not portable chain or ownership evidence";
fn point(height: u64, block: &Block) -> ChainPoint {
    ChainPoint {
        height,
        hash: block.block_hash(),
    }
}
fn stage(control: &Path, text: &str) {
    fs::write(control.join("stage"), text).unwrap();
}
fn signed_record(bytes: &[u8], secret: [u8; 32], tag: u8) -> Signed {
    Payload::from_record(&PublicRecord::decode(bytes).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let signer = Keypair::from_seckey_slice(&secp, &secret).unwrap();
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
    let commit = Transaction {
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
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
            },
        ],
    };
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
    assert_eq!(verified.author(), author);
    Signed {
        commit,
        reveal,
        bytes: bytes.to_vec(),
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
    fn transactions(&self) -> [Transaction; 2] {
        [self.commit.clone(), self.reveal.clone()]
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
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

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
    fn select(&self, blocks: &[Block]) {
        let mut current = self.branch.lock().unwrap();
        assert!(blocks.len() >= current.len());
        for (left, right) in current.iter().zip(blocks) {
            assert_eq!(left.block_hash(), right.block_hash());
        }
        for pair in blocks.windows(2) {
            assert_eq!(pair[1].header.prev_blockhash, pair[0].block_hash());
        }
        *current = blocks.to_vec();
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
        Ok(point(
            FIRST_HEIGHT + blocks.len() as u64 - 1,
            blocks.last().unwrap(),
        ))
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
struct Fixture {
    genesis: Txid,
    blocks: Vec<Block>,
    source: Arc<Source>,
    config: ArchiveConfig,
}
impl Fixture {
    fn new(selected_count: usize) -> Self {
        let bytes = include_bytes!("../../tests/vectors/names/genesis-administered.record");
        let genesis = signed_record(bytes, [4; 32], 8);
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(bytes).unwrap()).unwrap()
        else {
            panic!("public Genesis")
        };
        assert_eq!(rules.threshold, 2);
        let Payload::Claim(template) = Payload::from_record(
            &PublicRecord::decode(include_bytes!("../../tests/vectors/names/claim.record"))
                .unwrap(),
        )
        .unwrap() else {
            panic!("public Claim")
        };
        let claims = ["alpha", "bravo"].map(|name| {
            let mut claim = template.clone();
            claim.registry = genesis.id();
            claim.name = Name::parse(name).unwrap();
            signed_record(
                &Payload::Claim(claim).to_record().unwrap().encode().unwrap(),
                [5; 32],
                if name == "alpha" { 11 } else { 12 },
            )
        });
        let approval = Payload::Approve(Approval {
            registry: genesis.id(),
            record_txid: claims[0].id(),
            record_sha256: sha256::Hash::hash(&claims[0].bytes).to_byte_array(),
        })
        .to_record()
        .unwrap()
        .encode()
        .unwrap();
        let approvals = [11, 12].map(|key| {
            let mut secret = [0; 32];
            secret[31] = key;
            let author = Keypair::from_seckey_slice(&Secp256k1::new(), &secret)
                .unwrap()
                .x_only_public_key()
                .0;
            assert!(rules.is_approver(&author));
            signed_record(&approval, secret, key + 20)
        });
        let bodies = vec![
            genesis.transactions().to_vec(),
            claims.iter().map(|r| r.commit.clone()).collect(),
            claims.iter().map(|r| r.reveal.clone()).collect(),
            approvals.iter().map(|r| r.commit.clone()).collect(),
            approvals.iter().map(|r| r.reveal.clone()).collect(),
            vec![],
            vec![],
            vec![],
        ];
        let mut blocks = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            blocks.push(witness_block(body, blocks.last(), 24100 + i as u32));
        }
        assert!((3..=blocks.len()).contains(&selected_count));
        let config = ArchiveConfig {
            chain: Chain::BitcoinTestnet4,
            application_start: point(FIRST_HEIGHT, &blocks[0]),
            retention: Retention::Unpruned,
        };
        let source = Arc::new(Source {
            branch: Mutex::new(blocks[..selected_count].to_vec()),
            calls: AtomicUsize::new(0),
        });
        Self {
            genesis: genesis.id(),
            blocks,
            source,
            config,
        }
    }
    fn seed(&self, path: &Path, through: u64) -> Arc<Engine> {
        let engine =
            Arc::new(Engine::open(path, self.config.clone(), Some(self.source.clone())).unwrap());
        self.scan_selected(&engine);
        engine
            .register_names(self.genesis, self.config.application_start)
            .unwrap();
        self.advance(&engine, through);
        engine
    }
    fn scan_selected(&self, engine: &Engine) {
        let status = engine.synchronize_headers().unwrap();
        let count = self.source.branch.lock().unwrap().len() as u64;
        assert!(status.scanned_blocks <= count);
        for _ in status.scanned_blocks..count {
            engine.scan_next().unwrap();
        }
        assert_eq!(engine.status().unwrap().scanned_blocks, count);
        assert_eq!(engine.status().unwrap().unresolved_dependencies, 0);
    }
    fn advance(&self, engine: &Engine, through: u64) {
        let start = engine
            .names_status(self.genesis)
            .unwrap()
            .unwrap()
            .projected
            .height;
        for height in start + 1..=through {
            let step = engine.names_step(self.genesis).unwrap();
            assert_eq!(
                step.applied,
                Some(point(
                    height,
                    &self.blocks[(height - FIRST_HEIGHT) as usize]
                ))
            );
            assert_eq!(step.rolled_back, 0);
        }
    }
    fn page(&self, engine: &Engine) -> NamesPage {
        let page = engine.names_view(self.genesis, None, 128).unwrap();
        assert!(page.next.is_none());
        page
    }
}
fn engine_state(engine: &Engine, genesis: Txid) -> Value {
    json!({"archive":engine.status().unwrap(),
        "names":engine.names_status(genesis).unwrap(),
        "view":engine.names_view(genesis,None,128).unwrap()})
}

struct Response {
    code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Response {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
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
    Ok(Response {
        code,
        headers,
        body,
    })
}
fn request(method: &str, path: &str, host: &str, extra: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n")
}
fn get(address: SocketAddr, host: &str, path: &str) -> io::Result<Response> {
    http(address, &request("GET", path, host, ""))
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

// A process group belongs exclusively to this test host and its gateway child.
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
struct GatewayProcess {
    child: OwnedChild,
    directory: PathBuf,
    address: SocketAddr,
}
impl GatewayProcess {
    fn start(
        control: &Path,
        name: &str,
        genesis: Txid,
        endpoint: SocketAddr,
        rpc: SocketAddr,
    ) -> Self {
        let directory = control.join(name);
        fs::create_dir(&directory).unwrap();
        for folder in ["home", "names", "state", "data"] {
            fs::create_dir(directory.join(folder)).unwrap();
        }
        let token = directory.join("token");
        fs::write(&token, TOKEN).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let config = directory.join("config.json");
        // Intentionally incomplete RPC config: refusal occurs before any RPC
        // request; omitting both settings would select public P2P instead.
        fs::write(
            &config,
            serde_json::to_vec(&json!({"archive":{
            "endpoint":endpoint,"token_file":token},"rpc_url":format!("http://{rpc}/")}))
            .unwrap(),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env_clear()
            .current_dir(&directory)
            .env("HOME", directory.join("home"))
            .env("TMPDIR", &directory)
            .env("XDG_STATE_HOME", directory.join("state"))
            .env("XDG_DATA_HOME", directory.join("data"))
            .env("URMA_CONFIG", config)
            .env("URMA_LOG_OUTPUT", "stderr")
            .args([
                "gateway",
                "serve",
                "--domain",
                "portal.example",
                "--registry",
            ])
            .arg(format!("tbtc={genesis}"))
            .args([
                "--bind",
                "127.0.0.1:0",
                "--scheme",
                "http",
                "--workers",
                "1",
                "--rescan-seconds",
                "1",
                "--names-dir",
            ])
            .arg(directory.join("names"))
            .arg("--store")
            .arg(directory.join("store"))
            .stdin(Stdio::null())
            .stdout(File::create(directory.join("stdout")).unwrap())
            .stderr(File::create(directory.join("stderr")).unwrap());
        let mut child = OwnedChild {
            child: Some(command.spawn().unwrap()),
            group: false,
        };
        let deadline = Instant::now() + POLL_TIMEOUT;
        let address = loop {
            let logs = bounded_text(&directory.join("stderr"));
            if let Some(value) = logs
                .split("listening on http://")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
            {
                break value.parse::<SocketAddr>().unwrap();
            }
            assert!(
                child.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "gateway exited: {logs}"
            );
            assert!(Instant::now() < deadline, "gateway listen timeout: {logs}");
            thread::sleep(Duration::from_millis(10));
        };
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        Self {
            child,
            directory,
            address,
        }
    }
    fn logs(&self) -> String {
        bounded_text(&self.directory.join("stderr"))
    }
    fn wait(&mut self, mut predicate: impl FnMut(&Value) -> bool) -> Value {
        let deadline = Instant::now() + POLL_TIMEOUT;
        loop {
            let response = get(self.address, "portal.example", "/.well-known/urma/ready");
            if let Ok(response) = response {
                let value = response.json();
                if predicate(&value) {
                    return value;
                }
            }
            assert!(
                self.child
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "gateway exited: {}",
                self.logs()
            );
            assert!(
                Instant::now() < deadline,
                "gateway readiness timeout: {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait_failures(&mut self, since: usize, count: usize) {
        let deadline = Instant::now() + POLL_TIMEOUT;
        loop {
            let logs = self.logs();
            if logs.matches("registry rescan failed;").count() >= since + count {
                return;
            }
            assert!(Instant::now() < deadline, "fallback not observed: {logs}");
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn assert_no_index(&self) {
        assert_eq!(
            fs::read_dir(self.directory.join("names")).unwrap().count(),
            0
        );
        assert!(
            !self.directory.join("data/urma").exists(),
            "public P2P cache created"
        );
        assert!(!self.logs().contains(TOKEN), "fixture bearer leaked");
    }
    fn finish(mut self) {
        self.assert_no_index();
        self.child.terminate().unwrap();
        let listener =
            TcpListener::bind(self.address).expect("gateway listener still owned after reap");
        drop(listener);
    }
}
fn rpc_trap() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}
fn no_rpc(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "gateway attempted RPC"
    );
}
fn row(value: &Value) -> &Value {
    assert_eq!(value["networks"].as_array().unwrap().len(), 1);
    &value["networks"][0]
}
fn assert_source(source: &Value, page: &NamesPage) {
    assert_eq!(source["kind"], "local-node-operator");
    assert!(source["scan_age_seconds"].is_null());
    assert!(source["view_age_seconds"].as_u64().is_some());
    assert_eq!(source["projected"], json!(page.status.projected));
    assert_eq!(
        source["selected_tip"],
        json!(page.status.selected_tip.unwrap())
    );
    assert_eq!(source["complete_to_tip"], page.status.complete_to_tip);
    assert_eq!(source["generation"], page.status.generation);
    assert_eq!(source["snapshot"], json!(page.snapshot));
    assert_eq!(source["tip_basis"], "operator-reported");
    assert_eq!(source["trust"], TRUST);
}
fn assert_ready(gateway: &GatewayProcess, page: &NamesPage, ready: bool) -> Value {
    let response = get(gateway.address, "portal.example", "/.well-known/urma/ready").unwrap();
    assert_eq!(response.code, if ready { 200 } else { 503 });
    let value = response.json();
    assert_eq!(value["ready"], ready);
    let row = row(&value);
    assert_eq!(row["network"], NETWORK);
    assert_eq!(row["suffix"], "tbtc");
    assert_eq!(row["registry"], page.status.genesis.to_string());
    assert_eq!(row["state"], if ready { "ready" } else { "index-behind" });
    assert_eq!(row["index_height"], page.status.projected.height);
    assert_eq!(row["chain_tip"], page.status.selected_tip.unwrap().height);
    assert!(row["scan_age_seconds"].is_null());
    assert!(row["view_age_seconds"].as_u64().is_some());
    assert_source(&row["names_source"], page);
    value
}
fn proof(gateway: &GatewayProcess, page: &NamesPage, name: &str) -> Value {
    let response = get(
        gateway.address,
        &format!("{name}.tbtc.portal.example"),
        "/.well-known/urma/proof",
    )
    .unwrap();
    assert_eq!(response.code, 200);
    assert_eq!(
        response.header("URMA-Names-Source"),
        ["local-node-operator"]
    );
    assert_eq!(
        response.header("URMA-Names-Complete-To-Tip"),
        [if page.status.complete_to_tip {
            "true"
        } else {
            "false"
        }]
    );
    assert_eq!(
        response.header("URMA-Registry"),
        [page.status.genesis.to_string().as_str()]
    );
    assert_eq!(
        response.header("URMA-Index"),
        [format!(
            "{} {}",
            page.status.projected.height, page.status.projected.hash
        )
        .as_str()]
    );
    for header in ["URMA-Root", "URMA-Author", "URMA-Payload-SHA256"] {
        assert!(response.header(header).is_empty());
    }
    let value = response.json();
    assert_eq!(value["format"], "URMA-PORTAL-PROOF-1");
    assert_eq!(
        value["chain_tip"],
        json!({"height":page.status.selected_tip.unwrap().height,
        "block_hash":page.status.selected_tip.unwrap().hash.to_string()})
    );
    assert_eq!(value["resolver"]["network"], NETWORK);
    assert_eq!(
        value["resolver"]["registry"],
        page.status.genesis.to_string()
    );
    assert_eq!(
        value["resolver"]["genesis_height"],
        page.status.genesis_block.height
    );
    assert_eq!(value["resolver"]["height"], page.status.projected.height);
    assert_eq!(
        value["resolver"]["block_hash"],
        page.status.projected.hash.to_string()
    );
    assert_eq!(value["resolver"]["name"], name);
    assert_eq!(value["resolver"]["resolution"], json!(Resolution::Unbound));
    let pending: Vec<_> = page
        .entries
        .iter()
        .filter_map(|entry| match entry {
            NamesEntry::Pending { txid, record } if record.name.as_str() == name => {
                Some((*txid, record))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(txid, record)| json!({"txid":txid,"record":record}))
        .collect();
    assert_eq!(value["resolver"]["pending"], json!(pending));
    assert_eq!(value["resolver"]["locally_cached"], true);
    assert_source(&value["resolver"]["source"], page);
    assert!(value.get("root").is_none());
    assert!(value.get("declared").is_none());
    value
}
fn ordinary_unbound(gateway: &GatewayProcess, page: &NamesPage, behind: bool) {
    let response = get(gateway.address, "bravo.tbtc.portal.example", "/").unwrap();
    assert_eq!(response.code, if behind { 503 } else { 404 });
    assert_eq!(
        response.header("URMA-State"),
        [if behind { "index-behind" } else { "unbound" }]
    );
    assert_eq!(
        response.header("URMA-Names-Source"),
        ["local-node-operator"]
    );
    assert_eq!(
        response.header("URMA-Names-Complete-To-Tip"),
        [if page.status.complete_to_tip {
            "true"
        } else {
            "false"
        }]
    );
    assert!(response.header("URMA-Root").is_empty());
}

#[derive(Clone)]
enum OperatorMode {
    Unavailable,
    Healthy(NamesPage),
    ChangedPage {
        prefix: NamesPage,
        changed: NamesPage,
    },
}
struct ScriptedOperator {
    address: SocketAddr,
    mode: Arc<Mutex<OperatorMode>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl ScriptedOperator {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let mode = Arc::new(Mutex::new(OperatorMode::Unavailable));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let state = mode.clone();
        let seen = requests.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("owned operator accept: {e}"),
                };
                let deadline = Instant::now() + HTTP_TIMEOUT;
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    assert!(bytes.len() < 16 * 1024, "owned request head bound");
                    let left = deadline.checked_duration_since(Instant::now()).unwrap();
                    stream.set_read_timeout(Some(left)).unwrap();
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let head = String::from_utf8(bytes).unwrap();
                let target = head
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                assert!(
                    head.lines()
                        .any(|line| line == format!("Authorization: Bearer {TOKEN}"))
                );
                assert!(target.starts_with("/v1/names/"));
                assert!(target.contains("/view?limit=128"));
                {
                    let mut requests = seen.lock().unwrap();
                    assert!(requests.len() < 64, "owned operator request log bound");
                    requests.push(target.to_owned());
                }
                let (code, value) = match &*state.lock().unwrap() {
                    OperatorMode::Unavailable => (503, json!({"error":"owned unavailable"})),
                    OperatorMode::Healthy(page) => {
                        assert!(!target.contains("&cursor="));
                        (200, json!(page))
                    }
                    OperatorMode::ChangedPage { prefix, changed } => {
                        if let Some(hex) = target.split("&cursor=").nth(1) {
                            let cursor: urma_node_client::names::NamesCursor =
                                serde_json::from_slice(&hex::decode(hex).unwrap()).unwrap();
                            assert_eq!(Some(&cursor), prefix.next.as_ref());
                            (200, json!(changed))
                        } else {
                            (200, json!(prefix))
                        }
                    }
                };
                let body = serde_json::to_vec(&value).unwrap();
                let response = format!(
                    "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if code == 200 {
                        "OK"
                    } else {
                        "Service Unavailable"
                    },
                    body.len()
                );
                stream
                    .set_write_timeout(Some(
                        deadline.checked_duration_since(Instant::now()).unwrap(),
                    ))
                    .unwrap();
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self {
            address,
            mode,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn set(&self, mode: OperatorMode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn cleanup(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("owned operator join exceeded bound".into());
        }
        worker
            .join()
            .map_err(|_| "owned operator panicked".to_owned())
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
    }
}
impl Drop for ScriptedOperator {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("{e}");
        }
    }
}
fn fallback_log(gateway: &GatewayProcess) {
    let logs = gateway.logs();
    assert!(
        logs.contains("optional Names archive unavailable; attempting autonomous registry refresh"),
        "{logs}"
    );
    assert!(logs.contains("needs node_auth_file in config"), "{logs}");
    assert!(
        logs.contains(
            "registry rescan failed; serving the previous index until it is no longer current"
        ),
        "{logs}"
    );
}
fn stable_metadata(mut source: Value) -> Value {
    assert!(
        source
            .as_object_mut()
            .unwrap()
            .remove("view_age_seconds")
            .is_some()
    );
    source
}
fn stable_proof(mut proof: Value) -> Value {
    let source = proof["resolver"]["source"].take();
    proof["resolver"]["source"] = stable_metadata(source);
    proof
}
fn assert_seed(fixture: &Fixture, engine: &Engine, projected: u64) {
    let page = fixture.page(engine);
    assert_eq!(
        page.chain_genesis,
        Chain::BitcoinTestnet4.genesis().unwrap().0
    );
    assert_eq!(page.status.projected.height, projected);
    assert_eq!(
        page.entries
            .iter()
            .filter(|e| matches!(e, NamesEntry::Pending { .. }))
            .count(),
        2
    );
    assert_eq!(
        engine
            .names_resolve(fixture.genesis, &Name::parse("bravo").unwrap())
            .unwrap()
            .resolution,
        Resolution::Unbound
    );
    if projected >= 104 {
        assert!(matches!(
            engine
                .names_resolve(fixture.genesis, &Name::parse("alpha").unwrap())
                .unwrap()
                .resolution,
            Resolution::Bound(_)
        ));
        assert_eq!(
            page.entries
                .iter()
                .filter(|e| matches!(e,NamesEntry::Pending{record,..} if record.completed))
                .count(),
            1
        );
    } else {
        assert_eq!(
            engine
                .names_resolve(fixture.genesis, &Name::parse("alpha").unwrap())
                .unwrap()
                .resolution,
            Resolution::Unbound
        );
        assert!(
            page.entries
                .iter()
                .all(|e| matches!(e,NamesEntry::Pending{record,..} if !record.completed))
        );
    }
}
fn healthy(control: &Path) {
    stage(
        control,
        "G1 genuine signed Node Service and real gateway incomplete healthy view",
    );
    let fixture = Fixture::new(7);
    let engine = fixture.seed(&control.join("archive"), 104);
    assert_seed(&fixture, &engine, 104);
    let page = fixture.page(&engine);
    assert_eq!(page.status.selected_tip.unwrap().height, 106);
    assert!(!page.status.complete_to_tip);
    let before = engine_state(&engine, fixture.genesis);
    let calls = fixture.source.count();
    let service = Session::start(engine.clone());
    let rpc = rpc_trap();
    let mut gateway = GatewayProcess::start(
        control,
        "gateway",
        fixture.genesis,
        service.address,
        rpc.local_addr().unwrap(),
    );
    gateway.wait(|value| row(value)["names_source"]["snapshot"] == json!(page.snapshot));
    assert_ready(&gateway, &page, true);
    ordinary_unbound(&gateway, &page, false);
    proof(&gateway, &page, "bravo");
    assert_eq!(engine_state(&engine, fixture.genesis), before);
    assert_eq!(fixture.source.count(), calls);
    no_rpc(&rpc);
    gateway.assert_no_index();
    stage(
        control,
        "G1 gateway owned kill/reap and actual Service normal shutdown/join",
    );
    gateway.finish();
    service.finish();
    drop(engine);
    let reopened = Engine::open(&control.join("archive"), fixture.config, None).unwrap();
    let after = engine_state(&reopened, fixture.genesis);
    assert_eq!(after["archive"], before["archive"]);
    assert_eq!(after["names"], before["names"]);
    assert_eq!(after["view"]["entries"], before["view"]["entries"]);
    assert_eq!(after["view"]["rules"], before["view"]["rules"]);
    assert_eq!(
        after["view"]["snapshot"]["revision"],
        before["view"]["snapshot"]["revision"]
    );
    assert_ne!(
        after["view"]["snapshot"]["instance"],
        before["view"]["snapshot"]["instance"]
    );
}
fn lag_and_age(control: &Path) {
    stage(control, "G2 actual operator tip P+2 incomplete may serve");
    let fixture = Fixture::new(7);
    let engine = fixture.seed(&control.join("archive"), 104);
    assert_seed(&fixture, &engine, 104);
    let service = Session::start(engine.clone());
    let rpc = rpc_trap();
    let mut gateway = GatewayProcess::start(
        control,
        "gateway",
        fixture.genesis,
        service.address,
        rpc.local_addr().unwrap(),
    );
    let page = fixture.page(&engine);
    gateway.wait(|value| row(value)["names_source"]["snapshot"] == json!(page.snapshot));
    assert_ready(&gateway, &page, true);
    ordinary_unbound(&gateway, &page, false);
    stage(
        control,
        "G2 grow actual selected tip to P+3, successful view publication still behind",
    );
    fixture.source.select(&fixture.blocks);
    fixture.scan_selected(&engine);
    let page = fixture.page(&engine);
    assert_eq!(page.status.projected.height, 104);
    assert_eq!(page.status.selected_tip.unwrap().height, 107);
    assert!(!page.status.complete_to_tip);
    let before = engine_state(&engine, fixture.genesis);
    let calls = fixture.source.count();
    gateway.wait(|value| row(value)["names_source"]["snapshot"] == json!(page.snapshot));
    let readiness = assert_ready(&gateway, &page, false);
    ordinary_unbound(&gateway, &page, true);
    let baseline = stable_proof(proof(&gateway, &page, "bravo"));
    let metadata = stable_metadata(row(&readiness)["names_source"].clone());
    stage(
        control,
        "G2 normal Service shutdown makes archive unavailable, autonomous refresh configuration refuses",
    );
    service.finish();
    let since = gateway.logs().matches("registry rescan failed;").count();
    gateway.wait_failures(since, 3);
    let retained = assert_ready(&gateway, &page, false);
    // With three failed rescan periods the acquisition clock must advance;
    // never mistake continued old-view serving for a new scan or acquisition.
    assert!(row(&retained)["view_age_seconds"].as_u64().unwrap() >= 2);
    assert!(
        row(&retained)["names_source"]["view_age_seconds"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert_eq!(
        stable_metadata(row(&retained)["names_source"].clone()),
        metadata
    );
    assert_eq!(stable_proof(proof(&gateway, &page, "bravo")), baseline);
    fallback_log(&gateway);
    no_rpc(&rpc);
    assert_eq!(engine_state(&engine, fixture.genesis), before);
    assert_eq!(fixture.source.count(), calls);
    stage(control, "G2 gateway bounded owned cleanup");
    gateway.finish();
}
fn invalid_traversal(control: &Path) {
    stage(
        control,
        "G3 unavailable at startup, fallback refused before RPC",
    );
    let fixture = Fixture::new(3);
    let engine = fixture.seed(&control.join("archive"), 102);
    assert_seed(&fixture, &engine, 102);
    let baseline = fixture.page(&engine);
    assert!(baseline.status.complete_to_tip);
    let operator = ScriptedOperator::start();
    let rpc = rpc_trap();
    let mut gateway = GatewayProcess::start(
        control,
        "gateway",
        fixture.genesis,
        operator.address,
        rpc.local_addr().unwrap(),
    );
    gateway.wait_failures(0, 1);
    let response = get(gateway.address, "portal.example", "/.well-known/urma/ready").unwrap();
    assert_eq!(response.code, 503);
    let value = response.json();
    assert_eq!(value["ready"], false);
    assert_eq!(row(&value)["state"], "unavailable");
    assert!(row(&value).get("names_source").is_none());
    fallback_log(&gateway);
    no_rpc(&rpc);
    stage(
        control,
        "G3 publish genuine baseline with pending-only alpha unbound",
    );
    operator.set(OperatorMode::Healthy(baseline.clone()));
    gateway.wait(|value| row(value)["names_source"]["snapshot"] == json!(baseline.snapshot));
    assert_ready(&gateway, &baseline, true);
    let old_proof = stable_proof(proof(&gateway, &baseline, "alpha"));
    // A new genuine projection now binds alpha. Its Name(alpha) prefix must
    // not overwrite the baseline when the following page's snapshot changes.
    fixture.source.select(&fixture.blocks[..7]);
    fixture.scan_selected(&engine);
    fixture.advance(&engine, 104);
    assert_seed(&fixture, &engine, 104);
    let prefix = engine.names_view(fixture.genesis, None, 1).unwrap();
    assert_eq!(prefix.entries.len(), 1);
    assert!(matches!(&prefix.entries[0],NamesEntry::Name{name,state}
        if name.as_str()=="alpha" && matches!(&state.binding,urma_names::state::Binding::Bound(_))));
    let mut changed = engine
        .names_view(fixture.genesis, prefix.next.as_ref(), 128)
        .unwrap();
    assert!(!changed.entries.is_empty());
    assert!(changed.next.is_none());
    assert_eq!(changed.snapshot, prefix.snapshot);
    // Explicit negative transport fixture: corrupt metadata only, preserving
    // genuine names/pending payloads. This does not claim malicious P2P evidence.
    changed.snapshot.revision = changed.snapshot.revision.checked_add(1).unwrap();
    let before = engine_state(&engine, fixture.genesis);
    let calls = fixture.source.count();
    let requests = operator.count();
    let since = gateway.logs().matches("registry rescan failed;").count();
    operator.set(OperatorMode::ChangedPage { prefix, changed });
    stage(
        control,
        "G3 valid new Name(alpha) prefix then changed snapshot rejected without merge",
    );
    gateway.wait_failures(since, 3);
    let seen = operator.requests.lock().unwrap();
    assert!(
        seen[requests..]
            .iter()
            .any(|path| path.contains("&cursor=")),
        "second page was never requested"
    );
    drop(seen);
    let retained = assert_ready(&gateway, &baseline, true);
    assert!(row(&retained)["view_age_seconds"].as_u64().unwrap() >= 2);
    assert_eq!(stable_proof(proof(&gateway, &baseline, "alpha")), old_proof);
    fallback_log(&gateway);
    no_rpc(&rpc);
    gateway.assert_no_index();
    assert_eq!(engine_state(&engine, fixture.genesis), before);
    assert_eq!(fixture.source.count(), calls);
    stage(
        control,
        "G3 bounded gateway cleanup and owned operator join",
    );
    gateway.finish();
    operator.finish();
}

#[test]
#[ignore = "owned bounded subprocess host, not a standalone gateway test"]
fn gateway_archive_host() {
    let control = PathBuf::from(std::env::var_os("U4_GATEWAY_ARCHIVE_TEMP").expect("owned TEMP"));
    let case = std::env::var("U4_GATEWAY_ARCHIVE_CASE").unwrap();
    match case.as_str() {
        "healthy" => healthy(&control),
        "lag" => lag_and_age(&control),
        "invalid" => invalid_traversal(&control),
        _ => panic!("unknown owned case"),
    };
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
            "gateway_archive_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U4_GATEWAY_ARCHIVE_TEMP", directory.path())
        .env("U4_GATEWAY_ARCHIVE_CASE", case)
        .env("TMPDIR", directory.path())
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
            // Preserve group ownership until success is checked: a failed host
            // might leave a gateway child even though the host itself exited.
            assert!(
                exit.success(),
                "gateway host {case} failed: {exit}; {}",
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
            "gateway host {case} exceeded45s; owned group kill/reap abnormal cleanup only; {}",
            logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn gateway_reads_genuine_operator_view_without_creating_scan_index() {
    run_host("healthy");
}
#[test]
fn gateway_uses_operator_tip_lag_and_retains_acquisition_clock_after_failures() {
    run_host("lag");
}
#[test]
fn gateway_falls_back_and_rejects_changed_page_without_partial_publication() {
    run_host("invalid");
}
