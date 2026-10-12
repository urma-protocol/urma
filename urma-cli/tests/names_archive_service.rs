//! Real authenticated Node Service -> public Client -> CLI Names reads.
//! Genuine signed Names history is placed in witness-integrity-valid mock-selected
//! blocks. These fixtures make no PoW, script, UTXO or consensus claim.
//! The subprocess host bounds abnormal cleanup; it does not hard-cancel I/O.
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
    payload::{Approval, Payload},
    state::{PendingRecord, Resolution, Target, Verdict},
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
const NETWORK: &str = "bitcoin-regtest";
const FIRST_HEIGHT: u64 = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(90);
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

fn request(method: &str, path: &str, headers: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n{headers}\r\n")
}
fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
}

// One absolute deadline for harness HTTP connect/write/read; no Client U2 API.
fn http(address: SocketAddr, request: &str) -> io::Result<(u16, Value)> {
    assert!(address.ip().is_loopback());
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
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
            return Err(io::Error::other("response header limit"));
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
        .ok_or_else(|| io::Error::other("missing status"))?
        .parse::<u16>()
        .map_err(io::Error::other)?;
    let headers: Vec<_> = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect();
    assert!(
        headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
                && value.trim() == "application/json")
    );
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() != 1 {
        return Err(io::Error::other("missing/duplicate response length"));
    }
    let length = lengths[0]
        .1
        .trim()
        .parse::<usize>()
        .map_err(io::Error::other)?;
    if length > 1024 * 1024 {
        return Err(io::Error::other("test response body limit"));
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

struct Host {
    child: Option<Child>,
    directory: PathBuf,
    // Only the explicit Surf host creates a new group. Bridge and its CLI
    // inherit it; retain the group ID even after the host child is reaped.
    owned_group: Option<u32>,
}

impl Host {
    fn logs(&self) -> String {
        ["stage", "stdout", "stderr"]
            .map(|name| {
                let mut text = String::new();
                if let Ok(file) = File::open(self.directory.join(name)) {
                    let _ = file.take(64 * 1024).read_to_string(&mut text);
                }
                text
            })
            .join("\n")
    }
    fn finish(mut self) {
        let deadline = Instant::now() + HOST_TIMEOUT;
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.child.take();
                assert!(exit.success(), "Names host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                if self.owned_group.is_some() {
                    assert_eq!(report["surf_bridge_reads_and_orphan_fallback"], true);
                } else {
                    assert_eq!(report["cli_reads_and_orphan_fallback"], true);
                }
                assert_eq!(report["normal_service_joins_returned"], true);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Names host exceeded 90s; kill/reap is abnormal cleanup, not a normal Service join; {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(group) = self.owned_group.take() {
            kill_owned_group(group);
        }
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                result => {
                    eprintln!("Names host cleanup/reap exceeded bound: {result:?}");
                    return;
                }
            }
        }
    }
}

struct Source {
    branch: Mutex<Vec<Block>>,
    calls: AtomicUsize,
}
impl Source {
    fn at(&self, height: u64) -> Result<Block, Error> {
        let index = height
            .checked_sub(FIRST_HEIGHT)
            .and_then(|h| usize::try_from(h).ok())
            .ok_or_else(|| Error::Invalid("mock height below start".into()))?;
        self.branch
            .lock()
            .unwrap()
            .get(index)
            .cloned()
            .ok_or_else(|| Error::Invalid("mock height unavailable".into()))
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
    fn selected(&self, blocks: Vec<Block>) {
        let mut branch = self.branch.lock().unwrap();
        assert_eq!(blocks.len(), branch.len());
        assert_eq!(blocks[0].block_hash(), branch[0].block_hash());
        for pair in blocks.windows(2) {
            assert_eq!(pair[1].header.prev_blockhash, pair[0].block_hash());
        }
        *branch = blocks;
    }
}
impl ChainSource for Source {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Chain::BitcoinRegtest.genesis().unwrap().0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let branch = self.branch.lock().unwrap();
        Ok(point(
            FIRST_HEIGHT + branch.len() as u64 - 1,
            branch.last().unwrap(),
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
    index: NamesIndex,
}
impl Fixture {
    fn new() -> Self {
        let bytes = include_bytes!("../../tests/vectors/names/genesis-administered.record");
        let genesis = signed_record(bytes, [4; 32], 8);
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(bytes).unwrap()).unwrap()
        else {
            panic!("public administered genesis");
        };
        assert_eq!(rules.threshold, 2);
        let Payload::Claim(template) = Payload::from_record(
            &PublicRecord::decode(include_bytes!("../../tests/vectors/names/claim.record"))
                .unwrap(),
        )
        .unwrap() else {
            panic!("public claim corpus");
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
            secret[31] = key; // Public corpus approvers use scalar 11/12, not repeated bytes.
            let author = Keypair::from_seckey_slice(&Secp256k1::new(), &secret)
                .unwrap()
                .x_only_public_key()
                .0;
            assert!(rules.is_approver(&author));
            signed_record(&approval, secret, key + 20)
        });
        // Claims commit after genesis, reveal next block; approval commits and
        // reveals follow. Every record goes through the real scanner/projection.
        let bodies = vec![
            genesis.transactions().to_vec(),
            claims.iter().map(|r| r.commit.clone()).collect(),
            claims.iter().map(|r| r.reveal.clone()).collect(),
            approvals.iter().map(|r| r.commit.clone()).collect(),
            approvals.iter().map(|r| r.reveal.clone()).collect(),
            vec![],
        ];
        let mut blocks = Vec::new();
        for (i, txs) in bodies.iter().enumerate() {
            blocks.push(witness_block(txs, blocks.last(), 20100 + i as u32));
        }
        let config = ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: point(FIRST_HEIGHT, &blocks[0]),
            retention: Retention::Unpruned,
        };
        let mut index = NamesIndex::new(
            NETWORK,
            config.chain.genesis().unwrap().0.to_string(),
            blocks[0].block_hash().to_string(),
            Registry::new(genesis.id(), FIRST_HEIGHT, rules).unwrap(),
        );
        index.blocks.push(Checkpoint {
            height: FIRST_HEIGHT,
            hash: blocks[0].block_hash().to_string(),
        });
        let source = Arc::new(Source {
            branch: Mutex::new(blocks.clone()),
            calls: AtomicUsize::new(0),
        });
        Self {
            genesis: genesis.id(),
            blocks,
            source,
            config,
            index,
        }
    }
    fn seed(&self, path: &Path) -> Arc<Engine> {
        let engine =
            Arc::new(Engine::open(path, self.config.clone(), Some(self.source.clone())).unwrap());
        engine.synchronize_headers().unwrap();
        for _ in &self.blocks {
            engine.scan_next().unwrap();
        }
        engine
            .register_names(self.genesis, self.config.application_start)
            .unwrap();
        for offset in 1..=4 {
            let step = engine.names_step(self.genesis).unwrap();
            assert_eq!(
                step.applied,
                Some(point(FIRST_HEIGHT + offset, &self.blocks[offset as usize]))
            );
            if offset == 2 {
                assert_eq!(step.outcomes.len(), 2);
                assert!(step.outcomes.iter().all(|o| o.verdict == Verdict::Pending));
            }
        }
        assert!(
            matches!(
                engine
                    .names_resolve(self.genesis, &Name::parse("alpha").unwrap())
                    .unwrap()
                    .resolution,
                Resolution::Bound(_)
            ),
            "signed approval threshold must bind alpha"
        );
        assert_eq!(
            engine
                .names_resolve(self.genesis, &Name::parse("bravo").unwrap())
                .unwrap()
                .resolution,
            Resolution::Unbound
        );
        engine
    }
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
        let response = http(self.address, &request("POST", "/v1/shutdown", &auth()));
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

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            while Instant::now() < deadline {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => thread::sleep(Duration::from_millis(5)),
                    Err(error) => {
                        eprintln!("CLI reap: {error}");
                        return;
                    }
                }
            }
            eprintln!("CLI reap exceeded bound");
        }
    }
}
fn invoke(
    control: &Path,
    registry: Txid,
    index: &Path,
    command: &str,
    name: Option<&str>,
    rpc: SocketAddr,
) -> Value {
    let out = control.join("cli-stdout");
    let err = control.join("cli-stderr");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_urma"));
    cmd.env_clear()
        .current_dir(control)
        .env("HOME", control.join("home"))
        .env("TMPDIR", control)
        .env("URMA_CONFIG", control.join("config.json"))
        .env("URMA_OUTPUT", "json")
        .env("URMA_LOG_OUTPUT", "stderr")
        .env("URMA_NAMES_DIR", control.join("default-names-indexes"))
        .env("URMA_RPC_URL", format!("http://{rpc}/"))
        .env("URMA_NODE_AUTH_FILE", control.join("rpc-cookie"))
        .args(["names", command, "--network", NETWORK, "--index"])
        .arg(index)
        .arg("--registry")
        .arg(registry.to_string());
    if let Some(name) = name {
        cmd.arg(name);
    }
    let mut child = OwnedChild(Some(
        cmd.stdin(Stdio::null())
            .stdout(File::create(&out).unwrap())
            .stderr(File::create(&err).unwrap())
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(12);
    let exit = loop {
        if let Some(exit) = child.0.as_mut().unwrap().try_wait().unwrap() {
            child.0.take();
            break exit;
        }
        assert!(Instant::now() < deadline, "CLI deadline exceeded");
        thread::sleep(Duration::from_millis(5));
    };
    for path in [&out, &err] {
        assert!(
            fs::metadata(path).unwrap().len() < 1024 * 1024,
            "CLI log bound"
        );
    }
    let stderr = fs::read_to_string(err).unwrap();
    assert!(!stderr.contains(TOKEN), "fixture bearer leaked to CLI logs");
    assert!(exit.success(), "CLI failed: {exit}; {stderr}");
    serde_json::from_slice(&fs::read(out).unwrap()).unwrap()
}

fn pending(page: &NamesPage) -> BTreeMap<Txid, PendingRecord> {
    assert!(
        page.next.is_none(),
        "this fixture fits one real page; no multipage claim"
    );
    page.entries
        .iter()
        .filter_map(|entry| match entry {
            NamesEntry::Pending { txid, record } => Some((*txid, record.clone())),
            _ => None,
        })
        .collect()
}
fn pending_rows(rows: &BTreeMap<Txid, PendingRecord>, name: Option<&Name>) -> Vec<Value> {
    // Legacy CLI TXID order, distinct from Service displayed-hex cursor order.
    rows.iter()
        .filter(|(_, row)| name.is_none_or(|name| row.name == *name))
        .map(|(txid, record)| json!({"txid":txid.to_string(),"record":record}))
        .collect()
}
fn expected_resolve(engine: &Engine, page: &NamesPage, name: &Name) -> Value {
    let resolved = engine.names_resolve(page.status.genesis, name).unwrap();
    assert_eq!(json!(resolved.status), json!(page.status));
    json!({"network":NETWORK,"registry":page.status.genesis.to_string(),
        "genesis_height":page.status.genesis_block.height,"height":page.status.projected.height,
        "block_hash":page.status.projected.hash.to_string(),"name":name.as_str(),
        "resolution":resolved.resolution,"pending":pending_rows(&pending(page),Some(name)),"locally_cached":true})
}
fn expected_pending(genesis: Txid, height: u64, rows: &BTreeMap<Txid, PendingRecord>) -> Value {
    json!({"network":NETWORK,"registry":genesis.to_string(),"height":height,"pending":pending_rows(rows,None)})
}
fn read_state(engine: &Engine) -> Value {
    // Public global projection revision remains readable even when Names is stale.
    json!({"archive":engine.status().unwrap(),"snapshot":engine.wire_page(None,1).unwrap().snapshot})
}
fn assert_no_rpc(listener: &TcpListener) {
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "CLI unexpectedly connected to the owned RPC trap"
    );
}

fn scenario(control: &Path) {
    stage(control, "seed genuine administered history");
    let fixture = Fixture::new();
    let archive = control.join("archive");
    let engine = fixture.seed(&archive);
    let session = Session::start(engine.clone());
    fs::create_dir(control.join("home")).unwrap();
    for (name, contents) in [("token", TOKEN), ("rpc-cookie", "fixture:fixture")] {
        let path = control.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(
        control.join("config.json"),
        serde_json::to_vec(&json!({"archive":{
        "endpoint":session.address,"token_file":control.join("token")}}))
        .unwrap(),
    )
    .unwrap();
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    rpc.set_nonblocking(true).unwrap();
    let rpc_addr = rpc.local_addr().unwrap();
    let missing_index = control.join("never-created-index.json");
    let page = engine.names_view(fixture.genesis, None, 128).unwrap();
    assert_eq!(page.status.projected.height, 104);
    assert!(
        !page.status.complete_to_tip,
        "CLI must preserve a projection behind selected tip"
    );
    let rows = pending(&page);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.values().filter(|row| row.completed).count(), 1);
    let before = read_state(&engine);
    let source_calls = fixture.source.count();
    stage(
        control,
        "real CLI reads authenticated Service, without local index",
    );
    for name in ["alpha", "bravo"] {
        let normalized = Name::parse(name).unwrap();
        assert_eq!(
            invoke(
                control,
                fixture.genesis,
                &missing_index,
                "resolve",
                Some(name),
                rpc_addr
            ),
            expected_resolve(&engine, &page, &normalized)
        );
    }
    assert_eq!(
        invoke(
            control,
            fixture.genesis,
            &missing_index,
            "pending",
            None,
            rpc_addr
        ),
        expected_pending(fixture.genesis, 104, &rows)
    );
    assert!(!missing_index.exists());
    assert!(!control.join("default-names-indexes").exists());
    assert_eq!(
        fixture.source.count(),
        source_calls,
        "CLI read called chain source"
    );
    assert_eq!(
        read_state(&engine),
        before,
        "CLI changed coverage/evidence/revision"
    );
    assert_eq!(
        json!(engine.names_status(fixture.genesis).unwrap().unwrap()),
        json!(page.status)
    );
    assert_eq!(
        json!(engine.names_view(fixture.genesis, None, 128).unwrap()),
        json!(page)
    );
    assert_no_rpc(&rpc);

    stage(
        control,
        "public reorg preserves genesis but orphans projection104",
    );
    let local_index = control.join("genesis-index.json");
    fixture.index.persist(&local_index).unwrap();
    assert_eq!(NamesIndex::load(&local_index).unwrap(), fixture.index);
    let index_bytes = fs::read(&local_index).unwrap();
    let mut replacement = vec![fixture.blocks[0].clone()];
    for offset in 1..fixture.blocks.len() {
        replacement.push(witness_block(
            &[],
            replacement.last(),
            30100 + offset as u32,
        ));
    }
    fixture.source.selected(replacement);
    engine.synchronize_headers().unwrap();
    assert!(matches!(
        engine.names_status(fixture.genesis),
        Err(Error::Stale)
    ));
    let before = read_state(&engine);
    let source_calls = fixture.source.count();
    let (code, _) = http(
        session.address,
        &request(
            "GET",
            &format!("/v1/names/{}/view?limit=128", fixture.genesis),
            &auth(),
        ),
    )
    .unwrap();
    assert_eq!(
        code, 409,
        "fallback must follow a real orphan-checkpoint refusal"
    );
    let name = Name::parse("alpha").unwrap();
    let index = &fixture.index;
    assert_eq!(index.registry.resolve(&name), Resolution::Unbound);
    stage(
        control,
        "same CLI configuration falls back to owned genesis index",
    );
    assert_eq!(
        invoke(
            control,
            fixture.genesis,
            &local_index,
            "resolve",
            Some("alpha"),
            rpc_addr
        ),
        json!({"network":NETWORK,"registry":fixture.genesis.to_string(),"genesis_height":100,
            "height":100,"block_hash":index.tip_hash(),"name":"alpha",
            "resolution":index.registry.resolve(&name),"pending":[],"locally_cached":true})
    );
    assert_eq!(
        invoke(
            control,
            fixture.genesis,
            &local_index,
            "pending",
            None,
            rpc_addr
        ),
        expected_pending(fixture.genesis, 100, &BTreeMap::new())
    );
    assert_eq!(
        fs::read(&local_index).unwrap(),
        index_bytes,
        "fallback rewrote local index"
    );
    assert!(!missing_index.exists());
    assert!(!control.join("default-names-indexes").exists());
    assert_eq!(
        fixture.source.count(),
        source_calls,
        "fallback initiated chain acquisition"
    );
    assert_eq!(
        read_state(&engine),
        before,
        "fallback scanned/stepped/mutated archive"
    );
    assert!(matches!(
        engine.names_status(fixture.genesis),
        Err(Error::Stale)
    ));
    assert_no_rpc(&rpc);
    stage(
        control,
        "authenticated shutdown, join, drop and ownership reopen",
    );
    session.finish();
    drop(engine);
    let reopened = Engine::open(&archive, fixture.config, None).unwrap();
    assert_eq!(read_state(&reopened)["archive"], before["archive"]);
    drop(reopened);
}

#[test]
#[ignore = "owned subprocess host for actual Service and real CLI"]
fn names_archive_service_host() {
    let control =
        PathBuf::from(std::env::var_os("U3_NAMES_ARCHIVE_SERVICE_TEMP").expect("owned TEMP"));
    let receipt = match std::env::var_os("U3_NAMES_ARCHIVE_SERVICE_CASE") {
        None => {
            scenario(&control);
            json!({"cli_reads_and_orphan_fallback":true,"normal_service_joins_returned":true})
        }
        Some(case) if case == "surf" => {
            surf_scenario(&control);
            json!({"surf_bridge_reads_and_orphan_fallback":true,"normal_service_joins_returned":true})
        }
        Some(case) => panic!("unknown owned Names host case: {case:?}"),
    };
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}

#[test]
fn real_names_service_cli_reads_exact_projection_then_falls_back_without_acquisition() {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "names_archive_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_NAMES_ARCHIVE_SERVICE_TEMP", directory.path())
        .env("TMPDIR", directory.path())
        .stdin(Stdio::null())
        .stdout(File::create(directory.path().join("stdout")).unwrap())
        .stderr(File::create(directory.path().join("stderr")).unwrap())
        .spawn()
        .unwrap();
    Host {
        child: Some(child),
        directory: directory.path().to_owned(),
        owned_group: None,
    }
    .finish();
}

// Only signal the process group created by this test's process_group(0).
// The outer parent is outside that group, so cleanup also reaches a CLI child
// still inside the bridge's g_spawn_sync. Reap the owned host in Host::drop;
// this does not claim that Rust can waitpid arbitrary non-child descendants.
fn kill_owned_group(group: u32) {
    assert!(group > 1 && group <= i32::MAX as u32, "invalid owned PGID");
    let mut command = Command::new("/bin/kill");
    command
        .env_clear()
        .args(["-KILL", "--", &format!("-{group}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut killer = match command.spawn() {
        Ok(child) => OwnedChild(Some(child)),
        Err(error) => {
            eprintln!("cannot signal owned Surf host group {group}: {error}");
            return;
        }
    };
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match killer.0.as_mut().unwrap().try_wait() {
            Ok(Some(exit)) => {
                killer.0.take();
                // A group already gone after normal exit is also expected.
                if !matches!(exit.code(), Some(0 | 1)) {
                    eprintln!("owned Surf group kill helper failed: {exit}");
                }
                return;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            other => {
                eprintln!("owned Surf group kill/reap exceeded bound or failed: {other:?}");
                return; // OwnedChild bounds cleanup of the kill helper itself.
            }
        }
    }
}

fn required_surf_bridge() -> PathBuf {
    let path = std::env::var_os("URMA_SURF_BRIDGE")
        .expect("explicit Surf integration requires URMA_SURF_BRIDGE; no automatic skip");
    let path =
        fs::canonicalize(path).expect("URMA_SURF_BRIDGE must name an existing external bridge");
    let metadata = fs::metadata(&path).unwrap();
    assert!(metadata.is_file(), "URMA_SURF_BRIDGE must be a file");
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "URMA_SURF_BRIDGE must be executable"
    );
    path
}

fn invoke_surf_bridge(
    control: &Path,
    registry: Txid,
    rpc: SocketAddr,
    expected_code: i32,
) -> String {
    let bridge = required_surf_bridge();
    let out = control.join("bridge-stdout");
    let err = control.join("bridge-stderr");
    let mut command = Command::new(bridge);
    command
        .env_clear()
        .current_dir(control)
        .env("HOME", control.join("home"))
        .env("TMPDIR", control)
        .env("XDG_DATA_HOME", control.join("data"))
        .env("XDG_STATE_HOME", control.join("state"))
        .env("XDG_CONFIG_HOME", control.join("xdg-config"))
        .env("XDG_CACHE_HOME", control.join("cache"))
        .env("LANG", "C")
        .env("GIO_USE_VFS", "local")
        .env("GSETTINGS_BACKEND", "memory")
        .env("URMA_SURF_REGTEST", "1")
        .env("URMA_BIN", env!("CARGO_BIN_EXE_urma"))
        .env("URMA_CONFIG", control.join("config.json"))
        .env("URMA_LOG_OUTPUT", "stderr")
        .env("URMA_NAMES_DIR", control.join("surf-names"))
        .env("URMA_WEB_STORE", control.join("web-store"))
        .env("URMA_RPC_URL", format!("http://{rpc}/"))
        .env("URMA_NODE_AUTH_FILE", control.join("rpc-cookie"))
        .env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
        .env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
        .args(["resolve", "rbtc", "alpha"])
        .arg(registry.to_string());
    // No separate group here: bridge -> CLI remains in the outer owned host
    // group. An abnormal host result/timeout triggers group cleanup in parent.
    let mut child = OwnedChild(Some(
        command
            .stdin(Stdio::null())
            .stdout(File::create(&out).unwrap())
            .stderr(File::create(&err).unwrap())
            .spawn()
            .expect("external Surf bridge spawn"),
    ));
    let deadline = Instant::now() + Duration::from_secs(12);
    let exit = loop {
        if let Some(exit) = child.0.as_mut().unwrap().try_wait().unwrap() {
            child.0.take();
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "Surf bridge exceeded owned deadline"
        );
        thread::sleep(Duration::from_millis(5));
    };
    for path in [&out, &err] {
        assert!(
            fs::metadata(path).unwrap().len() < 1024 * 1024,
            "bridge log bound"
        );
    }
    let stdout = fs::read_to_string(out).unwrap();
    let stderr = fs::read_to_string(err).unwrap();
    for marker in [
        "AddressSanitizer",
        "LeakSanitizer",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
    ] {
        assert!(
            !stdout.contains(marker) && !stderr.contains(marker),
            "Surf bridge sanitizer diagnostic: {stdout}; {stderr}"
        );
    }
    assert_eq!(
        exit.code(),
        Some(expected_code),
        "Surf bridge must exit normally with the exact expected code: {exit}; {stdout}; {stderr}"
    );
    stdout
}

fn surf_scenario(control: &Path) {
    required_surf_bridge(); // Missing dependency is an explicit failure in host too.
    stage(
        control,
        "seed genuine Names fixture for external Surf bridge",
    );
    let fixture = Fixture::new();
    let archive = control.join("archive");
    let engine = fixture.seed(&archive);
    let session = Session::start(engine.clone());
    fs::create_dir(control.join("home")).unwrap();
    for (name, contents) in [("token", TOKEN), ("rpc-cookie", "fixture:fixture")] {
        let path = control.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(
        control.join("config.json"),
        serde_json::to_vec(&json!({"archive":{
        "endpoint":session.address,"token_file":control.join("token")}}))
        .unwrap(),
    )
    .unwrap();
    let rpc = TcpListener::bind("127.0.0.1:0").unwrap();
    rpc.set_nonblocking(true).unwrap();
    let rpc_addr = rpc.local_addr().unwrap();
    let names = control.join("surf-names");
    let local_index = names
        .join(NETWORK)
        .join(format!("{}.json", fixture.genesis));
    assert!(!names.exists());
    let page = engine.names_view(fixture.genesis, None, 128).unwrap();
    assert!(!page.status.complete_to_tip);
    let Resolution::Bound(bound) = engine
        .names_resolve(fixture.genesis, &Name::parse("alpha").unwrap())
        .unwrap()
        .resolution
    else {
        panic!("fixture alpha must be bound");
    };
    let Target::Publication(target) = bound.target else {
        panic!("fixture must name a publication");
    };
    let before = read_state(&engine);
    let source_calls = fixture.source.count();
    stage(
        control,
        "external Surf bridge resolves without a local index",
    );
    assert_eq!(
        invoke_surf_bridge(control, fixture.genesis, rpc_addr, 0).trim_end(),
        format!("resolved=1 txid={target} err=")
    );
    assert!(
        !names.exists(),
        "healthy archive resolve created a local Names index"
    );
    assert!(!control.join("cache").exists());
    assert!(!control.join("web-store").exists());
    assert_eq!(fixture.source.count(), source_calls);
    assert_eq!(read_state(&engine), before);
    assert_eq!(
        json!(engine.names_view(fixture.genesis, None, 128).unwrap()),
        json!(page)
    );
    assert_no_rpc(&rpc);

    stage(control, "orphan projection through public selected reorg");
    fs::create_dir_all(local_index.parent().unwrap()).unwrap();
    fixture.index.persist(&local_index).unwrap();
    assert_eq!(NamesIndex::load(&local_index).unwrap(), fixture.index);
    assert_eq!(
        fixture
            .index
            .registry
            .resolve(&Name::parse("alpha").unwrap()),
        Resolution::Unbound
    );
    let index_bytes = fs::read(&local_index).unwrap();
    let mut replacement = vec![fixture.blocks[0].clone()];
    for offset in 1..fixture.blocks.len() {
        replacement.push(witness_block(
            &[],
            replacement.last(),
            40100 + offset as u32,
        ));
    }
    fixture.source.selected(replacement);
    engine.synchronize_headers().unwrap();
    assert!(matches!(
        engine.names_status(fixture.genesis),
        Err(Error::Stale)
    ));
    let before = read_state(&engine);
    let source_calls = fixture.source.count();
    let (code, _) = http(
        session.address,
        &request(
            "GET",
            &format!("/v1/names/{}/view?limit=128", fixture.genesis),
            &auth(),
        ),
    )
    .unwrap();
    assert_eq!(
        code, 409,
        "real orphan checkpoint must refuse before fallback"
    );
    stage(
        control,
        "external Surf bridge refuses Unbound from genuine local fallback",
    );
    assert_eq!(
        invoke_surf_bridge(control, fixture.genesis, rpc_addr, 1).trim_end(),
        format!(
            "resolved=0 txid= err=alpha.rbtc is Unbound in registry {:.12}…",
            fixture.genesis.to_string()
        )
    );
    assert_eq!(fs::read(&local_index).unwrap(), index_bytes);
    assert!(!control.join("cache").exists());
    assert!(!control.join("web-store").exists());
    assert_eq!(fixture.source.count(), source_calls);
    assert_eq!(read_state(&engine), before);
    assert!(matches!(
        engine.names_status(fixture.genesis),
        Err(Error::Stale)
    ));
    assert_no_rpc(&rpc);
    stage(
        control,
        "Surf host authenticated shutdown/join and ownership reopen",
    );
    session.finish();
    drop(engine);
    let reopened = Engine::open(&archive, fixture.config, None).unwrap();
    assert_eq!(read_state(&reopened)["archive"], before["archive"]);
}

#[test]
#[ignore = "requires operator-built external Surf bridge in URMA_SURF_BRIDGE; no GUI"]
fn real_surf_bridge_names_archive_then_local_fallback_without_acquisition() {
    let bridge = required_surf_bridge();
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "names_archive_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_NAMES_ARCHIVE_SERVICE_TEMP", directory.path())
        .env("U3_NAMES_ARCHIVE_SERVICE_CASE", "surf")
        .env("URMA_SURF_BRIDGE", bridge)
        .env("TMPDIR", directory.path())
        .stdin(Stdio::null())
        .stdout(File::create(directory.path().join("stdout")).unwrap())
        .stderr(File::create(directory.path().join("stderr")).unwrap())
        .process_group(0);
    let child = command.spawn().unwrap();
    let group = child.id(); // process_group(0) makes this new child its group leader.
    Host {
        child: Some(child),
        directory: directory.path().to_owned(),
        owned_group: Some(group),
    }
    .finish();
}
