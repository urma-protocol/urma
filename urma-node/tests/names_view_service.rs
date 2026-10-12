//! Authenticated paged Names reads through actual Service.run(false).
//! Genuine Taproot signatures and witness-integrity-valid blocks establish fixture
//! evidence; mock selection does not claim PoW, script, UTXO or full consensus.
//! The owned subprocess bounds abnormal cleanup, not hard cancellation of I/O.
#[allow(dead_code)]
mod common;

use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    block::Header,
    hashes::{Hash, sha256},
    opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
    script::{Builder, PushBytesBuf},
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
};
use common::{FIRST_HEIGHT, MemorySource, config, point, readonly_archive, vector, witness_block};
use rusqlite::types::Value as SqlValue;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_core::{
    envelope,
    format::{PublicRecord, Urma},
    multipart::VerifiedRecord,
};
use urma_names::{name::Name, payload::Payload, state::Verdict};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveConfig, ChainPoint, Retention},
    names::{NamesCursor, NamesEntry, NamesPage},
    service::Service,
    source::ChainSource,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_TIMEOUT: Duration = Duration::from_secs(45);

fn value<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn stage(control: &Path, text: &str) {
    fs::write(control.join("stage"), text).unwrap();
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<SqlValue>>>,
}

// Read-only inspection follows Service shutdown/join and Engine release.
fn snapshot(directory: &Path) -> Snapshot {
    let db = readonly_archive(directory);
    let schema: Vec<(String, String, String, Option<String>)> = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables = schema
        .iter()
        .filter(|row| row.0 == "table")
        .map(|row| {
            let name = &row.1;
            let quoted = format!("\"{}\"", name.replace('"', "\"\""));
            let mut statement = db
                .prepare(&format!("SELECT * FROM {quoted} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, SqlValue>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name.clone(), rows)
        })
        .collect();
    Snapshot {
        version: db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap(),
        schema,
        tables,
    }
}

struct CountedSource {
    inner: MemorySource,
    calls: AtomicUsize,
}

impl CountedSource {
    fn new(blocks: &[Block]) -> Self {
        Self {
            inner: MemorySource::new(blocks),
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

// Count every source method, including genesis/tip, without changing common.
impl ChainSource for CountedSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.genesis()
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.tip()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.header(height)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.block(height)
    }
}

// Same public Names corpus and genuine Taproot/BIP340 construction as the
// Names projection tests; no VerifiedRecord/scan mark/undo frame is fabricated.
fn signed_record(bytes: &[u8], seed: u8, tag: u8) -> Signed {
    Payload::from_record(&PublicRecord::decode(bytes).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let signer = Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
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
struct Seed {
    directory: PathBuf,
    config: ArchiveConfig,
    genesis: Txid,
    other: Txid,
    unregistered: Txid,
    claims: [Signed; 2],
    blocks: Vec<Block>,
    source: Arc<CountedSource>,
}
impl Seed {
    fn new(control: &Path) -> Self {
        let genesis_bytes = vector("names/genesis-administered.record");
        let genesis = signed_record(&genesis_bytes, 4, 8);
        let other = signed_record(&genesis_bytes, 4, 9);
        let unregistered = signed_record(&genesis_bytes, 4, 10);
        let Payload::Claim(template) =
            Payload::from_record(&PublicRecord::decode(&vector("names/claim.record")).unwrap())
                .unwrap()
        else {
            panic!("public claim corpus");
        };
        let claims = ["alpha", "bravo"].map(|name| {
            let mut claim = template.clone();
            claim.registry = genesis.id();
            claim.name = Name::parse(name).unwrap();
            signed_record(
                &Payload::Claim(claim).to_record().unwrap().encode().unwrap(),
                5,
                if name == "alpha" { 11 } else { 12 },
            )
        });
        let first = witness_block(
            &[genesis.transactions(), unregistered.transactions()].concat(),
            None,
            10100,
        );
        // Genuine Names placement: commits AFTER genesis and reveals one block
        // later. No SQL rows, outcomes, signatures or inclusion are fabricated.
        let second = witness_block(
            &[
                other.transactions().to_vec(),
                claims.iter().map(|claim| claim.commit.clone()).collect(),
            ]
            .concat(),
            Some(&first),
            10101,
        );
        let third = witness_block(
            &claims
                .iter()
                .map(|claim| claim.reveal.clone())
                .collect::<Vec<_>>(),
            Some(&second),
            10102,
        );
        let fourth = witness_block(&[], Some(&third), 10103);
        let blocks = vec![first, second, third, fourth];
        let source = Arc::new(CountedSource::new(&blocks));
        let directory = control.join("archive");
        let config = config(&blocks[0], Retention::Unpruned);
        let engine = Engine::open(&directory, config.clone(), Some(source.clone())).unwrap();
        engine.synchronize_headers().unwrap();
        for _ in &blocks {
            engine.scan_next().unwrap();
        }
        engine
            .register_names(genesis.id(), point(FIRST_HEIGHT, &blocks[0]))
            .unwrap();
        engine
            .register_names(other.id(), point(FIRST_HEIGHT + 1, &blocks[1]))
            .unwrap();
        let empty = engine.names_step(genesis.id()).unwrap();
        assert_eq!(empty.applied, Some(point(FIRST_HEIGHT + 1, &blocks[1])));
        assert!(empty.outcomes.is_empty());
        let populated = engine.names_step(genesis.id()).unwrap();
        assert_eq!(populated.applied, Some(point(FIRST_HEIGHT + 2, &blocks[2])));
        assert_eq!(populated.outcomes.len(), 2);
        assert!(
            populated
                .outcomes
                .iter()
                .all(|outcome| outcome.verdict == Verdict::Pending),
            "fixture claims must be admitted"
        );
        let page = engine.names_view(genesis.id(), None, 128).unwrap();
        assert!(
            page.entries.len() > 1,
            "fixture must exercise a real continuation"
        );
        assert!(page.next.is_none());
        assert!(!page.status.complete_to_tip);
        assert!(engine.record(unregistered.id()).unwrap().is_some());
        assert!(engine.names_status(unregistered.id()).unwrap().is_none());
        drop(engine);
        Self {
            directory,
            config,
            genesis: genesis.id(),
            other: other.id(),
            unregistered: unregistered.id(),
            claims,
            blocks,
            source,
        }
    }
    fn path(&self, id: Txid, query: &str) -> String {
        format!("/v1/names/{id}/view?{query}")
    }
    fn view(&self, limit: u32) -> String {
        self.path(self.genesis, &format!("limit={limit}"))
    }
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

struct Session {
    address: SocketAddr,
    engine: Option<Arc<Engine>>,
    source: Arc<CountedSource>,
    control: PathBuf,
    worker: Option<JoinHandle<Result<(), Error>>>,
}

impl Session {
    fn start(seed: &Seed, control: &Path) -> Self {
        let engine = Arc::new(
            Engine::open(
                &seed.directory,
                seed.config.clone(),
                Some(seed.source.clone()),
            )
            .unwrap(),
        );
        let service =
            Service::bind("127.0.0.1:0".parse().unwrap(), TOKEN.into(), engine.clone()).unwrap();
        let address = service.address().unwrap();
        let worker = thread::spawn(move || service.run(false));
        Self {
            address,
            engine: Some(engine),
            source: seed.source.clone(),
            control: control.to_owned(),
            worker: Some(worker),
        }
    }
    fn engine(&self) -> &Engine {
        self.engine.as_ref().unwrap()
    }
    fn call(&self, method: &str, path: &str, headers: &str, expected: u16) -> Value {
        stage(
            &self.control,
            &format!("{method} {path}: expect {expected}"),
        );
        let before = serde_json::to_value(self.engine().status().unwrap()).unwrap();
        let source_calls = self.source.calls();
        let (code, body) = http(self.address, &request(method, path, headers)).unwrap();
        assert_eq!(code, expected, "{method} {path}: {body}");
        if expected != 200 {
            assert!(body["error"].is_string());
        }
        assert_eq!(
            serde_json::to_value(self.engine().status().unwrap()).unwrap(),
            before,
            "Names route changed archive coverage/evidence"
        );
        assert_eq!(
            self.source.calls(),
            source_calls,
            "Names route called the chain source"
        );
        body
    }
    fn page(&self, seed: &Seed, id: Txid, cursor: Option<&NamesCursor>, limit: u32) -> NamesPage {
        let query = match cursor {
            Some(cursor) => format!("limit={limit}&cursor={}", cursor_hex(cursor)),
            None => format!("limit={limit}"),
        };
        let expected = self.engine().names_view(id, cursor, limit).unwrap();
        let body = self.call("GET", &seed.path(id, &query), &auth(), 200);
        let page: NamesPage = serde_json::from_value(body.clone()).unwrap();
        let shared: urma_node_client::names::NamesPage =
            serde_json::from_value(body.clone()).unwrap();
        assert_eq!(value(&page), body);
        assert_eq!(value(shared), body);
        assert_eq!(
            value(expected),
            body,
            "HTTP differs from the exact public Engine page"
        );
        assert_eq!(page.chain_genesis, seed.config.chain.genesis().unwrap().0);
        assert_eq!(page.status.genesis, id);
        assert_eq!(
            value(&page.status),
            value(self.engine().names_status(id).unwrap().unwrap())
        );
        page
    }
    fn cleanup(&mut self) -> Result<(), String> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let shutdown = http(self.address, &request("POST", "/v1/shutdown", &auth()))
            .map_err(|e| e.to_string());
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !worker.is_finished() {
            return Err("Service shutdown/join exceeded harness cleanup bound".into());
        }
        worker
            .join()
            .map_err(|_| "Service thread panicked".to_owned())?
            .map_err(|e| e.to_string())?;
        match shutdown {
            Ok((200, body)) if body == json!({"stopping":true}) => Ok(()),
            result => Err(format!("authenticated shutdown failed: {result:?}")),
        }
    }
    fn finish(mut self) {
        self.cleanup().unwrap();
        let weak = Arc::downgrade(self.engine.as_ref().unwrap());
        drop(self.engine.take());
        assert!(
            weak.upgrade().is_none(),
            "Service retained Engine after joined shutdown"
        );
        assert!(
            TcpStream::connect_timeout(&self.address, Duration::from_millis(200)).is_err(),
            "Service listener remains open"
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("bounded Service cleanup: {error}");
        }
        // Rust cannot kill a timed-out worker thread. The owning host subprocess
        // is supervised below; abnormal termination is not a normal Service join.
    }
}

fn cursor_hex(cursor: &NamesCursor) -> String {
    let encoded = hex::encode(serde_json::to_vec(cursor).unwrap());
    assert_eq!(
        serde_json::from_slice::<NamesCursor>(&hex::decode(&encoded).unwrap()).unwrap(),
        *cursor
    );
    encoded
}
fn continuation(seed: &Seed, cursor: &NamesCursor) -> String {
    seed.path(
        seed.genesis,
        &format!("limit=1&cursor={}", cursor_hex(cursor)),
    )
}

fn pages(control: &Path) {
    let seed = Seed::new(control);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let full = session.page(&seed, seed.genesis, None, 128);
    assert_eq!(
        full.status.projected,
        point(FIRST_HEIGHT + 2, &seed.blocks[2])
    );
    assert_eq!(
        full.status.selected_tip,
        Some(point(FIRST_HEIGHT + 3, &seed.blocks[3]))
    );
    assert!(full.next.is_none());
    assert!(
        !full.status.complete_to_tip,
        "end of local rows must not claim tip projection"
    );
    let Payload::Genesis(rules) = Payload::from_record(
        &PublicRecord::decode(&vector("names/genesis-administered.record")).unwrap(),
    )
    .unwrap() else {
        unreachable!()
    };
    assert_eq!(full.rules, rules);
    // Check fixture-derived bytes survived JSON serialization, without
    // re-testing Engine phase/order, approvals, expiry or retained-state policy.
    for claim in &seed.claims {
        let pending = full
            .entries
            .iter()
            .find_map(|entry| match entry {
                NamesEntry::Pending { txid, record } if *txid == claim.id() => Some(record),
                _ => None,
            })
            .expect("genuine signed claim present in page");
        assert_eq!(
            pending.sha256,
            sha256::Hash::hash(&claim.bytes).to_byte_array()
        );
    }
    let first = session.page(&seed, seed.genesis, None, 1);
    assert_eq!(first.entries.len(), 1);
    assert!(first.next.is_some());
    let mut entries = first.entries.clone();
    let mut cursor = first.next;
    let mut requests = 1;
    while let Some(next) = cursor {
        assert!(
            requests < 8,
            "bounded fixture traversal failed to terminate"
        );
        let page = session.page(&seed, seed.genesis, Some(&next), 1);
        assert_eq!(page.snapshot, full.snapshot);
        assert_eq!(value(&page.status), value(&full.status));
        assert_eq!(page.rules, full.rules);
        entries.extend(page.entries);
        cursor = page.next;
        requests += 1;
    }
    assert_eq!(entries, full.entries);
    assert!(requests > 1);
    assert!(
        session
            .engine()
            .names_status(seed.unregistered)
            .unwrap()
            .is_none()
    );
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "paged read registered/stepped/mutated archive"
    );
}

fn refusals(control: &Path) {
    let seed = Seed::new(control);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let first = session.page(&seed, seed.genesis, None, 1);
    let cursor = first.next.as_ref().unwrap();
    let encoded = cursor_hex(cursor);
    for path in [seed.view(1), continuation(&seed, cursor)] {
        session.call("GET", &path, "", 401);
        session.call("GET", &path, "Authorization: Bearer wrong\r\n", 401);
        session.call("GET", &path, &(auth() + "Content-Length: 1\r\n"), 400);
        session.call(
            "GET",
            &path,
            &(auth() + "Transfer-Encoding: chunked\r\n"),
            400,
        );
    }
    let malformed_path = "/v1/names/not-a-txid/view?limit=bad";
    session.call("GET", malformed_path, "", 401);
    session.call("GET", malformed_path, &auth(), 400);
    let mut queries = vec![
        "".to_owned(),
        "limit".into(),
        "limit=".into(),
        "limit=0".into(),
        "limit=129".into(),
        "limit=-1".into(),
        "limit=+1".into(),
        "limit=1.0".into(),
        "limit=4294967296".into(),
        "Limit=1".into(),
        "limit=1&limit=1".into(),
        "limit=1&other=1".into(),
        "limit=1&".into(),
        "cursor=00".into(),
        "limit=1&cursor=".into(),
        "limit=1&cursor=0".into(),
        "limit=1&cursor=gg".into(),
        "limit=1&cursor=%7B".into(),
        "limit=1&cursor=7b".into(),
        format!("limit=1&cursor={encoded}&cursor={encoded}"),
        format!("limit=1&cursor={}", "00".repeat(513)),
    ];
    for changed in 0..8 {
        let mut bad = value(cursor);
        match changed {
            0 => bad["extra"] = true.into(),
            1 => bad["snapshot"]["extra"] = true.into(),
            2 => bad["snapshot"]["instance"] = "short".into(),
            3 => bad["snapshot"]["instance"] = "g".repeat(32).into(),
            4 => bad["after"] = json!({"Name":"UPPER"}),
            5 => bad["after"] = json!({"Pending":"gg"}),
            6 => bad["genesis"] = "00".into(),
            7 => bad["snapshot"]["revision"] = "overflow".into(),
            _ => unreachable!(),
        }
        queries.push(format!(
            "limit=1&cursor={}",
            hex::encode(serde_json::to_vec(&bad).unwrap())
        ));
    }
    for query in queries {
        session.call("GET", &seed.path(seed.genesis, &query), &auth(), 400);
    }
    // Both registries exist: a valid cursor for one cannot traverse the other.
    session.call(
        "GET",
        &seed.path(seed.other, &format!("limit=1&cursor={encoded}")),
        &auth(),
        400,
    );
    let mut rebound = cursor.clone();
    rebound.genesis = seed.other;
    session.call("GET", &continuation(&seed, &rebound), &auth(), 400);
    // Authentic local genesis without registration is an error, never an empty
    // successful page, and a read cannot choose a registry implicitly.
    session.call(
        "GET",
        &seed.path(seed.unregistered, "limit=1"),
        &auth(),
        422,
    );
    assert!(
        session
            .engine()
            .names_status(seed.unregistered)
            .unwrap()
            .is_none()
    );
    session.call(
        "GET",
        &seed.path(Txid::from_byte_array([78; 32]), "limit=128"),
        &auth(),
        422,
    );
    session.call("POST", &seed.view(1), &auth(), 404);
    session.call(
        "GET",
        &format!("/v1/names/{}/view", seed.genesis),
        &auth(),
        404,
    );
    session.call(
        "GET",
        &format!("/v1/names/{}/view-other?limit=1", seed.genesis),
        &auth(),
        404,
    );
    session.page(&seed, seed.genesis, Some(cursor), 1); // Refusals did not stale it.
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "refused view requests mutated archive"
    );
}

fn same_generation(control: &Path) {
    let seed = Seed::new(control);
    let session = Session::start(&seed, control);
    let first = session.page(&seed, seed.genesis, None, 1);
    let old_cursor = first.next.as_ref().unwrap().clone();
    let archive_before = value(session.engine().status().unwrap());
    let step = session.engine().names_step(seed.genesis).unwrap();
    assert_eq!(step.applied, Some(point(FIRST_HEIGHT + 3, &seed.blocks[3])));
    assert!(step.outcomes.is_empty());
    assert!(step.status.complete_to_tip);
    assert_eq!(step.status.generation, first.status.generation);
    assert_eq!(value(session.engine().status().unwrap()), archive_before);
    // Preserve the Engine instance for the revision-only invalidation control;
    // reopening first would hide it behind restart instance invalidation.
    session.call("GET", &continuation(&seed, &old_cursor), &auth(), 409);
    let fresh = session.page(&seed, seed.genesis, None, 1);
    assert_eq!(fresh.snapshot.instance, first.snapshot.instance);
    assert!(fresh.snapshot.revision > first.snapshot.revision);
    assert_eq!(fresh.status.generation, first.status.generation);
    assert!(fresh.status.complete_to_tip);
    assert_eq!(fresh.entries, first.entries);
    session.page(&seed, seed.genesis, Some(fresh.next.as_ref().unwrap()), 1);
    session.finish();
    let after_step = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    session.call("GET", &continuation(&seed, &old_cursor), &auth(), 409);
    let fresh = session.page(&seed, seed.genesis, None, 1);
    assert!(fresh.status.complete_to_tip);
    session.page(&seed, seed.genesis, Some(fresh.next.as_ref().unwrap()), 1);
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        after_step,
        "stale cursor/fresh read mutated projection"
    );
}

fn restart_orphan(control: &Path) {
    let seed = Seed::new(control);
    let before = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    let original = session.page(&seed, seed.genesis, None, 1);
    let cursor = original.next.as_ref().unwrap().clone();
    session.finish();
    let session = Session::start(&seed, control);
    session.call("GET", &continuation(&seed, &cursor), &auth(), 409);
    let restarted = session.page(&seed, seed.genesis, None, 1);
    assert_ne!(restarted.snapshot.instance, original.snapshot.instance);
    assert_eq!(restarted.snapshot.revision, original.snapshot.revision);
    assert_eq!(restarted.entries, original.entries);
    assert_eq!(value(&restarted.status), value(&original.status));
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        before,
        "restart/stale cursor reads mutated archive"
    );

    let second = witness_block(&[], Some(&seed.blocks[0]), 10201);
    let third = witness_block(&[], Some(&second), 10202);
    let fourth = witness_block(&[], Some(&third), 10203);
    seed.source
        .inner
        .replace_branch(&[seed.blocks[0].clone(), second, third, fourth]);
    let session = Session::start(&seed, control);
    session.engine().synchronize_headers().unwrap();
    assert!(session.engine().status().unwrap().generation > original.status.generation);
    // Application/genesis100 remains selected; projection102 and the separate
    // registered genesis101 are orphaned by the same genuine public selection.
    assert!(matches!(
        session.engine().names_status(seed.genesis),
        Err(Error::Stale)
    ));
    assert!(matches!(
        session.engine().names_status(seed.other),
        Err(Error::Stale)
    ));
    session.finish();
    let after_reorg = snapshot(&seed.directory);
    let session = Session::start(&seed, control);
    session.call("GET", &seed.view(1), &auth(), 409);
    session.call("GET", &seed.path(seed.other, "limit=1"), &auth(), 409);
    session.call("GET", &continuation(&seed, &cursor), &auth(), 409);
    assert!(
        session
            .engine()
            .names_status(seed.unregistered)
            .unwrap()
            .is_none()
    );
    session.finish();
    assert_eq!(
        snapshot(&seed.directory),
        after_reorg,
        "stale/orphan reads stepped or registered implicitly"
    );
}

#[test]
#[ignore = "owned subprocess host for the Names-view-service cases"]
fn names_view_service_host() {
    let control =
        PathBuf::from(std::env::var_os("U3_NAMES_VIEW_SERVICE_TEMP").expect("owned TEMP"));
    let scenario = std::env::var("U3_NAMES_VIEW_SERVICE_CASE").unwrap();
    stage(&control, &format!("seeding actual Engine: {scenario}"));
    match scenario.as_str() {
        "pages" => pages(&control),
        "refusals" => refusals(&control),
        "same-generation" => same_generation(&control),
        "restart-orphan" => restart_orphan(&control),
        _ => panic!("unknown owned scenario"),
    }
    fs::write(
        control.join("result.json"),
        serde_json::to_vec(&json!({"scenario":scenario,"normal_service_joins_returned":true}))
            .unwrap(),
    )
    .unwrap();
}

struct Host {
    child: Option<Child>,
    directory: PathBuf,
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
    fn finish(mut self, scenario: &str) {
        let deadline = Instant::now() + HOST_TIMEOUT;
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.child.take();
                assert!(exit.success(), "Names host failed: {exit}; {}", self.logs());
                let report: Value =
                    serde_json::from_slice(&fs::read(self.directory.join("result.json")).unwrap())
                        .unwrap();
                assert_eq!(report["scenario"], scenario);
                assert_eq!(report["normal_service_joins_returned"], true);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Names host exceeded 45s; kill/reap is abnormal cleanup, not a normal Service join; {}",
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

fn run(scenario: &str) {
    let directory = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "names_view_service_host",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("U3_NAMES_VIEW_SERVICE_TEMP", directory.path())
        .env("U3_NAMES_VIEW_SERVICE_CASE", scenario)
        .env("TMPDIR", directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            File::create(directory.path().join("stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            File::create(directory.path().join("stderr")).unwrap(),
        ))
        .spawn()
        .unwrap();
    // Guard owns child before assertions, and TEMP outlives its cleanup.
    Host {
        child: Some(child),
        directory: directory.path().to_owned(),
    }
    .finish(scenario);
}

#[test]
fn names_view_http_pages_roundtrip_exact_shared_dtos_without_source_calls_or_writes() {
    run("pages");
}
#[test]
fn names_view_http_auth_query_cursor_registry_and_route_refusals_preserve_archive() {
    run("refusals");
}
#[test]
fn names_view_http_same_generation_names_step_invalidates_cursor_without_implicit_progress() {
    run("same-generation");
}
#[test]
fn names_view_http_restart_and_orphan_projection_or_genesis_refuse_stale_reads() {
    run("restart-orphan");
}
