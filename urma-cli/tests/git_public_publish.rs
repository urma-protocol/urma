#[path = "../../urma-runtime/tests/support/wallet_electrum.rs"]
#[allow(dead_code)]
mod wallet_electrum;

use bitcoin::{
    Amount, Network, OutPoint, Transaction, TxIn, TxMerkleNode, TxOut, Txid, absolute,
    block::{Header, Version},
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
    pow::CompactTarget,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version as TxVersion,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use urma_runtime::disk_plan::DiskPlan;
use urma_wallet::account::{Account, KeyPath};
use wallet_electrum::{PHRASE, funder, scripthash};

const FUNDING: u64 = 50_000_000;
const REFUSAL: &str = "mock provider refuses this broadcast";
const ELECTRUM_METHODS: [&str; 6] = [
    "server.version",
    "blockchain.block.header",
    "blockchain.headers.subscribe",
    "blockchain.transaction.get",
    "blockchain.scripthash.listunspent",
    "blockchain.transaction.broadcast",
];

struct Ledger {
    headers: Vec<Header>,
    heights: HashMap<Txid, usize>,
    transactions: Vec<Transaction>,
    accepted: Vec<Txid>,
    refused: Vec<Txid>,
    methods: Vec<String>,
    refusing: bool,
    mining: bool,
}

impl Ledger {
    fn new(account: &Account) -> Self {
        let funding = Transaction {
            version: TxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(FUNDING),
                script_pubkey: account.script(KeyPath::RECEIVE).unwrap(),
            }],
        };
        let mut ledger = Self {
            headers: vec![genesis_block(Network::Regtest).header],
            heights: HashMap::new(),
            transactions: vec![funding.clone()],
            accepted: Vec::new(),
            refused: Vec::new(),
            methods: Vec::new(),
            refusing: false,
            mining: false,
        };
        ledger.mine(vec![funding.compute_txid()]);
        ledger
    }

    fn funding(&self) -> &Transaction {
        &self.transactions[0]
    }

    fn tip(&self) -> usize {
        self.headers.len() - 1
    }

    fn mine(&mut self, txids: Vec<Txid>) {
        let height = self.headers.len();
        let first = txids.first().map(|txid| txid.to_byte_array());
        self.headers.push(Header {
            version: Version::TWO,
            prev_blockhash: self.headers[height - 1].block_hash(),
            merkle_root: TxMerkleNode::from_byte_array(first.unwrap_or_default()),
            time: 1_700_000_000 + u32::try_from(height).unwrap(),
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        });
        for txid in txids {
            self.heights.insert(txid, height);
        }
    }

    fn mine_mempool(&mut self) {
        let pending = self
            .transactions
            .iter()
            .map(Transaction::compute_txid)
            .filter(|txid| !self.heights.contains_key(txid))
            .collect();
        self.mine(pending);
    }

    fn spent(&self, outpoint: OutPoint) -> bool {
        self.transactions.iter().any(|tx| {
            tx.input
                .iter()
                .any(|input| input.previous_output == outpoint)
        })
    }

    fn unspent(&self, key: &str) -> Value {
        let mut rows = Vec::new();
        for tx in &self.transactions {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(txid, u32::try_from(vout).unwrap());
                if scripthash(&output.script_pubkey) != key || self.spent(outpoint) {
                    continue;
                }
                let height = self.heights.get(&txid).copied().unwrap_or(0);
                rows.push(json!({"tx_hash":txid,"tx_pos":vout,"height":height,"value":output.value.to_sat()}));
            }
        }
        Value::Array(rows)
    }

    fn transaction(&self, params: &Value) -> Result<Value, Value> {
        let txid: Txid = params[0].as_str().unwrap().parse().unwrap();
        let Some(tx) = self
            .transactions
            .iter()
            .find(|tx| tx.compute_txid() == txid)
        else {
            return Err(json!({"code":2,"message":"No such mempool or blockchain transaction."}));
        };
        let raw = hex::encode(serialize(tx));
        if params[1] != true {
            return Ok(json!(raw));
        }
        match self.heights.get(&txid) {
            Some(height) => Ok(json!({
                "txid": txid,
                "hex": raw,
                "confirmations": self.tip() - height + 1,
                "blockhash": self.headers[*height].block_hash(),
            })),
            None => Ok(json!({"txid":txid,"hex":raw})),
        }
    }

    fn broadcast(&mut self, params: &Value) -> Result<Value, Value> {
        let raw = hex::decode(params[0].as_str().unwrap()).unwrap();
        let tx: Transaction = deserialize(&raw).unwrap();
        let txid = tx.compute_txid();
        if self.refusing {
            self.refused.push(txid);
            return Err(json!({"code":1,"message":REFUSAL}));
        }
        self.transactions.push(tx);
        self.accepted.push(txid);
        if self.mining {
            self.mine(vec![txid]);
        }
        Ok(json!(txid))
    }

    fn respond(&mut self, method: &str, params: &Value) -> Result<Value, Value> {
        self.methods.push(method.to_owned());
        match method {
            "server.version" => Ok(json!(["MockPublic 1.0", params[1]])),
            "blockchain.block.header" => {
                let height = usize::try_from(params[0].as_u64().unwrap()).unwrap();
                match self.headers.get(height) {
                    Some(header) => Ok(json!(hex::encode(serialize(header)))),
                    None => Err(json!({"code":1,"message":"height out of range"})),
                }
            }
            "blockchain.headers.subscribe" => Ok(
                json!({"height":self.tip(),"hex":hex::encode(serialize(&self.headers[self.tip()]))}),
            ),
            "blockchain.transaction.get" => self.transaction(params),
            "blockchain.scripthash.listunspent" => Ok(self.unspent(params[0].as_str().unwrap())),
            "blockchain.transaction.broadcast" => self.broadcast(params),
            other => Err(json!({"code":-32601,"message":format!("unknown method {other}")})),
        }
    }
}

struct Mock {
    ledger: Arc<Mutex<Ledger>>,
    address: String,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Mock {
    fn start() -> Self {
        let ledger = Arc::new(Mutex::new(Ledger::new(&funder())));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stopped = Arc::new(AtomicBool::new(false));
        let (stop, shared) = (stopped.clone(), ledger.clone());
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let ledger = shared.clone();
                thread::spawn(move || serve(stream.unwrap(), &ledger));
            }
        });
        Self {
            ledger,
            address,
            stopped,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("tcp://{}", self.address)
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _poke = TcpStream::connect(&self.address).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

fn serve(mut stream: TcpStream, ledger: &Mutex<Ledger>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let request: Value = serde_json::from_str(&line).unwrap();
        let method = request["method"].as_str().unwrap();
        let reply = match ledger.lock().unwrap().respond(method, &request["params"]) {
            Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            Err(error) => json!({"jsonrpc":"2.0","id":request["id"],"error":error}),
        };
        if writeln!(stream, "{reply}").is_err() {
            return;
        }
    }
}

struct Workspace {
    root: tempfile::TempDir,
}

fn private_file(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(repo)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

impl Workspace {
    fn new() -> Self {
        let workspace = Self {
            root: tempfile::tempdir().unwrap(),
        };
        private_file(&workspace.path("phrase"), PHRASE);
        private_file(&workspace.path("password"), "public publish test password");
        let vault = workspace.path("identity.vault");
        let recovered = workspace.urma(
            None,
            &[
                "key",
                "recover",
                "--phrase-file",
                workspace.text("phrase").as_str(),
                "--password-file",
                workspace.text("password").as_str(),
                "--output",
                vault.to_str().unwrap(),
            ],
        );
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        let repo = workspace.path("repo");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("README"), "Public non-sensitive test fixture.\n").unwrap();
        git(&repo, &["init", "--quiet"]);
        git(&repo, &["add", "README"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=Public Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "Public fixture",
            ],
        );
        workspace
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn text(&self, name: &str) -> String {
        self.path(name).to_str().unwrap().to_owned()
    }

    fn configure(&self, endpoint: &str) {
        let settings = json!({"public_endpoints":[{"electrum":endpoint}]});
        std::fs::write(self.path("config.json"), settings.to_string()).unwrap();
    }

    fn urma(&self, endpoints: Option<&str>, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env_remove("URMA_RPC_URL")
            .env_remove("URMA_NODE_AUTH_FILE")
            .env_remove("URMA_PUBLIC_ENDPOINTS")
            .env("HOME", self.path("home"))
            .env("XDG_DATA_HOME", self.path("data"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("URMA_CONFIG", self.path("config.json"))
            .env("URMA_NETWORK", "bitcoin-regtest")
            .env("URMA_VAULT", self.path("identity.vault"))
            .env("URMA_UNLOCK_FILE", self.path("password"))
            .args(args)
            .stdin(Stdio::null());
        if let Some(endpoints) = endpoints {
            command.env("URMA_PUBLIC_ENDPOINTS", endpoints);
        }
        command.output().unwrap()
    }

    fn publish(&self, endpoints: Option<&str>, extra: &[&str]) -> Output {
        let (repo, plan) = (self.text("repo"), self.text("plan"));
        let mut args = vec!["git", "publish", repo.as_str(), "--output", plan.as_str()];
        args.extend(extra);
        self.urma(endpoints, &args)
    }

    fn pairs(&self) -> Vec<(Transaction, Transaction)> {
        let plan = DiskPlan::load(&self.path("plan").join("publication")).unwrap();
        let decode = |raw: &str| deserialize(&hex::decode(raw).unwrap()).unwrap();
        (0..plan.record_count)
            .map(|index| {
                let pair = plan.record(index).unwrap();
                (decode(&pair.commit), decode(&pair.reveal))
            })
            .collect()
    }

    fn journal(&self) -> Vec<Value> {
        let path = self.path("plan").join("progress.observations.jsonl");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_locally_signed_from_account(ledger: &Ledger, pairs: &[(Transaction, Transaction)]) {
    let account = funder();
    let zero = account.receive_script().unwrap();
    let funding = ledger.funding();
    let (first, _) = &pairs[0];
    assert!(
        first
            .input
            .iter()
            .all(|input| input.previous_output.txid == funding.compute_txid()),
        "first commit spends coins outside the account"
    );
    let witness = first.input[0].witness.to_vec();
    let key = bitcoin::PublicKey::from_slice(&witness[1]).unwrap();
    let prevout = &funding.output[usize::try_from(first.input[0].previous_output.vout).unwrap()];
    assert_eq!(
        bitcoin::ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap()),
        prevout.script_pubkey
    );
    let digest = SighashCache::new(first)
        .p2wpkh_signature_hash(
            0,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let signature = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
    Secp256k1::new()
        .verify_ecdsa(
            &Message::from_digest(digest.to_byte_array()),
            &signature.signature,
            &key.inner,
        )
        .unwrap();
    for (index, (commit, reveal)) in pairs.iter().enumerate() {
        assert_eq!(
            commit.output[1].script_pubkey, zero,
            "commit {index} change"
        );
        assert_eq!(
            reveal.output[0].script_pubkey, zero,
            "reveal {index} return"
        );
        if index > 0 {
            let previous = OutPoint::new(pairs[index - 1].0.compute_txid(), 1);
            assert_eq!(commit.input[0].previous_output, previous);
        }
    }
}

fn assert_public_publication(workspace: &Workspace, mock: &Mock, order: &[Txid]) {
    let pairs = workspace.pairs();
    let ledger = mock.ledger();
    assert_eq!(ledger.accepted, order);
    assert!(ledger.refused.is_empty());
    let frozen: HashMap<Txid, Transaction> = pairs
        .iter()
        .flat_map(|(commit, reveal)| [commit.clone(), reveal.clone()])
        .map(|tx| (tx.compute_txid(), tx))
        .collect();
    for tx in &ledger.transactions[1..] {
        assert_eq!(serialize(tx), serialize(&frozen[&tx.compute_txid()]));
    }
    assert_locally_signed_from_account(&ledger, &pairs);
    assert!(
        ledger
            .methods
            .iter()
            .all(|method| ELECTRUM_METHODS.contains(&method.as_str())),
        "{:?}",
        ledger.methods
    );
    let journal = workspace.journal();
    assert!(!journal.is_empty());
    for line in &journal {
        assert_eq!(line["source"], "public_provider_observation", "{line}");
        assert_eq!(line["chain"], "bitcoin-regtest", "{line}");
    }
    let progress: Value = serde_json::from_slice(
        &std::fs::read(workspace.path("plan").join("progress.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(progress["complete"], true);
    assert_no_local_node(workspace);
}

fn assert_no_local_node(workspace: &Workspace) {
    let config = std::fs::read_to_string(workspace.path("config.json")).unwrap();
    let settings: Value = serde_json::from_str(&config).unwrap();
    assert_eq!(settings.as_object().unwrap().len(), 1, "{settings}");
    let cache = workspace.path("data").join("urma");
    for entry in std::fs::read_dir(&cache).into_iter().flatten() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            !name.contains("p2p") && !name.contains("header"),
            "light client state {name}"
        );
    }
}

fn commits_then_reveals(pairs: &[(Transaction, Transaction)]) -> (Vec<Txid>, Vec<Txid>) {
    pairs
        .iter()
        .map(|(commit, reveal)| (commit.compute_txid(), reveal.compute_txid()))
        .unzip()
}

#[test]
fn git_publish_without_node_or_core_funds_signs_and_broadcasts_through_public_providers() {
    let workspace = Workspace::new();
    let mock = Mock::start();
    mock.ledger().mining = true;
    workspace.configure(&mock.endpoint());
    let output = workspace.publish(None, &["--yes"]);
    let text = stderr(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("Selected funding: 0.50000000 BTC"), "{text}");
    assert!(
        text.contains("Mempool preflight unavailable from this endpoint"),
        "{text}"
    );
    assert!(text.contains("Target Confirmed reached for all"), "{text}");
    let order: Vec<Txid> = workspace
        .pairs()
        .iter()
        .flat_map(|(commit, reveal)| [commit.compute_txid(), reveal.compute_txid()])
        .collect();
    assert_public_publication(&workspace, &mock, &order);
}

#[test]
fn interrupted_public_publication_resumes_with_endpoints_from_the_environment() {
    let workspace = Workspace::new();
    let mock = Mock::start();
    workspace.configure("tcp://127.0.0.1:9");
    let endpoints = json!([{"electrum": mock.endpoint()}]).to_string();
    let first = workspace.publish(Some(&endpoints), &["--yes", "--watch", "false"]);
    let text = stderr(&first);
    assert!(first.status.success(), "{text}");
    assert!(text.contains("Pending/incomplete"), "{text}");
    assert!(!text.contains("Target Confirmed reached"), "{text}");
    let (commits, reveals) = commits_then_reveals(&workspace.pairs());
    assert_eq!(mock.ledger().accepted, commits);
    {
        let mut ledger = mock.ledger();
        ledger.mine_mempool();
        ledger.mining = true;
    }
    let plan = workspace.text("plan");
    let resumed = workspace.urma(
        Some(&endpoints),
        &["git", "resume", "--plan", plan.as_str(), "--yes"],
    );
    let text = stderr(&resumed);
    assert!(resumed.status.success(), "{text}");
    assert!(text.contains("Target Confirmed reached for all"), "{text}");
    let order: Vec<Txid> = commits.into_iter().chain(reveals).collect();
    assert_public_publication(&workspace, &mock, &order);
}

#[test]
fn refused_public_broadcast_is_reported_without_claiming_publication() {
    let workspace = Workspace::new();
    let mock = Mock::start();
    mock.ledger().refusing = true;
    workspace.configure(&mock.endpoint());
    let output = workspace.publish(None, &["--yes"]);
    let text = stderr(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(REFUSAL), "{text}");
    for claim in [
        "Target Confirmed reached",
        "Target Mempool reached",
        "Pending/incomplete",
    ] {
        assert!(!text.contains(claim), "{text}");
    }
    let (commits, _) = commits_then_reveals(&workspace.pairs());
    let ledger = mock.ledger();
    assert!(ledger.accepted.is_empty());
    assert_eq!(ledger.refused, commits[..1]);
    assert_eq!(ledger.transactions.len(), 1);
    for line in workspace.journal() {
        assert_eq!(line["source"], "public_provider_observation", "{line}");
        for row in line["report"]["transactions"].as_array().unwrap() {
            assert_eq!(row["presence"]["status"], "missing", "{line}");
        }
    }
    let progress = workspace.path("plan").join("progress.json");
    if progress.exists() {
        let report: Value = serde_json::from_slice(&std::fs::read(progress).unwrap()).unwrap();
        assert_eq!(report["complete"], false);
        assert_eq!(report["confirmed"], false);
    }
}
