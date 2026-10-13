use bitcoin::{
    Amount, CompressedPublicKey, Denomination, OutPoint, PubkeyHash, ScriptBuf, ScriptHash,
    Transaction, TxIn, TxOut, Txid, absolute, base58,
    consensus::{deserialize, serialize},
    hashes::Hash,
    transaction::Version,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use urma_chain::observation::Chain;
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_wallet::account::{Account, Branch, KeyPath};

fn vectors() -> (PathBuf, Value) {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/identity-vault-v2");
    let json = std::fs::read(directory.join("vectors.json")).unwrap();
    (directory, serde_json::from_slice(&json).unwrap())
}

fn account(chain: Chain) -> Account {
    let (_, v) = vectors();
    let phrase = IdentityPhrase::parse(v["phrase"].as_str().unwrap()).unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    Account::from_root(chain, &root).unwrap()
}

fn external(index: u32) -> KeyPath {
    KeyPath::new(Branch::External, index)
}

fn internal(index: u32) -> KeyPath {
    KeyPath::new(Branch::Internal, index)
}

fn chain_label(chain: Chain) -> &'static str {
    match chain {
        Chain::BitcoinRegtest => "bitcoin-regtest",
        Chain::LitecoinTestnet => "litecoin-testnet",
        other => panic!("no mock for {other:?}"),
    }
}

struct Ledger {
    chain: Chain,
    funding: Transaction,
    submissions: Vec<String>,
}

impl Ledger {
    fn amount(&self, vout: usize) -> Value {
        let value = self.funding.output[vout].value;
        serde_json::from_str(&value.to_string_in(Denomination::Bitcoin)).unwrap()
    }

    fn script(&self, vout: usize) -> String {
        hex::encode(self.funding.output[vout].script_pubkey.as_bytes())
    }

    fn respond(&mut self, method: &str, args: &Value) -> Result<Value, (i64, String)> {
        let txid = self.funding.compute_txid();
        match method {
            "getblockhash" if args[0] == 0 => {
                Ok(json!(self.chain.genesis().unwrap().0.to_string()))
            }
            "getblockhash" => Ok(json!("11".repeat(32))),
            "scantxoutset" => {
                let rows: Vec<Value> = (0..self.funding.output.len())
                    .map(|vout| {
                        json!({"txid":txid,"vout":vout,"amount":self.amount(vout),
                        "height":1,"scriptPubKey":self.script(vout)})
                    })
                    .collect();
                Ok(json!({"success":true,"unspents":rows}))
            }
            "gettxout" if args[0] == json!(txid) => {
                let vout = usize::try_from(args[1].as_u64().unwrap()).unwrap();
                Ok(
                    json!({"value":self.amount(vout),"confirmations":100,"coinbase":false,
                    "scriptPubKey":{"hex":self.script(vout)}}),
                )
            }
            "gettxout" => Ok(Value::Null),
            "getrawtransaction" if args[0] == json!(txid) => {
                Ok(json!(hex::encode(serialize(&self.funding))))
            }
            "testmempoolaccept" => {
                let raw: Transaction =
                    deserialize(&hex::decode(args[0][0].as_str().unwrap()).unwrap()).unwrap();
                Ok(json!([{"txid":raw.compute_txid(),"allowed":true}]))
            }
            "sendrawtransaction" => {
                let raw = args[0].as_str().unwrap().to_owned();
                let sent: Transaction = deserialize(&hex::decode(&raw).unwrap()).unwrap();
                self.submissions.push(raw);
                Ok(json!(sent.compute_txid()))
            }
            other => Err((-32601, format!("mock does not serve {other}"))),
        }
    }
}

struct Mock {
    ledger: Arc<Mutex<Ledger>>,
    url: String,
    cookie: PathBuf,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Mock {
    fn start(directory: &Path, account: &Account, coins: &[(KeyPath, u64)]) -> Self {
        let funding = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..TxIn::default()
            }],
            output: coins
                .iter()
                .map(|(path, value)| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: account.script(*path).unwrap(),
                })
                .collect(),
        };
        let ledger = Arc::new(Mutex::new(Ledger {
            chain: account.chain(),
            funding,
            submissions: Vec::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stopped = Arc::new(AtomicBool::new(false));
        let (served, stop) = (ledger.clone(), stopped.clone());
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                serve(stream.unwrap(), &served);
            }
        });
        let cookie = directory.join("mock.cookie");
        std::fs::write(&cookie, "public-fixture:public-fixture").unwrap();
        Self {
            ledger,
            url,
            cookie,
            stopped,
            thread: Some(thread),
        }
    }

    fn outpoint(&self, vout: u32) -> String {
        let txid = self.ledger.lock().unwrap().funding.compute_txid();
        OutPoint::new(txid, vout).to_string()
    }

    fn submissions(&self) -> Vec<Transaction> {
        let ledger = self.ledger.lock().unwrap();
        ledger
            .submissions
            .iter()
            .map(|raw| deserialize(&hex::decode(raw).unwrap()).unwrap())
            .collect()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _poke = TcpStream::connect(self.url.strip_prefix("http://").unwrap()).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

fn serve(mut stream: TcpStream, ledger: &Mutex<Ledger>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let method = request["method"].as_str().unwrap();
    let answer = ledger.lock().unwrap().respond(method, &request["params"]);
    let response = match answer {
        Ok(result) => json!({"result":result,"error":null,"id":request["id"]}),
        Err((code, message)) => {
            json!({"result":null,"error":{"code":code,"message":message},"id":request["id"]})
        }
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .unwrap();
    stream.write_all(&bytes).unwrap();
}

struct Vault {
    _temp: tempfile::TempDir,
    vault: PathBuf,
    password: PathBuf,
}

impl Vault {
    fn valid() -> Self {
        Self::file("valid.vault")
    }

    fn file(name: &str) -> Self {
        let (directory, v) = vectors();
        let temp = tempfile::tempdir().unwrap();
        let password = temp.path().join("password");
        std::fs::write(&password, v["vault"]["password"].as_str().unwrap()).unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            vault: directory.join(name),
            password,
            _temp: temp,
        }
    }

    fn dir(&self) -> &Path {
        self._temp.path()
    }

    fn run(&self, chain: Chain, mock: Option<&Mock>, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env("URMA_OUTPUT", "json")
            .env("URMA_VAULT", &self.vault)
            .env("URMA_UNLOCK_FILE", &self.password)
            .env("URMA_CONFIG", self.dir().join("no-config"))
            .env("URMA_NETWORK", chain_label(chain))
            .env_remove("URMA_RPC_URL")
            .env_remove("URMA_NODE_AUTH_FILE")
            .args(args);
        if let Some(mock) = mock {
            command
                .env("URMA_RPC_URL", &mock.url)
                .env("URMA_NODE_AUTH_FILE", &mock.cookie);
        }
        command.output().unwrap()
    }

    fn json(&self, chain: Chain, mock: Option<&Mock>, args: &[&str]) -> Value {
        let output = self.run(chain, mock, args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn refused(output: Output) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap()
}

fn witness_script(tx: &Transaction, index: usize) -> ScriptBuf {
    let public = CompressedPublicKey::from_slice(tx.input[index].witness.nth(1).unwrap()).unwrap();
    ScriptBuf::new_p2wpkh(&public.wpubkey_hash())
}

fn send<'a>(to: &'a str, amount: &'a str, max_fee: &'a str) -> Vec<&'a str> {
    vec![
        "wallet",
        "send",
        "--to",
        to,
        "--amount",
        amount,
        "--max-fee",
        max_fee,
        "--yes",
    ]
}

const SPREAD: [(Branch, u32, u64); 3] = [
    (Branch::External, 0, 30_000),
    (Branch::Internal, 1, 25_000),
    (Branch::External, 3, 20_000),
];

fn spread() -> Vec<(KeyPath, u64)> {
    SPREAD
        .iter()
        .map(|(branch, index, value)| (KeyPath::new(*branch, *index), *value))
        .collect()
}

#[test]
fn send_spends_several_inputs_and_changes_to_the_next_internal_path() {
    let chain = Chain::BitcoinRegtest;
    let funder = account(chain);
    let vault = Vault::valid();
    let mock = Mock::start(vault.dir(), &funder, &spread());
    let to = funder.address(external(9)).unwrap();
    let sent = vault.json(chain, Some(&mock), &send(&to, "50000", "10000"));
    assert_eq!(sent["status"], "broadcast");
    assert_eq!(sent["chain"], "bitcoin-regtest");
    assert_eq!(sent["inputs"], json!([mock.outpoint(0), mock.outpoint(1)]));
    assert_eq!(sent["change"]["path"], "m/84'/1'/0'/1/2");
    assert_eq!(
        sent["change"]["address"],
        funder.address(internal(2)).unwrap()
    );
    let fee = sent["fee"].as_u64().unwrap();
    assert_eq!(sent["change"]["value"], 55_000 - 50_000 - fee);
    let [tx] = mock.submissions().try_into().unwrap();
    assert_eq!(tx.compute_txid().to_string(), sent["txid"]);
    assert_eq!(witness_script(&tx, 0), funder.script(external(0)).unwrap());
    assert_eq!(witness_script(&tx, 1), funder.script(internal(1)).unwrap());
    assert_eq!(
        tx.output[0].script_pubkey,
        funder.script(external(9)).unwrap()
    );
    assert_eq!(tx.output[0].value.to_sat(), 50_000);
    assert_eq!(
        tx.output[1].script_pubkey,
        funder.script(internal(2)).unwrap()
    );
}

#[test]
fn send_over_the_fee_cap_is_refused_before_broadcast() {
    let chain = Chain::BitcoinRegtest;
    let funder = account(chain);
    let vault = Vault::valid();
    let mock = Mock::start(vault.dir(), &funder, &spread());
    let to = funder.address(external(9)).unwrap();
    let stderr = refused(vault.run(chain, Some(&mock), &send(&to, "50000", "100")));
    assert!(stderr.contains("exceeds the approved maximum"), "{stderr}");
    let mut steep = send(&to, "50000", "10000");
    steep.extend(["--rate", "60"]);
    let stderr = refused(vault.run(chain, Some(&mock), &steep));
    assert!(stderr.contains("exceeds the approved maximum"), "{stderr}");
    assert!(mock.submissions().is_empty());
}

#[test]
fn litecoin_testnet_send_pays_a_legacy_destination() {
    let chain = Chain::LitecoinTestnet;
    let funder = account(chain);
    let vault = Vault::valid();
    let mock = Mock::start(vault.dir(), &funder, &[(internal(0), 80_000)]);
    let hash = [0x42; 20];
    let cases = [
        (
            0x6f,
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)),
        ),
        (
            0x3a,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)),
        ),
    ];
    for (round, (version, script)) in cases.into_iter().enumerate() {
        let to = base58::encode_check(&[&[version][..], &hash].concat());
        let sent = vault.json(chain, Some(&mock), &send(&to, "10000", "10000"));
        assert_eq!(sent["chain"], "litecoin-testnet");
        assert_eq!(sent["to"], to);
        let tx = mock.submissions().remove(round);
        assert_eq!(tx.output[0].script_pubkey, script);
        assert_eq!(tx.output[0].value.to_sat(), 10_000);
        assert_eq!(
            tx.output[1].script_pubkey,
            funder.script(internal(1)).unwrap()
        );
    }
    let mainnet = base58::encode_check(&[&[0x30][..], &hash].concat());
    refused(vault.run(chain, Some(&mock), &send(&mainnet, "10000", "10000")));
    assert_eq!(mock.submissions().len(), 2);
}

#[test]
fn key_list_wallets_and_exports_equal_the_vectors() {
    let (_, v) = vectors();
    let vault = Vault::valid();
    let listed = vault.json(Chain::BitcoinRegtest, None, &["key", "list"]);
    let rows = v["chains"].as_array().unwrap();
    let wallets = listed["wallets"].as_object().unwrap();
    assert_eq!(wallets.len(), rows.len());
    for row in rows {
        let name = row["chain"].as_str().unwrap();
        assert_eq!(
            wallets[name],
            json!({"path":row["path"],"designated_address":row["external_0"]}),
            "{name}"
        );
    }
    for chain in [Chain::BitcoinRegtest, Chain::LitecoinTestnet] {
        let name = chain_label(chain);
        let row = rows.iter().find(|row| row["chain"] == name).unwrap();
        let exported = vault.json(chain, None, &["wallet", "export"]);
        assert_eq!(
            exported,
            json!({"chain":name,"path":row["path"],"fingerprint":v["fingerprint"],
                "account_xpub":row["account_xpub"],
                "descriptors":{"external":row["descriptors"][0],"internal":row["descriptors"][1]},
                "secrets":false})
        );
    }
}

#[test]
fn wire_plan_spends_two_coins_and_returns_to_the_designated_script() {
    let chain = Chain::BitcoinRegtest;
    let funder = account(chain);
    let vault = Vault::valid();
    let coins = [(external(4), 2_600), (internal(2), 3_000)];
    let mock = Mock::start(vault.dir(), &funder, &coins);
    let output = vault.dir().join("wire-plan.json");
    let path = output.to_str().unwrap();
    let mut args = vec!["wire", "plan", "two coins", "--output", path];
    args.extend(["--max-fee", "2000"]);
    let report = vault.json(chain, Some(&mock), &args);
    assert_eq!(report["broadcast"], false);
    let plan: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    let receive = funder.receive_script().unwrap();
    assert_eq!(plan["return_script"], hex::encode(receive.as_bytes()));
    assert_eq!(plan["author"], report["author"]);
    let record = &plan["records"][0];
    assert_eq!(record["funding"].as_array().unwrap().len(), 2);
    let decode = |field: &str| -> Transaction {
        deserialize(&hex::decode(record[field].as_str().unwrap()).unwrap()).unwrap()
    };
    let commit = decode("commit");
    let reveal = decode("reveal");
    let spent: Vec<String> = commit
        .input
        .iter()
        .map(|input| input.previous_output.to_string())
        .collect();
    assert_eq!(spent, [mock.outpoint(1), mock.outpoint(0)]);
    assert_eq!(
        witness_script(&commit, 0),
        funder.script(internal(2)).unwrap()
    );
    assert_eq!(
        witness_script(&commit, 1),
        funder.script(external(4)).unwrap()
    );
    assert_eq!(commit.output[1].script_pubkey, receive);
    assert_eq!(reveal.output[0].script_pubkey, receive);
    assert!(mock.submissions().is_empty());
}

#[test]
fn v1_vault_is_refused_by_every_wallet_command() {
    let chain = Chain::BitcoinRegtest;
    let funder = account(chain);
    let vault = Vault::file("version-1.vault");
    let mock = Mock::start(vault.dir(), &funder, &spread());
    let to = funder.address(external(9)).unwrap();
    let commands: [Vec<&str>; 6] = [
        vec!["wallet", "status"],
        vec!["wallet", "utxos"],
        vec!["wallet", "address"],
        vec!["wallet", "address", "--next"],
        vec!["wallet", "export"],
        send(&to, "50000", "10000"),
    ];
    for args in commands {
        let stderr = refused(vault.run(chain, Some(&mock), &args));
        assert!(
            stderr.contains("unsupported identity vault version"),
            "{args:?}: {stderr}"
        );
    }
    assert!(mock.submissions().is_empty());
}
