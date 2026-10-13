use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, absolute,
    block::{Header, Version},
    blockdata::constants::genesis_block,
    consensus::serialize,
    hashes::Hash,
    pow::CompactTarget,
    transaction::Version as TxVersion,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use urma_chain::observation::Chain;
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_runtime::{electrum::Electrum, endpoints::PublicEndpoint, node::Node, pinning::Pins};
use urma_wallet::account::{Account, KeyPath};

pub const PHRASE: &str =
    "abandon amount liar amount expire adjust cage candy arch gather drum buyer";

pub fn funder() -> Account {
    let root = Root::from_phrase(&IdentityPhrase::parse(PHRASE).unwrap()).unwrap();
    Account::from_root(Chain::BitcoinRegtest, &root).unwrap()
}

pub struct Fixture {
    pub funding: Transaction,
    header: Header,
    rows: HashMap<String, Vec<Value>>,
    pub listed: Mutex<Vec<String>>,
}

pub fn scripthash(script: &ScriptBuf) -> String {
    let mut digest = bitcoin::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array();
    digest.reverse();
    hex::encode(digest)
}

impl Fixture {
    pub fn new(account: &Account, coins: &[(KeyPath, u64)]) -> Self {
        let output = coins
            .iter()
            .map(|(path, value)| TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: account.script(*path).unwrap(),
            })
            .collect();
        let funding = Transaction {
            version: TxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..TxIn::default()
            }],
            output,
        };
        let txid = funding.compute_txid().to_string();
        let mut rows: HashMap<String, Vec<Value>> = HashMap::new();
        for (vout, output) in funding.output.iter().enumerate() {
            rows.entry(scripthash(&output.script_pubkey))
                .or_default()
                .push(
                    json!({"tx_hash":txid,"tx_pos":vout,"height":1,"value":output.value.to_sat()}),
                );
        }
        let header = Header {
            version: Version::TWO,
            prev_blockhash: genesis_block(Network::Regtest).block_hash(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(
                funding.compute_txid().to_byte_array(),
            ),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 1,
        };
        Self {
            funding,
            header,
            rows,
            listed: Mutex::new(Vec::new()),
        }
    }

    pub fn outpoint(&self, vout: u32) -> OutPoint {
        OutPoint::new(self.funding.compute_txid(), vout)
    }

    fn respond(&self, method: &str, params: &Value) -> Result<Value, Value> {
        let txid = self.funding.compute_txid().to_string();
        match method {
            "server.version" => Ok(json!(["MockX 1.0", params[1]])),
            "blockchain.block.header" => match params[0].as_u64() {
                Some(0) => Ok(json!(hex::encode(serialize(
                    &genesis_block(Network::Regtest).header
                )))),
                Some(1) => Ok(json!(hex::encode(serialize(&self.header)))),
                _ => Err(json!({"code":1,"message":"height out of range"})),
            },
            "blockchain.headers.subscribe" => {
                Ok(json!({"height":1,"hex":hex::encode(serialize(&self.header))}))
            }
            "blockchain.transaction.get" if params[0] == json!(txid) => match params[1] == true {
                true => Ok(
                    json!({"txid":txid,"confirmations":1,"blockhash":self.header.block_hash(),"hex":hex::encode(serialize(&self.funding))}),
                ),
                false => Ok(json!(hex::encode(serialize(&self.funding)))),
            },
            "blockchain.transaction.get" => {
                Err(json!({"code":2,"message":"No such mempool or blockchain transaction."}))
            }
            "blockchain.scripthash.listunspent" => {
                let key = params[0].as_str().unwrap().to_owned();
                let rows = self.rows.get(&key).cloned().unwrap_or_default();
                self.listed.lock().unwrap().push(key);
                Ok(Value::Array(rows))
            }
            other => Err(json!({"code":-32601,"message":format!("unknown method {other}")})),
        }
    }
}

pub struct Mock {
    endpoint: PublicEndpoint,
    stopped: Arc<AtomicBool>,
    address: String,
    thread: Option<thread::JoinHandle<()>>,
}

impl Mock {
    pub fn start(fixture: Arc<Fixture>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                serve(stream.unwrap(), &fixture);
            }
        });
        Self {
            endpoint: PublicEndpoint::Electrum(format!("tcp://{address}")),
            stopped,
            address,
            thread: Some(thread),
        }
    }

    pub fn node(&self) -> Node {
        let provider = Electrum::new(self.endpoint.clone(), Arc::new(Pins::ephemeral())).unwrap();
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(provider)]).unwrap()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _poke = TcpStream::connect(&self.address).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

fn serve(mut stream: TcpStream, fixture: &Fixture) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            return;
        }
        let request: Value = serde_json::from_str(&line).unwrap();
        let method = request["method"].as_str().unwrap();
        let reply = match fixture.respond(method, &request["params"]) {
            Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            Err(error) => json!({"jsonrpc":"2.0","id":request["id"],"error":error}),
        };
        writeln!(stream, "{reply}").unwrap();
    }
}

pub fn start(account: &Account, coins: &[(KeyPath, u64)]) -> (Arc<Fixture>, Mock) {
    let fixture = Arc::new(Fixture::new(account, coins));
    let mock = Mock::start(fixture.clone());
    (fixture, mock)
}
