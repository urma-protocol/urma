use bitcoin::{
    Amount, Transaction, TxIn, TxOut, absolute,
    consensus::{deserialize, serialize},
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use urma_chain::observation::Chain;
use urma_runtime::node::{Node, NodeConfig};

#[derive(Default)]
pub struct State {
    pub transactions: HashMap<String, bool>,
    pub submissions: Vec<String>,
    pub methods: Vec<String>,
    pub preflight: Option<String>,
    pub send_rejection: Option<String>,
    pub unavailable: bool,
    pub auto_confirm: bool,
    pub reorg: bool,
}

pub struct Mock {
    pub state: Arc<Mutex<State>>,
    pub config: NodeConfig,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    pub signer: Keypair,
}

impl Mock {
    pub fn new(directory: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let signer =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
        let funding = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: urma_wallet::signing::script(&signer).unwrap(),
            }],
        };
        let state = Arc::new(Mutex::new(State::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let (worker_state, worker_stop, worker_funding) =
            (state.clone(), stopped.clone(), funding.clone());
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let mut state = worker_state.lock().unwrap();
                let response = match respond(&mut state, &worker_funding, &request) {
                    Ok(value) => json!({"result":value,"error":null,"id":request["id"]}),
                    Err((code, reason)) => {
                        json!({"result":null,"error":{"code":code,"message":reason},"id":request["id"]})
                    }
                };
                let body = serde_json::to_vec(&response).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let cookie = directory.join("mock.cookie");
        std::fs::write(&cookie, "public-fixture:public-fixture").unwrap();
        Self {
            state,
            config: NodeConfig {
                chain: Chain::BitcoinRegtest,
                rpc_url: format!("http://{address}"),
                cookie_file: cookie,
            },
            stopped,
            thread: Some(thread),
            signer,
        }
    }

    pub fn node(&self) -> Node {
        Node::connect(self.config.clone()).unwrap()
    }

    pub fn confirm_all(&self) {
        for confirmed in self.state.lock().unwrap().transactions.values_mut() {
            *confirmed = true;
        }
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let address = self.config.rpc_url.strip_prefix("http://").unwrap();
        let _connection = TcpStream::connect(address).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

pub fn txid(raw: &str) -> String {
    deserialize::<Transaction>(&hex::decode(raw).unwrap())
        .unwrap()
        .compute_txid()
        .to_string()
}

fn respond(
    state: &mut State,
    funding: &Transaction,
    request: &Value,
) -> Result<Value, (i64, String)> {
    let method = request["method"].as_str().unwrap();
    state.methods.push(method.into());
    let args = &request["params"];
    let hash = "11".repeat(32);
    match method {
        "getblockhash" => Ok(if args[0] == 0 {
            json!(Chain::BitcoinRegtest.genesis().unwrap().0.to_string())
        } else if state.reorg {
            json!("22".repeat(32))
        } else {
            json!(hash)
        }),
        "getblockchaininfo" => Ok(json!({"blocks":100,"bestblockhash":hash})),
        "getblockheader" => Ok(json!({"height":100})),
        "getindexinfo" => Ok(json!({"txindex":{"synced":true}})),
        "scantxoutset" => Ok(
            json!({"success":true,"unspents":[{"txid":funding.compute_txid(),"vout":0,"amount":1,"height":1}]}),
        ),
        "gettxout" => Ok(
            json!({"value":1,"confirmations":100,"scriptPubKey":{"hex":hex::encode(funding.output[0].script_pubkey.as_bytes())}}),
        ),
        "getrawmempool" => Ok(json!(
            state
                .transactions
                .iter()
                .filter(|(_, confirmed)| !**confirmed)
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        )),
        "getrawtransaction" if args[0] == json!(funding.compute_txid()) => {
            Ok(json!(hex::encode(serialize(funding))))
        }
        "getrawtransaction" => {
            if state.unavailable {
                return Err((-28, "fixture source unavailable".into()));
            }
            match state.transactions.get(args[0].as_str().unwrap()) {
                Some(true) => Ok(json!({"confirmations":1,"blockhash":hash})),
                Some(false) => Ok(json!({"confirmations":0})),
                None => Err((-5, "fixture missing".into())),
            }
        }
        "testmempoolaccept" => {
            let id = txid(args[0][0].as_str().unwrap());
            Ok(match &state.preflight {
                Some(reason) => json!([{"txid":id,"allowed":false,"reject-reason":reason}]),
                None => json!([{"txid":id,"allowed":true}]),
            })
        }
        "sendrawtransaction" => {
            if let Some(reason) = &state.send_rejection {
                return Err((-26, reason.clone()));
            }
            let raw = args[0].as_str().unwrap();
            let id = txid(raw);
            state.submissions.push(raw.into());
            state.transactions.insert(id.clone(), state.auto_confirm);
            Ok(json!(id))
        }
        other => panic!("unexpected RPC {other}"),
    }
}
