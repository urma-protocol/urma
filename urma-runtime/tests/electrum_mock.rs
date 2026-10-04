use bitcoin::{
    Amount, Network, Transaction, TxIn, TxOut, absolute,
    block::{Header, Version},
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
    pow::CompactTarget,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version as TxVersion,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use urma_chain::observation::Chain;
use urma_runtime::{
    electrum::Electrum,
    endpoints::PublicEndpoint,
    error::Error,
    node::{Node, Presence},
    pinning::Pins,
    transport::{Evidence, Provider},
};

const MEMPOOL_TXID: &str = "4444444444444444444444444444444444444444444444444444444444444444";

struct Fixture {
    funding: Transaction,
    header: Header,
    signer: Keypair,
    flood: AtomicBool,
    close_after: AtomicUsize,
}

impl Fixture {
    fn new() -> Self {
        let signer =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[9; 32]).unwrap());
        let funding = Transaction {
            version: TxVersion::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([7; 32]),
                    vout: 0,
                },
                ..TxIn::default()
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: urma_wallet::signing::script(&signer).unwrap(),
                },
                TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: urma_wallet::signing::script(&signer).unwrap(),
                },
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: urma_wallet::signing::script(&signer).unwrap(),
                },
            ],
        };
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
            signer,
            flood: AtomicBool::new(false),
            close_after: AtomicUsize::new(0),
        }
    }

    fn unspent_rows(&self) -> Value {
        let txid = self.funding.compute_txid().to_string();
        if self.flood.load(Ordering::Acquire) {
            let rows: Vec<Value> = (0..65)
                .map(|index| json!({"tx_hash":txid,"tx_pos":index,"height":1,"value":1_000}))
                .collect();
            return Value::Array(rows);
        }
        json!([
            {"tx_hash":txid,"tx_pos":0,"height":1,"value":100_000_000},
            {"tx_hash":txid,"tx_pos":1,"height":1,"value":5_000},
        ])
    }

    fn address(&self) -> String {
        bitcoin::Address::from_script(&self.funding.output[0].script_pubkey, Network::Regtest)
            .unwrap()
            .to_string()
    }

    fn scripthash(&self) -> String {
        let mut digest =
            bitcoin::hashes::sha256::Hash::hash(self.funding.output[0].script_pubkey.as_bytes())
                .to_byte_array();
        digest.reverse();
        hex::encode(digest)
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
            "blockchain.transaction.get" if params[0] == json!(txid) => {
                if params[1] == json!(true) {
                    Ok(
                        json!({"txid":txid,"confirmations":1,"blockhash":self.header.block_hash(),"hex":hex::encode(serialize(&self.funding))}),
                    )
                } else {
                    Ok(json!(hex::encode(serialize(&self.funding))))
                }
            }
            "blockchain.transaction.get" if params[0] == json!(MEMPOOL_TXID) => {
                Ok(json!({"txid":MEMPOOL_TXID,"hex":"00","size":1}))
            }
            "blockchain.transaction.get" => Err(json!({
                "code":2,
                "message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
            })),
            "blockchain.scripthash.listunspent" if params[0] == json!(self.scripthash()) => {
                Ok(self.unspent_rows())
            }
            "blockchain.scripthash.listunspent" => Ok(json!([])),
            "blockchain.transaction.broadcast" => Ok(json!(txid)),
            other => Err(json!({"code":-32601,"message":format!("unknown method {other}")})),
        }
    }
}

struct Mock {
    endpoint: PublicEndpoint,
    methods: Arc<Mutex<Vec<String>>>,
    stopped: Arc<AtomicBool>,
    address: String,
    thread: Option<thread::JoinHandle<()>>,
}

impl Mock {
    fn start(fixture: Arc<Fixture>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let (log, stop) = (methods.clone(), stopped.clone());
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                serve(stream.unwrap(), &fixture, &log);
            }
        });
        Self {
            endpoint: PublicEndpoint::Electrum(format!("tcp://{address}")),
            methods,
            stopped,
            address,
            thread: Some(thread),
        }
    }

    fn provider(&self) -> Electrum {
        Electrum::new(self.endpoint.clone(), Arc::new(Pins::ephemeral())).unwrap()
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().unwrap().clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _poke = TcpStream::connect(&self.address).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

fn serve(mut stream: TcpStream, fixture: &Fixture, log: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = true;
    let mut served = 0;
    loop {
        let close_after = fixture.close_after.load(Ordering::Acquire);
        if close_after > 0 && served >= close_after {
            return;
        }
        served += 1;
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            return;
        }
        let request: Value = serde_json::from_str(&line).unwrap();
        let method = request["method"].as_str().unwrap().to_owned();
        log.lock().unwrap().push(method.clone());
        if first {
            let notification = json!({"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"height":1}]});
            writeln!(stream, "{notification}").unwrap();
            first = false;
        }
        let reply = match fixture.respond(&method, &request["params"]) {
            Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            Err(error) => json!({"jsonrpc":"2.0","id":request["id"],"error":error}),
        };
        writeln!(stream, "{reply}").unwrap();
    }
}

#[test]
fn handshake_verifies_protocol_and_genesis_then_maps_tip_and_headers() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let provider = mock.provider();
    assert_eq!(provider.evidence(), Evidence::PublicProviderObservation);
    assert!(provider.supports("addressutxos"));
    assert!(!provider.supports("getblock"));
    assert!(!provider.supports("getrawmempool"));
    assert!(!provider.supports("testmempoolaccept"));
    let tip = provider
        .call(Chain::BitcoinRegtest, "getblockchaininfo", &[])
        .unwrap();
    assert_eq!(tip["blocks"], 1);
    assert_eq!(
        tip["bestblockhash"],
        json!(fixture.header.block_hash().to_string())
    );
    assert_eq!(tip["initialblockdownload"], false);
    let genesis = provider
        .call(Chain::BitcoinRegtest, "getblockhash", &[json!(0)])
        .unwrap();
    assert_eq!(
        genesis,
        json!(Chain::BitcoinRegtest.genesis().unwrap().0.to_string())
    );
    let header = provider
        .call(
            Chain::BitcoinRegtest,
            "getblockheader",
            &[json!(fixture.header.block_hash().to_string())],
        )
        .unwrap();
    assert_eq!(header["height"], 1);
    let unseen = provider
        .call(
            Chain::BitcoinRegtest,
            "getblockheader",
            &[json!("22".repeat(32))],
        )
        .unwrap_err();
    assert!(matches!(unseen, Error::Unsupported(_)));
    assert_eq!(
        &mock.methods()[..3],
        [
            "server.version",
            "blockchain.block.header",
            "blockchain.headers.subscribe"
        ]
    );
}

#[test]
fn wrong_network_is_refused_at_handshake() {
    let mock = Mock::start(Arc::new(Fixture::new()));
    let provider = mock.provider();
    let error = provider
        .call(Chain::BitcoinTestnet4, "getblockchaininfo", &[])
        .unwrap_err();
    assert!(error.to_string().contains("genesis"));
}

#[test]
fn transactions_outputs_and_utxos_map_to_the_node_vocabulary() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let provider = mock.provider();
    let txid = json!(fixture.funding.compute_txid().to_string());
    let raw = provider
        .call(
            Chain::BitcoinRegtest,
            "getrawtransaction",
            &[txid.clone(), json!(false)],
        )
        .unwrap();
    assert_eq!(
        deserialize::<Transaction>(&hex::decode(raw.as_str().unwrap()).unwrap()).unwrap(),
        fixture.funding
    );
    let verbose = provider
        .call(
            Chain::BitcoinRegtest,
            "getrawtransaction",
            &[txid.clone(), json!(true)],
        )
        .unwrap();
    assert_eq!(verbose["confirmations"], 1);
    assert_eq!(
        verbose["blockhash"],
        json!(fixture.header.block_hash().to_string())
    );
    let absent = provider
        .call(
            Chain::BitcoinRegtest,
            "getrawtransaction",
            &[json!("33".repeat(32)), json!(false)],
        )
        .unwrap_err();
    assert!(matches!(absent, Error::Missing(_)));
    let unspent = provider
        .call(
            Chain::BitcoinRegtest,
            "gettxout",
            &[txid.clone(), json!(0), json!(true)],
        )
        .unwrap();
    assert_eq!(unspent["confirmations"], 1);
    assert_eq!(unspent["coinbase"], false);
    assert_eq!(unspent["value"].to_string(), "1");
    assert_eq!(
        unspent["scriptPubKey"]["hex"],
        json!(hex::encode(
            fixture.funding.output[0].script_pubkey.as_bytes()
        ))
    );
    let spent = provider
        .call(
            Chain::BitcoinRegtest,
            "gettxout",
            &[txid.clone(), json!(2), json!(true)],
        )
        .unwrap();
    assert!(spent.is_null());
    let rows = provider
        .call(
            Chain::BitcoinRegtest,
            "addressutxos",
            &[json!(fixture.address())],
        )
        .unwrap();
    assert_eq!(
        rows,
        json!([
            {"txid":txid,"vout":0,"value":100_000_000,"status":{"confirmed":true,"block_height":1}},
            {"txid":txid,"vout":1,"value":5_000,"status":{"confirmed":true,"block_height":1}},
        ])
    );
    let broadcast = provider
        .call(
            Chain::BitcoinRegtest,
            "sendrawtransaction",
            &[json!(hex::encode(serialize(&fixture.funding)))],
        )
        .unwrap();
    assert_eq!(broadcast, txid);
}

#[test]
fn node_routes_through_electrum_and_reports_provider_evidence() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let node =
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(mock.provider())]).unwrap();
    assert!(node.is_public());
    assert_eq!(node.inclusion_evidence(), "public_provider_observation");
    assert_eq!(node.provider_labels(), vec![mock.endpoint.url().to_owned()]);
    let observed = node.observe("getblockchaininfo", &[]).unwrap();
    assert_eq!(observed.provider, mock.endpoint.url());
    assert_eq!(observed.evidence, Evidence::PublicProviderObservation);
    assert_eq!(observed.value["blocks"], 1);
    assert_eq!(node.tip_height().unwrap(), 1);
    assert_eq!(
        node.presence(fixture.funding.compute_txid()).unwrap(),
        Presence::Confirmed {
            height: 1,
            block_hash: fixture.header.block_hash().to_string()
        }
    );
    assert_eq!(
        node.confirmations(fixture.funding.compute_txid()).unwrap(),
        1
    );
    assert!(node.block(1).is_err());
    assert_eq!(
        node.call("getrawmempool", &[])
            .unwrap_err()
            .to_string()
            .contains("no public provider"),
        true
    );
}

fn count(methods: &[String], name: &str) -> usize {
    methods.iter().filter(|method| method == &name).count()
}

#[test]
fn a_gettxout_sequence_over_one_script_costs_one_listunspent() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let provider = mock.provider();
    let txid = json!(fixture.funding.compute_txid().to_string());
    for vout in [0, 1, 2] {
        provider
            .call(
                Chain::BitcoinRegtest,
                "gettxout",
                &[txid.clone(), json!(vout), json!(true)],
            )
            .unwrap();
    }
    let methods = mock.methods();
    assert_eq!(count(&methods, "blockchain.scripthash.listunspent"), 1);
    assert_eq!(count(&methods, "blockchain.transaction.get"), 3);
    provider
        .call(
            Chain::BitcoinRegtest,
            "sendrawtransaction",
            &[json!(hex::encode(serialize(&fixture.funding)))],
        )
        .unwrap();
    provider
        .call(
            Chain::BitcoinRegtest,
            "addressutxos",
            &[json!(fixture.address())],
        )
        .unwrap();
    assert_eq!(
        count(&mock.methods(), "blockchain.scripthash.listunspent"),
        2
    );
}

#[test]
fn funding_selection_verifies_outputs_lazily_in_value_order() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let node =
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(mock.provider())]).unwrap();
    let funding = node.select_funding(&fixture.signer, 1_000).unwrap();
    assert_eq!(funding.vout, 1);
    assert_eq!(funding.prevout().unwrap().1.value.to_sat(), 5_000);
    let methods = mock.methods();
    assert_eq!(count(&methods, "blockchain.scripthash.listunspent"), 1);
    assert_eq!(count(&methods, "blockchain.transaction.get"), 2);
    let large = node.select_funding(&fixture.signer, 10_000).unwrap();
    assert_eq!(large.vout, 0);
    assert!(node.select_funding(&fixture.signer, 200_000_000).is_err());
}

#[test]
fn spendable_summary_is_verified_per_output_only_within_the_bound() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let node =
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(mock.provider())]).unwrap();
    let small = node.spendable(&fixture.signer).unwrap();
    assert!(small.verified);
    assert_eq!(small.reported, 2);
    assert_eq!(small.outputs.len(), 2);
    assert_eq!(count(&mock.methods(), "blockchain.transaction.get"), 2);
    drop(node);
    fixture.flood.store(true, Ordering::Release);
    let node =
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(mock.provider())]).unwrap();
    let before = count(&mock.methods(), "blockchain.transaction.get");
    let large = node.spendable(&fixture.signer).unwrap();
    assert!(!large.verified);
    assert_eq!(large.reported, 65);
    assert_eq!(large.outputs.len(), 65);
    assert_eq!(count(&mock.methods(), "blockchain.transaction.get"), before);
    assert_eq!(node.available_utxos(&fixture.signer).unwrap().len(), 65);
}

#[test]
fn a_mempool_transaction_maps_to_zero_confirmations() {
    let fixture = Arc::new(Fixture::new());
    let mock = Mock::start(fixture.clone());
    let provider = mock.provider();
    let verbose = provider
        .call(
            Chain::BitcoinRegtest,
            "getrawtransaction",
            &[json!(MEMPOOL_TXID), json!(true)],
        )
        .unwrap();
    assert_eq!(verbose, json!({"confirmations":0}));
    drop(provider);
    let node =
        Node::with_providers(Chain::BitcoinRegtest, vec![Box::new(mock.provider())]).unwrap();
    let routed = node
        .call("getrawtransaction", &[json!(MEMPOOL_TXID), json!(true)])
        .unwrap();
    assert_eq!(routed["confirmations"], 0);
}

#[test]
fn a_closed_socket_is_reconnected_and_the_request_retried_once() {
    let fixture = Arc::new(Fixture::new());
    fixture.close_after.store(3, Ordering::Release);
    let mock = Mock::start(fixture.clone());
    let provider = mock.provider();
    let first = provider
        .call(Chain::BitcoinRegtest, "getblockchaininfo", &[])
        .unwrap();
    assert_eq!(first["blocks"], 1);
    let second = provider
        .call(Chain::BitcoinRegtest, "getblockchaininfo", &[])
        .unwrap();
    assert_eq!(second["blocks"], 1);
    assert_eq!(count(&mock.methods(), "server.version"), 2);
    fixture.close_after.store(1, Ordering::Release);
    let refused = provider
        .call(Chain::BitcoinRegtest, "getblockchaininfo", &[])
        .unwrap_err();
    assert!(matches!(refused, Error::Io(_)));
}

#[test]
fn pins_trust_on_first_use_and_refuse_change() {
    let directory = tempfile::tempdir().unwrap();
    let pins = Pins::in_directory(directory.path()).unwrap();
    let first = [1_u8; 32];
    let second = [2_u8; 32];
    pins.check("electrum.example.org_50002", first).unwrap();
    let path = directory
        .path()
        .join("electrum-pins/electrum.example.org_50002.sha256");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap().trim(),
        hex::encode(first)
    );
    pins.check("electrum.example.org_50002", first).unwrap();
    assert!(pins.check("electrum.example.org_50002", second).is_err());
    pins.check("other.example.org_50002", second).unwrap();
    let reloaded = Pins::in_directory(directory.path()).unwrap();
    reloaded.check("electrum.example.org_50002", first).unwrap();
    assert!(
        reloaded
            .check("electrum.example.org_50002", second)
            .is_err()
    );
    let ephemeral = Pins::ephemeral();
    ephemeral
        .check("electrum.example.org_50002", second)
        .unwrap();
    assert!(
        ephemeral
            .check("electrum.example.org_50002", first)
            .is_err()
    );
    assert!(!directory.path().join("electrum-pins/x.sha256").exists());
}
