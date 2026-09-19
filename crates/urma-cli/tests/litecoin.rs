//! Deterministic, in-memory testnet RPC fixtures. No daemon, sockets, funds or
//! broadcasts. Fixed keys below belong exclusively to synthetic test vectors.
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap};
use urma::config;
use urma::error::{Error, bail};
use urma::{
    backend::{self, RecordSource},
    container, envelope,
    litecoin::{self, Plan, Rpc},
    transport::Funding,
};

const ROOT: [u8; 32] = [42; 32];
const BLOCK1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BLOCK2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const BLOCK3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let id = [7; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(&id), &ROOT);
    let mut content = [0; 32];
    let mut auth = [0; 32];
    let mut discovery = [0; 16];
    hkdf.expand(b"URMA/V0/private/content", &mut content)
        .unwrap();
    hkdf.expand(b"URMA/V0/private/authentication", &mut auth)
        .unwrap();
    hkdf.expand(b"URMA/V0/private/discovery", &mut discovery)
        .unwrap();
    bytes
        .chunks(urma::format::Urma::CHUNK_BYTES)
        .enumerate()
        .map(|(i, chunk)| {
            let mut record = urma::format::RecordKind::Private.prefix().to_vec();
            record.extend(id);
            record.extend(discovery);
            record.extend((i as u32).to_le_bytes());
            record.extend(
                (bytes.len().div_ceil(urma::format::Urma::CHUNK_BYTES) as u32).to_le_bytes(),
            );
            let mut iv = [0; 16];
            iv[..8].copy_from_slice(&(i as u64).to_be_bytes());
            record.extend(iv);
            let mut body = Sha256::digest(bytes).to_vec();
            body.extend((bytes.len() as u64).to_le_bytes());
            body.extend([0; 8]);
            body.extend(chunk);
            body.resize(48 + urma::format::Urma::CHUNK_BYTES, 0); // Deterministic padding, test vectors only.
            ctr::Ctr128BE::<aes::Aes256>::new(&content.into(), &iv.into())
                .apply_keystream(&mut body);
            record.extend(body);
            let mut mac = Hmac::<Sha256>::new_from_slice(&auth).unwrap();
            mac.update(&record);
            record.extend(mac.finalize().into_bytes());
            record
        })
        .collect()
}

fn funding_key() -> SecretKey {
    SecretKey::from_slice(&[2; 32]).unwrap()
}
fn funding(value: u64) -> Funding {
    let public = bitcoin::PublicKey::new(funding_key().public_key(&Secp256k1::new()));
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2wpkh(&public.wpubkey_hash().unwrap()),
        }],
    };
    Funding {
        raw_transaction: hex::encode(serialize(&tx)),
        vout: 0,
    }
}
fn tx(raw: &str) -> Transaction {
    deserialize(&hex::decode(raw).unwrap()).unwrap()
}
fn fixture(bytes: &[u8]) -> Plan {
    let amount = litecoin::quote(bytes.len(), 1)
        .unwrap()
        .minimum_funding_litoshis;
    litecoin::prepare(
        &records(bytes),
        bytes.len(),
        funding(amount),
        1,
        1,
        &mut StdRng::seed_from_u64(123),
    )
    .unwrap()
}
fn sign_commit(raw: &str, previous: &TxOut) -> String {
    let mut transaction = tx(raw);
    let hash = SighashCache::new(&transaction)
        .p2wpkh_signature_hash(
            0,
            &previous.script_pubkey,
            previous.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let secp = Secp256k1::new();
    let signature = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &funding_key()),
    );
    transaction.input[0].witness = Witness::from_slice(&[
        signature.to_vec(),
        funding_key().public_key(&secp).serialize().to_vec(),
    ]);
    hex::encode(serialize(&transaction))
}

struct Mock {
    info: Value,
    genesis: String,
    previous: TxOut,
    transactions: RefCell<BTreeMap<String, Value>>,
    calls: RefCell<Vec<String>>,
    blocks: BTreeMap<u64, Value>,
    unspent: bool,
    allow: bool,
    reorg: bool,
    tip_reads: RefCell<u32>,
    returned_txid_wrong: bool,
}
impl Mock {
    fn new(plan: &Plan) -> Self {
        Self {
            info: json!({"chain":"test","blocks":3,"initialblockdownload":false,
                "softforks":{"segwit":{"active":true},"taproot":{"active":true}}}),
            genesis: config::LITECOIN_GENESIS.into(),
            previous: tx(&plan.funding.raw_transaction).output[0].clone(),
            transactions: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
            blocks: BTreeMap::new(),
            unspent: true,
            allow: true,
            reorg: false,
            tip_reads: RefCell::new(0),
            returned_txid_wrong: false,
        }
    }
    fn sign(&self, draft: &Plan) -> Plan {
        litecoin::sign(self, draft).unwrap()
    }
    fn sends(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|m| m.as_str() == "sendrawtransaction")
            .count()
    }
    fn confirm(&mut self, raw: &str, height: u64) {
        let hash = [config::LITECOIN_GENESIS, BLOCK1, BLOCK2, BLOCK3][height as usize];
        let id = tx(raw).compute_txid().to_string();
        self.transactions.borrow_mut().insert(
            id.clone(),
            json!({"hex":raw,"confirmations":4-height,"blockhash":hash}),
        );
        self.blocks
            .insert(height, json!({"hash":hash,"height":height,"tx":[id]}));
    }
    fn scan_blocks(&mut self, plan: &Plan) {
        self.blocks.insert(
            1,
            json!({"hash":BLOCK1,"height":1,"confirmations":3,"previousblockhash":config::LITECOIN_GENESIS,
            "tx":[{"vin":[{}]}]}),
        );
        for (height, hash, previous) in [(2, BLOCK2, BLOCK1), (3, BLOCK3, BLOCK2)] {
            let reveal = &plan.reveals[(height - 2) % plan.reveals.len()];
            let witness: Vec<String> = tx(reveal).input[0]
                .witness
                .iter()
                .map(hex::encode)
                .collect();
            self.blocks.insert(height as u64,json!({"hash":hash,"height":height,"confirmations":4-height,
                "previousblockhash":previous,"mweb":{"opaque":"left to Core"},"tx":[{"version":2,"vin":[{"scriptSig":{"hex":""},"txinwitness":witness}],"vout":[{"scriptPubKey":{"hex":hex::encode(tx(reveal).output[0].script_pubkey.as_bytes())}}]}]}));
        }
    }
}
impl Rpc for Mock {
    fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        self.calls.borrow_mut().push(method.into());
        Ok(match method {
            "getblockchaininfo" => self.info.clone(),
            "getblockhash" => match args[0].as_u64().unwrap() {
                0 => json!(self.genesis),
                1 => json!(BLOCK1),
                2 => json!(BLOCK2),
                3 => {
                    *self.tip_reads.borrow_mut() += 1;
                    if self.reorg && *self.tip_reads.borrow() >= 3 {
                        json!(BLOCK1)
                    } else {
                        json!(BLOCK3)
                    }
                }
                _ => bail!("unexpected height"),
            },
            "getblock" => self
                .blocks
                .values()
                .find(|b| b["hash"] == args[0])
                .cloned()
                .ok_or_else(|| urma::error::Error::Missing("block unavailable".into()))?,
            "signrawtransactionwithwallet" => {
                assert_eq!(args[2], "ALL");
                json!({"complete":true,"hex":sign_commit(args[0].as_str().unwrap(), &self.previous)})
            }
            "getrawtransaction" => self
                .transactions
                .borrow()
                .get(args[0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null),
            "gettxout" if !self.unspent => Value::Null,
            "gettxout" => {
                json!({"coinbase":false,"confirmations":5,"scriptPubKey":{"hex":hex::encode(self.previous.script_pubkey.as_bytes())},
                "value":self.previous.value.to_btc()})
            }
            "testmempoolaccept" => {
                json!([{"allowed":self.allow,"txid":tx(args[0][0].as_str().unwrap()).compute_txid().to_string()}])
            }
            "sendrawtransaction" => {
                let raw = args[0].as_str().unwrap();
                let id = tx(raw).compute_txid().to_string();
                self.transactions
                    .borrow_mut()
                    .insert(id.clone(), json!({"hex":raw,"confirmations":0}));
                if self.returned_txid_wrong {
                    json!("wrong")
                } else {
                    json!(id)
                }
            }
            _ => bail!("unexpected RPC method"),
        })
    }
}

#[test]
fn deterministic_offline_plans_and_exact_funding_at_boundaries() {
    for length in [1, 404, 32768, 32769, 1_048_577] {
        let bytes = vec![19; length];
        let a = fixture(&bytes);
        let b = fixture(&bytes);
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
        let costs = litecoin::quote(length, 1).unwrap();
        let node = Mock::new(&a);
        let signed = node.sign(&a);
        let inspected = litecoin::inspect(&signed, true).unwrap();
        assert_eq!(
            inspected["quote"]["minimum_funding_litoshis"],
            costs.minimum_funding_litoshis
        );
        assert_eq!(
            tx(&a.commit).compute_txid(),
            tx(&signed.commit).compute_txid()
        );
        assert_eq!(tx(&a.commit).output.last().unwrap().value.to_sat(), 1000);
        let recovered: Vec<_> = a
            .reveals
            .iter()
            .map(|r| envelope::extract(&tx(r).input[0].witness).unwrap().record)
            .collect();
        assert_eq!(
            container::open(&ROOT, &recovered).unwrap().as_slice(),
            bytes
        );
        assert_eq!(node.sends(), 0);
        assert!(
            litecoin::prepare(
                &records(&bytes),
                length,
                funding(costs.minimum_funding_litoshis - 1),
                1,
                1,
                &mut StdRng::seed_from_u64(0)
            )
            .is_err()
        );
    }
    for (len, rate) in [
        (0, 1),
        (1, 0),
        (1, 101),
        (urma::config::Limits::INPUT_BYTES + 1, 1),
        (urma::config::Limits::INPUT_BYTES, 100),
    ] {
        assert!(litecoin::quote(len, rate).is_err());
    }
}

#[test]
fn tampered_journals_fail_offline_and_never_reach_rpc() {
    let draft = fixture(&vec![4; 32769]);
    let node = Mock::new(&draft);
    let signed = node.sign(&draft);
    let mut cases = Vec::new();
    let mut p = signed.clone();
    p.network = "main".into();
    cases.push(p);
    let mut p = signed.clone();
    p.network = "testnet4".into();
    cases.push(p);
    let mut p = signed.clone();
    p.version = 2;
    cases.push(p);
    let mut p = signed.clone();
    p.fee_rate_litoshi_vb = 2;
    cases.push(p);
    let mut p = signed.clone();
    p.reveals[1] = p.reveals[0].clone();
    cases.push(p);
    let mut p = signed.clone();
    p.input_bytes = 404;
    cases.push(p);
    let mut p = signed.clone();
    p.funding.vout = 1;
    cases.push(p);
    let mut p = signed.clone();
    let mut c = tx(&p.commit);
    c.output.last_mut().unwrap().value = Amount::ZERO;
    p.commit = hex::encode(serialize(&c));
    cases.push(p);
    let mut p = signed.clone();
    let mut r = tx(&p.reveals[0]);
    let mut w: Vec<Vec<u8>> = r.input[0].witness.iter().map(|b| b.to_vec()).collect();
    w[0][0] ^= 1;
    r.input[0].witness = Witness::from_slice(&w);
    p.reveals[0] = hex::encode(serialize(&r));
    cases.push(p);
    for p in cases {
        node.calls.borrow_mut().clear();
        assert!(litecoin::inspect(&p, true).is_err());
        assert!(litecoin::broadcast(&node, &p, 500_000).is_err());
        assert!(node.calls.borrow().is_empty());
    }
    assert!(litecoin::inspect(&draft, true).is_err());
    assert!(litecoin::inspect(&signed, false).is_err());
}

#[test]
fn genesis_sync_and_activation_gates_fail_before_signing_or_submission() {
    let draft = fixture(b"test");
    let node = Mock::new(&draft);
    let signed = node.sign(&draft);
    for case in 0..5 {
        let mut node = Mock::new(&draft);
        match case {
            0 => node.info["chain"] = json!("main"),
            1 => node.genesis = BLOCK1.into(),
            2 => node.info["initialblockdownload"] = json!(true),
            3 => node.info["softforks"]["taproot"]["active"] = json!(false),
            _ => node.info["softforks"]["segwit"]["active"] = json!(false),
        }
        assert!(litecoin::broadcast(&node, &signed, 500_000).is_err());
        assert_eq!(node.sends(), 0);
        assert!(!node.calls.borrow().iter().any(|m| m == "testmempoolaccept"));
        if case < 2 {
            assert!(litecoin::sign(&node, &draft).is_err());
        }
    }
}

#[test]
fn staged_publication_waits_for_confirmation_and_is_idempotent() {
    let draft = fixture(b"test");
    let mut node = Mock::new(&draft);
    let signed = node.sign(&draft);
    node.calls.borrow_mut().clear();
    assert!(litecoin::broadcast(&node, &signed, 1).is_err());
    assert!(node.calls.borrow().is_empty());
    assert_eq!(
        litecoin::broadcast(&node, &signed, 500_000).unwrap()["status"],
        "commit_submitted"
    );
    assert_eq!(node.sends(), 1);
    assert_eq!(
        litecoin::broadcast(&node, &signed, 500_000).unwrap()["status"],
        "awaiting_commit_confirmation"
    );
    assert_eq!(node.sends(), 1);
    node.confirm(&signed.commit, 1);
    litecoin::broadcast(&node, &signed, 500_000).unwrap();
    assert_eq!(node.sends(), 2);
    litecoin::broadcast(&node, &signed, 500_000).unwrap();
    assert_eq!(node.sends(), 2);
    node.confirm(&signed.reveals[0], 2);
    let state = litecoin::status(&node, &signed).unwrap();
    assert_eq!(state["commit"]["confirmations"], 3);
    assert_eq!(state["reveals"][0]["confirmations"], 2);
}

#[test]
fn spent_funding_policy_rejection_and_ambiguous_submission_fail_closed() {
    let draft = fixture(b"test");
    let signed = Mock::new(&draft).sign(&draft);
    for case in 0..3 {
        let mut node = Mock::new(&draft);
        match case {
            0 => node.unspent = false,
            1 => node.allow = false,
            _ => node.previous.value = Amount::from_sat(1),
        }
        assert!(litecoin::broadcast(&node, &signed, 500_000).is_err());
        assert_eq!(node.sends(), 0);
    }
    let mut node = Mock::new(&draft);
    node.returned_txid_wrong = true;
    assert!(litecoin::broadcast(&node, &signed, 500_000).is_err());
    assert_eq!(node.sends(), 1);
    // Reconcile ambiguous acceptance before any retry: no automatic second send.
    assert_eq!(
        litecoin::status(&node, &signed).unwrap()["commit"]["state"],
        "pending"
    );
    litecoin::broadcast(&node, &signed, 500_000).unwrap();
    assert_eq!(node.sends(), 1);
}

#[test]
fn discovery_recovers_without_journal_and_reports_explicit_core_trust() {
    let bytes = include_bytes!("../../../tests/fixtures/tiny-public-test.jpg");
    let plan = fixture(bytes);
    let mut node = Mock::new(&plan);
    node.scan_blocks(&plan);
    let source = litecoin::LitecoinRecords {
        rpc: &node,
        start_height: 1,
    };
    let recovered = backend::recover(&source, &ROOT).unwrap();
    assert_eq!(recovered.objects.len(), 1);
    assert_eq!(
        recovered
            .objects
            .values()
            .next()
            .unwrap()
            .finish()
            .unwrap()
            .as_slice(),
        bytes
    );
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "36b364e7a1be115cf74c5b4f396fb93b6de56edd54c6ee04246de3f7739ad6e6"
    );
    assert_eq!(
        serde_json::to_value(recovered.observation.evidence).unwrap(),
        "litecoin_core_trusted"
    );
    assert!(
        !node
            .calls
            .borrow()
            .iter()
            .any(|m| m == "getrawtransaction" || m == "signrawtransactionwithwallet")
    );
    assert!(
        backend::recover(&source, &[43; 32])
            .unwrap()
            .objects
            .is_empty()
    );
}

#[test]
fn missing_chunks_forged_candidates_and_reorgs_do_not_claim_success() {
    let bytes = vec![9; 32769];
    let plan = fixture(&bytes);
    let mut node = Mock::new(&plan);
    node.scan_blocks(&plan);
    let original = node.blocks[&3]["tx"].clone();
    node.blocks.get_mut(&3).unwrap()["tx"] = json!([]);
    let recovered = backend::recover(
        &litecoin::LitecoinRecords {
            rpc: &node,
            start_height: 1,
        },
        &ROOT,
    )
    .unwrap();
    let object = recovered.objects.values().next().unwrap();
    assert_eq!(object.received(), 1);
    assert!(object.finish().is_err());
    node.blocks.get_mut(&3).unwrap()["tx"] = original;
    let mut forged = tx(&plan.reveals[0]);
    let mut stack: Vec<Vec<u8>> = forged.input[0].witness.iter().map(|p| p.to_vec()).collect();
    // Flip ciphertext inside a push, preserving script framing and discovery metadata.
    stack[1][200] ^= 1;
    forged.input[0].witness = Witness::from_slice(&stack);
    let witness: Vec<_> = forged.input[0].witness.iter().map(hex::encode).collect();
    node.blocks.get_mut(&2).unwrap()["tx"]
        .as_array_mut()
        .unwrap()
        .push(json!({"version":2,"vin":[{"scriptSig":{"hex":""},"txinwitness":witness}],"vout":[{"scriptPubKey":{"hex":hex::encode(forged.output[0].script_pubkey.as_bytes())}}]}));
    let recovered = backend::recover(
        &litecoin::LitecoinRecords {
            rpc: &node,
            start_height: 1,
        },
        &ROOT,
    )
    .unwrap();
    assert_eq!(recovered.rejected_records, 1);
    assert_eq!(
        recovered
            .objects
            .values()
            .next()
            .unwrap()
            .finish()
            .unwrap()
            .as_slice(),
        bytes
    );
    node.reorg = true;
    *node.tip_reads.borrow_mut() = 0;
    assert!(
        backend::recover(
            &litecoin::LitecoinRecords {
                rpc: &node,
                start_height: 1
            },
            &ROOT
        )
        .is_err()
    );
}

#[test]
fn source_bounds_and_wrong_witness_status_are_rejected() {
    let plan = fixture(b"test");
    let mut node = Mock::new(&plan);
    node.scan_blocks(&plan);
    assert!(
        litecoin::LitecoinRecords {
            rpc: &node,
            start_height: 4
        }
        .read_records(&mut |_| Ok(()))
        .is_err()
    );
    node.info["blocks"] = json!(config::LITECOIN_MAX_SCAN_BLOCKS + 1);
    assert!(
        litecoin::LitecoinRecords {
            rpc: &node,
            start_height: 1
        }
        .read_records(&mut |_| Ok(()))
        .is_err()
    );
    node.info["blocks"] = json!(3);
    let signed = node.sign(&plan);
    let mut altered = tx(&signed.commit);
    altered.input[0].witness = Witness::new();
    node.transactions.borrow_mut().insert(
        altered.compute_txid().to_string(),
        json!({"hex":hex::encode(serialize(&altered)),"confirmations":0}),
    );
    assert!(litecoin::status(&node, &signed).is_err());
}

#[test]
fn bitcoin_validator_still_rejects_litecoin_network_and_unsigned_commits() {
    let p = fixture(b"test");
    let costs = litecoin::quote(p.input_bytes, 1).unwrap();
    let common = urma::transport::Plan {
        network: config::LITECOIN_NETWORK.into(),
        version: p.version,
        object_id: "07".repeat(32),
        start_height: 1,
        input_bytes: p.input_bytes,
        fee_sats: costs.total_fee_litoshis,
        commit_fee_sats: costs.commit_fee_litoshis,
        reveal_fee_sats: costs.reveal_fee_litoshis,
        fee_rate_sat_vb: 1,
        funding: p.funding,
        commit: p.commit,
        reveals: p.reveals,
        mining_address: String::new(),
    };
    assert!(urma::transport::validate_plan(&common).is_err());
}

#[test]
fn local_rpc_origin_validation_never_reads_credentials_for_remote_urls() {
    for endpoint in [
        "https://127.0.0.1:19332",
        "http://example.com:19332",
        "http://192.0.2.1:19332",
        "http://user:password@127.0.0.1:19332",
        "http://127.0.0.1:19332/wallet/other",
        "http://127.0.0.1:19332/?token=value",
    ] {
        assert!(
            litecoin::Core::connect(
                endpoint,
                std::path::Path::new("/nonexistent-cookie"),
                urma::config::RpcScope::Node
            )
            .is_err()
        );
    }
}

#[test]
fn simulated_publish_then_independent_discovery_recovers_original_jpeg() {
    let bytes = include_bytes!("../../../tests/fixtures/tiny-public-test.jpg");
    let draft = fixture(bytes);
    let mut publisher = Mock::new(&draft);
    let signed = publisher.sign(&draft);
    let budget = litecoin::quote(bytes.len(), 1).unwrap().total_fee_litoshis;
    litecoin::broadcast(&publisher, &signed, budget).unwrap();
    publisher.confirm(&signed.commit, 1);
    litecoin::broadcast(&publisher, &signed, budget).unwrap();
    publisher.confirm(&signed.reveals[0], 2);
    assert_eq!(publisher.sends(), 2);
    let mut receiver = Mock::new(&draft);
    receiver.scan_blocks(&signed);
    // Receiver sees only synthetic chain responses; no publisher RPC state or
    // wallet/journal/transaction IDs are passed to the recovery interface.
    drop(publisher);
    drop(signed);
    drop(draft);
    let result = backend::recover(
        &litecoin::LitecoinRecords {
            rpc: &receiver,
            start_height: 1,
        },
        &ROOT,
    )
    .unwrap();
    assert_eq!(
        result
            .objects
            .values()
            .next()
            .unwrap()
            .finish()
            .unwrap()
            .as_slice(),
        bytes
    );
    assert_eq!(receiver.sends(), 0);
}

#[test]
fn cli_quote_and_offline_draft_require_no_daemon_and_never_overwrite() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("object.urma");
    let funding_path = dir.path().join("funding.json");
    let journal = dir.path().join("draft.json");
    std::fs::write(&bundle, container::pack(&records(b"test")).unwrap()).unwrap();
    let amount = litecoin::quote(4, 1).unwrap().minimum_funding_litoshis;
    std::fs::write(&funding_path, serde_json::to_vec(&funding(amount)).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["expert", "litecoin"])
        .args(["quote", "--input-bytes", "404"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["network"],
        config::LITECOIN_NETWORK
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
    command.env("URMA_OUTPUT", "json");
    command.args(["expert", "litecoin"]);
    command
        .args(["prepare", "--bundle"])
        .arg(&bundle)
        .args(["--input-bytes", "4", "--funding"])
        .arg(&funding_path)
        .args(["--start-height", "1", "--journal"])
        .arg(&journal);
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["broadcast"], false);
    assert_eq!(report["status"], "draft");
    assert!(!command.output().unwrap().status.success());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["expert", "litecoin"])
        .args(["inspect", "--journal"])
        .arg(&journal)
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["expert", "litecoin"])
        .args(["--network", "main", "quote", "--input-bytes", "404"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn ambiguous_partial_reveal_resumes_identical_bytes_without_duplicate_sends() {
    let draft = fixture(&vec![9; 32769]);
    let mut node = Mock::new(&draft);
    let signed = node.sign(&draft);
    let budget = litecoin::quote(signed.input_bytes, 1)
        .unwrap()
        .total_fee_litoshis;
    node.confirm(&signed.commit, 1);
    node.returned_txid_wrong = true;
    assert!(litecoin::broadcast(&node, &signed, budget).is_err());
    assert_eq!(node.sends(), 1);
    node.returned_txid_wrong = false;
    let restored: Plan = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
    litecoin::broadcast(&node, &restored, budget).unwrap();
    assert_eq!(node.sends(), 2);
    litecoin::broadcast(&node, &restored, budget).unwrap();
    assert_eq!(node.sends(), 2);
    for raw in &signed.reveals {
        assert_eq!(
            node.transactions.borrow()[&tx(raw).compute_txid().to_string()]["hex"],
            *raw
        );
    }
}

#[test]
fn bounded_reader_respects_end_height_and_cancels_before_next_block() {
    use urma::litecoin::LitecoinRecords;
    let draft = fixture(&vec![9; 32769]);
    let mut node = Mock::new(&draft);
    node.scan_blocks(&draft);
    let reader = LitecoinRecords {
        rpc: &node,
        start_height: 1,
    };
    let mut visited = Vec::new();
    let mut records = 0;
    let observation = reader
        .read_range(
            urma::config::ScanEnd::Height(2),
            &mut |h| {
                visited.push(h);
                Ok(())
            },
            &mut |_| {
                records += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(visited, vec![1, 2]);
    assert_eq!(records, 1);
    assert!(matches!(
        observation.locator,
        urma::backend::Locator::BlockRange { tip_height: 2, .. }
    ));
    let mut visits = 0;
    assert!(
        reader
            .read_range(
                urma::config::ScanEnd::Height(3),
                &mut |_| {
                    visits += 1;
                    if visits == 2 {
                        bail!("cancelled")
                    }
                    Ok(())
                },
                &mut |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(visits, 2);
}
