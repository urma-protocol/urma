use bitcoin::Txid;
use serde_json::json;
use std::{
    io::Read,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_identity::{keyring::Keyring, phrase::IdentityPhrase};
use urma_runtime::{
    node::{Node, NodeConfig},
    plan::{PlanLimits, PublicationPlan, prepare_multipart},
    publish::publish,
    recovery::recover,
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "starts an isolated local Bitcoin Core regtest node"]
fn signed_publication_restart_reorg_and_recovery() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/urma-runtime-lab");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::tempdir_in(&root).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _daemon = Daemon(
        Command::new("bitcoind")
            .arg(format!("-datadir={}", directory.path().display()))
            .args([
                "-regtest",
                "-server=1",
                "-txindex=1",
                "-listen=0",
                "-dnsseed=0",
                "-discover=0",
                "-connect=0",
                "-fallbackfee=0.00001",
            ])
            .arg(format!("-rpcport={port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let config = NodeConfig {
        chain: Chain::BitcoinRegtest,
        rpc_url: format!("http://127.0.0.1:{port}"),
        cookie_file: directory.path().join("regtest/.cookie"),
    };
    let start = Instant::now();
    let node = loop {
        match Node::connect(config.clone()) {
            Ok(node) => break node,
            Err(error) => {
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "node did not start: {error}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    let phrase = IdentityPhrase::parse(&format!("{}art", "abandon ".repeat(23))).unwrap();
    let signer = Keyring::create(&phrase, "public-test-vector")
        .unwrap()
        .active()
        .unwrap();
    let address = urma_wallet::address::receive_address(&signer, Chain::BitcoinRegtest).unwrap();
    node.call("generatetoaddress", &[json!(102), json!(address)])
        .unwrap();
    let available_before = node.available_utxos(&signer).unwrap().len();
    assert_eq!(available_before, 3);
    let payload = vec![77; urma_core::multipart::Geometry::DATA_BYTES * 2 + 1];
    let plan = prepare_multipart(
        &node,
        &signer,
        &payload,
        *b"RUNTIME0",
        PlanLimits {
            fee_rate: 1,
            max_fee: 500_000,
            max_records: 10,
        },
    )
    .unwrap();
    assert_eq!(plan.records.len(), 5);
    let plan_path = directory.path().join("plan.json");
    let journal = directory.path().join("journal.json");
    plan.save_new(&plan_path).unwrap();
    use urma_runtime::publish::ensure_journal_distinct;
    assert!(ensure_journal_distinct(&plan_path, &plan_path).is_err());
    let alias = directory.path().join("plan-hardlink.json");
    std::fs::hard_link(&plan_path, &alias).unwrap();
    assert!(ensure_journal_distinct(&plan_path, &alias).is_err());
    ensure_journal_distinct(&plan_path, &journal).unwrap();
    assert!(publish(&node, &plan, "not-approved", &journal).is_err());
    let report = publish(&node, &plan, &plan.id().unwrap(), &journal).unwrap();
    assert!(!report.complete);
    assert!(!report.confirmed);
    assert_eq!(report.transactions.len(), 1);
    assert_eq!(
        node.available_utxos(&signer).unwrap().len(),
        available_before - 1
    );
    let reloaded = PublicationPlan::load(&plan_path).unwrap();
    let fresh = Node::connect(config).unwrap();
    for step in 0..12 {
        let report = publish(&fresh, &reloaded, &reloaded.id().unwrap(), &journal).unwrap();
        assert_eq!(report.complete, report.confirmed);
        if report.confirmed {
            break;
        }
        assert!(
            step < 11,
            "publication did not finish: {}",
            report.blocked_reason
        );
        node.call("generatetoaddress", &[json!(1), json!(address)])
            .unwrap();
    }
    assert!(
        publish(&fresh, &reloaded, &reloaded.id().unwrap(), &journal)
            .unwrap()
            .confirmed
    );
    let block = node.block_hash(node.tip_height().unwrap()).unwrap();
    let root_txid: Txid = reloaded.root_txid.parse().unwrap();
    let mut recovered = recover(
        &fresh,
        root_txid,
        urma_runtime::multipart::RecoveryLimits {
            max_payload_bytes: payload.len() as u64,
            max_nodes: 10,
        },
        directory.path(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    recovered.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, payload);
    node.call("invalidateblock", &[json!(block)]).unwrap();
    let reorg = publish(&fresh, &reloaded, &reloaded.id().unwrap(), &journal).unwrap();
    assert!(!reorg.complete);
    assert!(!reorg.confirmed);
    assert!(
        recover(
            &fresh,
            root_txid,
            urma_runtime::multipart::RecoveryLimits {
                max_payload_bytes: payload.len() as u64,
                max_nodes: 10
            },
            directory.path()
        )
        .is_err()
    );
    node.call("reconsiderblock", &[json!(block)]).unwrap();
    assert!(
        publish(&fresh, &reloaded, &reloaded.id().unwrap(), &journal)
            .unwrap()
            .confirmed
    );
    let mut forged = reloaded;
    forged.total_fee += 1;
    assert!(forged.validate().is_err());
}
