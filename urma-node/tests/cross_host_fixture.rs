//! Writes the two-archive fixture for the cross-host overlay experiment.
//! Not a check: run once with URMA_FIXTURE_DIR set. No network is used.
//! B retains a genuine signed record whose commit is the parent A lacks.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::Transaction;
use common::{Body, FIRST_HEIGHT, MemorySource, point, profile, witness_block};
use libp2p::{PeerId, identity::Keypair};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command, sync::Arc};
use urma_chain::observation::Chain;
use urma_node::{
    engine::Engine,
    model::{ArchiveConfig, Retention},
};

const B_URMA_PORT: u16 = 28400;
const A_PROXY_PORT: u16 = 28401;
const CONTROL: &str = "127.0.0.1:28331";

fn binary(dir: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_urma-node"))
        .env_clear()
        .arg("--data")
        .arg(dir.join("data"))
        .arg("--config")
        .arg(dir.join("config.json"))
        .args(args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: {stderr}");
    String::from_utf8(output.stdout).unwrap()
}

// One mock-selected LitecoinTestnet block, scanned in process, then the
// token and transport key are created by the real binary.
fn node(dir: &Path, transactions: &[Transaction], nonce: u32) -> PeerId {
    fs::create_dir_all(dir).unwrap();
    let block = witness_block(transactions, None, nonce);
    let config = ArchiveConfig {
        chain: Chain::LitecoinTestnet,
        application_start: point(FIRST_HEIGHT, &block),
        retention: Retention::Unpruned,
    };
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let source = Arc::new(MemorySource::with_bodies(
        Chain::LitecoinTestnet,
        FIRST_HEIGHT,
        vec![Body::from(&block)],
    ));
    let engine = Engine::open(&dir.join("data"), config, Some(source)).unwrap();
    engine.synchronize_headers().unwrap();
    assert_eq!(engine.scan_next().unwrap().scanned_blocks, 1);
    drop(engine);
    let token = dir.join("service.token");
    let key = dir.join("peer.key");
    binary(dir, &["create-token", token.to_str().unwrap()]);
    binary(dir, &["create-peer-key", key.to_str().unwrap()]);
    Keypair::from_protobuf_encoding(&fs::read(key).unwrap())
        .unwrap()
        .public()
        .to_peer_id()
}

fn status(dir: &Path) -> Value {
    serde_json::from_str(&binary(dir, &["status"])).unwrap()
}

fn run_md(b: PeerId, a: PeerId, parent: &str) -> String {
    let serve = |node: &str| {
        format!(
            "./urma-node --data {node}/data --config {node}/config.json serve \
             --listen {CONTROL} --token-file {node}/service.token \
             --p2p --no-commit-public --peer-key {node}/peer.key"
        )
    };
    let status = |node: &str| {
        format!(
            "curl -s -H \"Authorization: Bearer $(cat {node}/service.token)\" \
             http://{CONTROL}/v1/status"
        )
    };
    format!(
        "# Cross-host overlay fixture\n\n\
         Run every command from this directory. Parent TXID A lacks: `{parent}`.\n\
         B peer id: `{b}`. A peer id: `{a}`.\n\n\
         ## B (sprite)\n\n```sh\n{} --urma-listen 0.0.0.0:{B_URMA_PORT}\n{}\n```\n\n\
         ## Tunnel (this machine)\n\n```sh\n\
         sprite proxy -o cristian-zmole -s <B sprite> {A_PROXY_PORT}:{B_URMA_PORT}\n```\n\n\
         ## A (this machine)\n\n```sh\n\
         {} --urma-peer /ip4/127.0.0.1/tcp/{A_PROXY_PORT}/p2p/{b}\n{}\n```\n\n\
         Done when A reports `archive.unresolved_dependencies` 0 and the overlay \
         entry of `commit_sources` has `last_error` null.\n",
        serve("b"),
        status("b"),
        serve("a"),
        status("a"),
    )
}

#[test]
#[ignore = "writes a fixture under URMA_FIXTURE_DIR; not a standalone check"]
fn write_cross_host_fixture() {
    let root = std::env::var_os("URMA_FIXTURE_DIR").expect("URMA_FIXTURE_DIR");
    let root = Path::new(&root);
    assert!(!root.exists(), "fixture directory must be new");
    let pair = profile();
    let b = node(&root.join("b"), &pair.transactions(), 40101);
    let a = node(&root.join("a"), std::slice::from_ref(&pair.reveal), 40102);
    let (b_status, a_status) = (status(&root.join("b")), status(&root.join("a")));
    assert_eq!(b_status["unresolved_dependencies"], 0);
    assert_eq!(b_status["stored_transactions"], 2);
    assert_eq!(a_status["unresolved_dependencies"], 1);
    assert_eq!(a_status["stored_transactions"], 0);
    let parent = pair.commit.compute_txid().to_string();
    fs::write(root.join("RUN.md"), run_md(b, a, &parent)).unwrap();
    let ids = json!({"b":b.to_string(),"a":a.to_string(),"parent":parent,
        "b_urma_port":B_URMA_PORT,"a_proxy_port":A_PROXY_PORT,"control":CONTROL});
    fs::write(
        root.join("fixture.json"),
        serde_json::to_vec_pretty(&ids).unwrap(),
    )
    .unwrap();
}
