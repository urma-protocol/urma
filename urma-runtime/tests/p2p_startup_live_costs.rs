#![cfg(not(target_arch = "wasm32"))]

use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{Hash, sha256};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};
use urma_chain::observation::Chain;
use urma_runtime::config::P2P_HEADER_CACHE_MAX;
use urma_runtime::light::LightSync;
use urma_runtime::node::Node;
use urma_runtime::p2p::Anchor;

struct LiveTimings;

#[derive(Default)]
struct Fields(BTreeMap<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), json!(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().into(), json!(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), json!(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), json!(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), json!(format!("{value:?}")));
    }
}

impl Subscriber for LiveTimings {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "urma_startup"
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if self.enabled(event.metadata()) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            println!("{}", json!(fields.0));
        }
    }
}

fn copied_cache(directory: &Path, chain: Chain) -> (usize, String) {
    let input = std::env::var_os("URMA_STARTUP_CACHE").expect("explicit cache path required");
    let raw =
        urma_io::read_bounded(Path::new(&input), P2P_HEADER_CACHE_MAX * Header::SIZE).unwrap();
    assert!(raw.len() >= 2 * Header::SIZE && raw.len() % Header::SIZE == 0);
    let first: Header = deserialize(&raw[..Header::SIZE]).unwrap();
    let second: Header = deserialize(&raw[Header::SIZE..2 * Header::SIZE]).unwrap();
    let last: Header = deserialize(&raw[raw.len() - Header::SIZE..]).unwrap();
    let anchor = Anchor::embedded(chain).unwrap();
    assert_eq!(first, anchor.header);
    assert_eq!(second.block_hash(), anchor.next_hash);
    let path = directory.join(format!("{}-headers.bin", chain.label().replace(' ', "-")));
    std::fs::write(path, &raw).unwrap();
    println!(
        "{}",
        json!({ "probe": "live_read_only", "phase": "input", "profile": "release",
        "chain": chain.label(), "headers": raw.len() / Header::SIZE, "bytes": raw.len(),
        "start_height": anchor.height, "anchor_hash": first.block_hash().to_string(),
        "tip_hash": last.block_hash().to_string(), "bytes_sha256": sha256::Hash::hash(&raw).to_string() })
    );
    (raw.len() / Header::SIZE, last.block_hash().to_string())
}

fn progress(node: &Node) -> urma_runtime::light::Progress {
    match node.light_client_progress() {
        LightSync::Cold(progress) | LightSync::Running(progress) => progress,
        LightSync::Absent => panic!("Litecoin light client required"),
    }
}

#[test]
#[ignore = "explicit read-only live startup probe; requires cache, --release and external timeout"]
fn live_startup_on_a_cache_copy() {
    assert!(!cfg!(debug_assertions), "measure with --release");
    let chain = match std::env::var("URMA_STARTUP_CHAIN").as_deref() {
        Ok("mainnet") => Chain::LitecoinMainnet,
        Ok("testnet") => Chain::LitecoinTestnet,
        _ => panic!("URMA_STARTUP_CHAIN=mainnet|testnet required"),
    };
    let staging = std::env::var_os("URMA_STARTUP_STAGING").expect("parent-owned staging required");
    let directory = tempfile::tempdir_in(staging).unwrap();
    let (count, tip_hash) = copied_cache(directory.path(), chain);
    tracing::subscriber::set_global_default(LiveTimings).unwrap();
    let started = Instant::now();
    let node = Node::public_in(chain, directory.path()).unwrap();
    let constructor_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        progress(&node).headers_synced + 1,
        u64::try_from(count).unwrap()
    );
    println!(
        "{}",
        json!({ "phase": "constructor_complete", "elapsed_ms": constructor_ms })
    );
    let warmed = Instant::now();
    node.warm_light_client().unwrap();
    while !progress(&node).synced {
        assert!(
            started.elapsed() < Duration::from_secs(80),
            "live startup exceeded internal deadline"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let progress = progress(&node);
    println!(
        "{}",
        json!({ "probe": "live_read_only", "phase": "synced", "samples": 1,
        "input_tip_hash": tip_hash, "constructor_ms": constructor_ms,
        "warm_to_synced_ms": warmed.elapsed().as_secs_f64() * 1000.0,
        "total_ms": started.elapsed().as_secs_f64() * 1000.0,
        "headers_synced": progress.headers_synced, "headers_target": progress.headers_target,
        "peers_connected": progress.peers_connected })
    );
}
