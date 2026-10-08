//! Offline measurement; explicitly ignored so ordinary tests do not benchmark.
//!
//! Reproduce with an isolated target directory and no transport or network:
//! `cargo test --offline --locked --release -p urma-runtime --test p2p_startup_costs -- --ignored --nocapture`
//!
//! Optional inputs: URMA_STARTUP_SAMPLES=7 (3..100), URMA_STARTUP_REVISION=label.
//! URMA_STARTUP_CACHE=/explicit/headers.bin additionally measures a real cache;
//! it requires URMA_STARTUP_CHAIN=mainnet or testnet and the embedded checkpoint.
//! The original is only read, bounded to the production capacity, then copied to
//! a temporary directory. HeaderChain may reject/remove ONLY that temporary copy.
//! Successful JSON omits personal paths; read errors retain the usual path context.
//! Both committed retarget fixtures always run.
//!
//! Reload uses production HeaderChain::anchored, including anchor proof, file
//! read, decode, context replay (when present), tail PoW and index construction.
//! Context timings are captured from production `urma_startup` tracing events;
//! absent events are omitted, not reported as zero. Standalone tail/full PoW use
//! already decoded input and the production worker cap, with anchor proved first.
//! Full PoW is confined to this harness and does not change production policy.
//! One unreported warmup precedes samples, so filesystem/page cache is warm.
//! Re-run the identical command/input before and after the contextual commit;
//! totals include enabled tracing overhead and are not cold-start predictions.
//! Small fixtures do not establish the worst case for testnet minimum-difficulty
//! lookback. CPU scheduling, host load and frequency are not controlled.

#![cfg(not(target_arch = "wasm32"))]

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256};
use serde_json::json;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};
use urma_chain::observation::Chain;
use urma_chain::pow::check_header_pow;
use urma_runtime::config::{P2P_HEADER_CACHE_MAX, P2P_HEADER_CACHE_REVALIDATE, P2P_POW_WORKERS};
use urma_runtime::p2p::{Anchor, HeaderChain};

#[derive(Clone, Default)]
struct Timings(Arc<Mutex<BTreeMap<String, Vec<f64>>>>);

#[derive(Default)]
struct Stage {
    name: Option<String>,
    milliseconds: Option<f64>,
}

impl Visit for Stage {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "stage" {
            self.name = Some(value.to_owned());
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "elapsed_ms" {
            self.milliseconds = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

impl Subscriber for Timings {
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
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut stage = Stage::default();
        event.record(&mut stage);
        if let (Some(name), Some(milliseconds)) = (stage.name, stage.milliseconds) {
            self.0
                .lock()
                .unwrap()
                .entry(name)
                .or_default()
                .push(milliseconds);
        }
    }
}

struct Dataset {
    label: &'static str,
    chain: Chain,
    height: u64,
    headers: Vec<Header>,
    raw: Vec<u8>,
}

fn fixture(label: &'static str, chain: Chain, boundary: u64) -> Dataset {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../urma-chain/tests/fixtures/ltc-{label}-retarget-{boundary}.hex"
    ));
    let encoded = String::from_utf8(urma_io::read_bounded(&path, 1024 * 1024).unwrap()).unwrap();
    let headers: Vec<Header> = encoded
        .lines()
        .map(|line| deserialize(&hex::decode(line).unwrap()).unwrap())
        .collect();
    assert_eq!(headers.len(), 2018);
    let raw = headers.iter().flat_map(serialize).collect();
    Dataset {
        label,
        chain,
        height: boundary - 2017,
        headers,
        raw,
    }
}

fn cache(path: &Path, chain: Chain) -> Dataset {
    let raw = urma_io::read_bounded(path, P2P_HEADER_CACHE_MAX * Header::SIZE).unwrap();
    assert!(raw.len() >= 2 * Header::SIZE && raw.len() % Header::SIZE == 0);
    let headers: Vec<Header> = raw
        .chunks_exact(Header::SIZE)
        .map(|bytes| deserialize(bytes).unwrap())
        .collect();
    let anchor = Anchor::embedded(chain).unwrap();
    assert_eq!(
        headers[0], anchor.header,
        "cache must use the embedded checkpoint"
    );
    assert_eq!(headers[1].block_hash(), anchor.next_hash);
    Dataset {
        label: "opt_in_cache",
        chain,
        height: anchor.height,
        headers,
        raw,
    }
}

fn prove_parallel(chain: Chain, headers: &[Header]) {
    if headers.is_empty() {
        return;
    }
    let workers = std::thread::available_parallelism()
        .unwrap()
        .get()
        .min(P2P_POW_WORKERS)
        .min(headers.len());
    let chunk = headers.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let handles: Vec<_> = headers
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    for header in part {
                        check_header_pow(black_box(header), chain).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
}

fn milliseconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn summary(mut values: Vec<f64>) -> serde_json::Value {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    let median = match values.len() % 2 {
        0 => (values[middle - 1] + values[middle]) / 2.0,
        _ => values[middle],
    };
    json!({ "samples": values.len(), "min_ms": values[0],
        "median_ms": median, "max_ms": values[values.len() - 1] })
}

#[test]
fn even_sample_median_uses_both_middle_values() {
    assert_eq!(summary(vec![4.0, 1.0, 3.0, 2.0])["median_ms"], json!(2.5));
    assert_eq!(summary(vec![3.0, 1.0, 2.0])["median_ms"], json!(2.0));
}

fn measure(dataset: Dataset, samples: usize, revision: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("headers.bin");
    // Setup and copying are outside measurement; original input is never passed
    // to HeaderChain, whose rejection path removes a cache file.
    std::fs::write(&path, &dataset.raw).unwrap();
    let tail_start = dataset
        .headers
        .len()
        .saturating_sub(P2P_HEADER_CACHE_REVALIDATE)
        .max(1);
    let timings = Timings::default();
    let mut totals: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for sample in 0..=samples {
        let started = Instant::now();
        let loaded = tracing::subscriber::with_default(timings.clone(), || {
            HeaderChain::anchored(
                dataset.chain,
                path.clone(),
                dataset.height,
                dataset.headers[0],
                dataset.headers[1].block_hash(),
            )
            .unwrap()
        });
        let reload_ms = milliseconds(started);
        assert_eq!(
            loaded.synced_count() + 1,
            dataset.headers.len() as u64,
            "production reload rejected the temporary copy"
        );
        assert_eq!(
            loaded.tip_hash(),
            dataset.headers.last().unwrap().block_hash()
        );
        drop(loaded);
        let captured = std::mem::take(&mut *timings.0.lock().unwrap());
        let started = Instant::now();
        check_header_pow(black_box(&dataset.headers[0]), dataset.chain).unwrap();
        prove_parallel(dataset.chain, &dataset.headers[tail_start..]);
        let tail_ms = milliseconds(started);
        let started = Instant::now();
        check_header_pow(black_box(&dataset.headers[0]), dataset.chain).unwrap();
        prove_parallel(dataset.chain, &dataset.headers[1..]);
        let full_ms = milliseconds(started);
        if sample > 0 {
            totals
                .entry("reload_total".into())
                .or_default()
                .push(reload_ms);
            totals
                .entry("standalone_tail_pow".into())
                .or_default()
                .push(tail_ms);
            totals
                .entry("standalone_full_pow".into())
                .or_default()
                .push(full_ms);
            for (stage, values) in captured {
                totals.entry(stage).or_default().extend(values);
            }
        }
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        dataset.raw,
        "temporary input changed"
    );
    let stages: BTreeMap<_, _> = totals
        .into_iter()
        .map(|(stage, values)| (stage, summary(values)))
        .collect();
    println!(
        "{}",
        json!({ "revision": revision, "profile": "release", "filesystem_cache": "warm",
        "dataset": dataset.label, "chain": dataset.chain.label(), "headers": dataset.headers.len(),
        "start_height": dataset.height, "anchor_hash": dataset.headers[0].block_hash().to_string(),
        "tip_hash": dataset.headers.last().unwrap().block_hash().to_string(),
        "bytes_sha256": sha256::Hash::hash(&dataset.raw).to_string(),
        "bytes": dataset.raw.len(), "samples": samples, "unreported_warmups": 1,
        "pow_workers": std::thread::available_parallelism().unwrap().get().min(P2P_POW_WORKERS),
        "reload_pow_headers": 1 + dataset.headers.len() - tail_start,
        "full_pow_headers": dataset.headers.len(), "stages": stages })
    );
}

#[test]
#[ignore = "offline release measurement: explicitly run with --release --ignored --nocapture"]
fn offline_header_startup_costs() {
    assert!(!cfg!(debug_assertions), "measure with --release");
    let samples: usize = std::env::var("URMA_STARTUP_SAMPLES")
        .unwrap_or_else(|_| "7".into())
        .parse()
        .unwrap();
    assert!((3..=100).contains(&samples));
    let revision = std::env::var("URMA_STARTUP_REVISION").unwrap_or_else(|_| "unlabelled".into());
    measure(
        fixture("mainnet", Chain::LitecoinMainnet, 3_185_280),
        samples,
        &revision,
    );
    measure(
        fixture("testnet", Chain::LitecoinTestnet, 4_902_912),
        samples,
        &revision,
    );
    if let Some(path) = std::env::var_os("URMA_STARTUP_CACHE") {
        let chain = match std::env::var("URMA_STARTUP_CHAIN").as_deref() {
            Ok("mainnet") => Chain::LitecoinMainnet,
            Ok("testnet") => Chain::LitecoinTestnet,
            _ => panic!("URMA_STARTUP_CACHE requires URMA_STARTUP_CHAIN=mainnet|testnet"),
        };
        measure(cache(Path::new(&path), chain), samples, &revision);
    }
}
