use serde_json::json;
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_runtime::p2p::P2pProvider;
use urma_runtime::transport::{BlockEncoding, Evidence, Provider};

fn prove(chain: Chain) {
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let provider = P2pProvider::new(chain, dir.path()).unwrap();
    assert_eq!(provider.evidence(), Evidence::LightClientInclusion);
    assert_eq!(provider.block_encoding(), BlockEncoding::Esplora);
    assert!(!provider.supports("getrawtransaction"));
    provider.warm().unwrap();
    while !provider.synced() {
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "header sync did not finish: {:?}",
            provider.progress()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let synced_at = started.elapsed();
    let progress = provider.progress();
    let info = provider.call(chain, "getblockchaininfo", &[]).unwrap();
    let tip = info["blocks"].as_u64().unwrap();
    let best = info["bestblockhash"].as_str().unwrap().to_owned();
    assert_eq!(
        provider.call(chain, "getblockhash", &[json!(tip)]).unwrap(),
        json!(best)
    );
    let header = provider
        .call(chain, "getblockheader", &[json!(best)])
        .unwrap();
    assert_eq!(header["height"], json!(tip));
    let fetch_started = Instant::now();
    let raw = provider
        .call(chain, "getblock", &[json!(best), json!(0)])
        .unwrap();
    let bytes = raw.as_str().unwrap().len() / 2;
    let block = urma_chain::decode::esplora_block(
        &hex::decode(raw.as_str().unwrap()).unwrap(),
        chain,
        best.parse().unwrap(),
    )
    .unwrap();
    assert_eq!(block.block_hash().to_string(), best);
    println!(
        "{chain:?}: tip {tip} ({best}), headers synced {}/{} in {:.1}s with {} peers; block {} bytes, {} txs, fetched in {:.1}s",
        progress.headers_synced,
        progress.headers_target,
        synced_at.as_secs_f64(),
        progress.peers_connected,
        bytes,
        block.txdata.len(),
        fetch_started.elapsed().as_secs_f64()
    );
    assert!(
        provider
            .call(chain, "getblock", &[json!(best), json!(1)])
            .is_err()
    );
}

#[test]
#[ignore = "bounded read-only peer-to-peer proof; resolves dns seeds, syncs headers from the checkpoint and fetches one block"]
fn live_litecoin_mainnet_headers_and_one_block() {
    prove(Chain::LitecoinMainnet);
}

#[test]
#[ignore = "bounded read-only peer-to-peer proof; resolves dns seeds, syncs headers from the checkpoint and fetches one block"]
fn live_litecoin_testnet_headers_and_one_block() {
    prove(Chain::LitecoinTestnet);
}
