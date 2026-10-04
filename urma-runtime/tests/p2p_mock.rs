#[path = "support/mock_peer.rs"]
mod mock_peer;

use bitcoin::consensus::encode::serialize;
use mock_peer::{Behaviour, MockPeer, regtest_chain};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_runtime::p2p::{Anchor, P2pProvider};
use urma_runtime::transport::Provider;

fn provider(
    dir: &std::path::Path,
    blocks: &Arc<Vec<bitcoin::Block>>,
    peers: &[&MockPeer],
) -> P2pProvider {
    let anchor = Anchor {
        height: 0,
        header: blocks[0].header,
        next_hash: blocks[1].block_hash(),
    };
    let addresses = peers.iter().map(|peer| peer.address).collect();
    let provider = P2pProvider::with_peers(Chain::BitcoinRegtest, dir, anchor, addresses).unwrap();
    provider.warm().unwrap();
    let started = Instant::now();
    while !provider.synced() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "mock header sync stalled: {:?}",
            provider.progress()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    provider
}

fn getblock(provider: &P2pProvider, block: &bitcoin::Block) -> Result<Vec<u8>, String> {
    provider
        .call(
            Chain::BitcoinRegtest,
            "getblock",
            &[json!(block.block_hash().to_string()), json!(0)],
        )
        .map(|value| hex::decode(value.as_str().unwrap()).unwrap())
        .map_err(|error| error.to_string())
}

#[test]
fn a_synced_client_without_peers_fails_fast_and_withdraws_from_routing() {
    let blocks = Arc::new(regtest_chain(6));
    let dropping = mock_peer::spawn(blocks.clone(), Behaviour::EofOnGetData);
    let dir = tempfile::tempdir().unwrap();
    let provider = provider(dir.path(), &blocks, &[&dropping]);
    assert_eq!(provider.progress().headers_synced, 5);
    assert!(provider.ready());
    let started = Instant::now();
    let refused = getblock(&provider, &blocks[2]).unwrap_err();
    let first = started.elapsed();
    assert!(refused.contains("no connected peer"), "{refused}");
    assert!(
        first < Duration::from_secs(2),
        "first failure took {first:?}"
    );
    let started = Instant::now();
    let refused = getblock(&provider, &blocks[3]).unwrap_err();
    let second = started.elapsed();
    assert!(refused.contains("no connected peer"), "{refused}");
    assert!(
        second < Duration::from_millis(500),
        "second failure took {second:?}"
    );
    let settled = Instant::now();
    while provider.ready() {
        assert!(
            settled.elapsed() < Duration::from_secs(5),
            "readiness never dropped"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!provider.supports("getblock"));
    assert!(!provider.supports("getblockchaininfo"));
    assert!(provider.synced());
    assert_eq!(
        dropping.getdata.load(std::sync::atomic::Ordering::Acquire),
        1
    );
}

#[test]
fn a_dropping_peer_is_replaced_by_a_good_peer_inside_the_fetch() {
    let blocks = Arc::new(regtest_chain(6));
    let dropping = mock_peer::spawn(blocks.clone(), Behaviour::EofOnGetData);
    let good = mock_peer::spawn(blocks.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let provider = provider(dir.path(), &blocks, &[&dropping, &good]);
    assert_eq!(provider.progress().peers_connected, 2);
    let raw = getblock(&provider, &blocks[3]).unwrap();
    assert_eq!(raw, serialize(&blocks[3]));
    assert_eq!(
        dropping.getdata.load(std::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(good.getdata.load(std::sync::atomic::Ordering::Acquire), 1);
    let again = getblock(&provider, &blocks[3]).unwrap();
    assert_eq!(again, raw);
    assert_eq!(good.getdata.load(std::sync::atomic::Ordering::Acquire), 1);
    assert!(provider.ready());
}
