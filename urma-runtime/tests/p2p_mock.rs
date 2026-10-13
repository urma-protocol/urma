#[allow(dead_code)]
#[path = "support/mock_peer.rs"]
mod mock_peer;

use bitcoin::consensus::encode::serialize;
use mock_peer::{Behaviour, MockPeer, regtest_chain};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_runtime::config::P2P_BLOCK_PEER_TIMEOUT_SECS;
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
    assert_eq!(dropping.getdata.load(Ordering::Acquire), 1);
}

fn connected_within(provider: &P2pProvider, peers: usize, bound: Duration) {
    let started = Instant::now();
    while provider.progress().peers_connected != peers {
        assert!(
            started.elapsed() < bound,
            "peers never settled at {peers}: {:?}",
            provider.progress()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_window_of_blocks_arrives_in_about_one_round_trip_from_several_peers() {
    let blocks = Arc::new(regtest_chain(24));
    let trip = Duration::from_millis(400);
    let peers: Vec<MockPeer> = (0..4)
        .map(|_index| mock_peer::spawn(blocks.clone(), Behaviour::Delay(trip)))
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let handles: Vec<&MockPeer> = peers.iter().collect();
    let provider = provider(dir.path(), &blocks, &handles);
    assert_eq!(provider.progress().peers_connected, 4);
    let started = Instant::now();
    for height in 1..=16 {
        assert_eq!(
            getblock(&provider, &blocks[height]).unwrap(),
            serialize(&blocks[height]),
            "height {height}"
        );
    }
    let took = started.elapsed();
    assert!(took < trip * 3, "sixteen blocks took {took:?}");
    let asked: Vec<usize> = peers
        .iter()
        .map(|peer| peer.getdata.load(Ordering::Acquire))
        .collect();
    assert!(asked.iter().all(|count| *count >= 1), "{asked:?}");
}

#[test]
fn a_silent_peer_delays_only_its_own_heights() {
    let blocks = Arc::new(regtest_chain(16));
    let serving: Vec<MockPeer> = (0..3)
        .map(|_index| mock_peer::spawn(blocks.clone(), Behaviour::Serve))
        .collect();
    let silent = mock_peer::spawn(blocks.clone(), Behaviour::SilentOnGetData);
    let dir = tempfile::tempdir().unwrap();
    let mut handles: Vec<&MockPeer> = serving.iter().collect();
    handles.push(&silent);
    let provider = provider(dir.path(), &blocks, &handles);
    assert_eq!(provider.progress().peers_connected, 4);
    let started = Instant::now();
    for height in 1..=12 {
        assert_eq!(
            getblock(&provider, &blocks[height]).unwrap(),
            serialize(&blocks[height]),
            "height {height}"
        );
    }
    let took = started.elapsed();
    let one_timeout = Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS + 3);
    assert!(took < one_timeout, "a silent peer cost {took:?}");
    assert_eq!(silent.getdata.load(Ordering::Acquire), 1);
    connected_within(&provider, 3, one_timeout);
}

#[test]
fn a_sequential_walk_prefetches_ahead_and_serves_the_rest_from_cache() {
    let blocks = Arc::new(regtest_chain(8));
    let peers: Vec<MockPeer> = (0..4)
        .map(|_index| mock_peer::spawn(blocks.clone(), Behaviour::Serve))
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let handles: Vec<&MockPeer> = peers.iter().collect();
    let provider = provider(dir.path(), &blocks, &handles);
    assert_eq!(provider.progress().peers_connected, 4);
    assert_eq!(provider.progress().headers_synced, 7);
    for height in 1..=6 {
        assert_eq!(
            getblock(&provider, &blocks[height]).unwrap(),
            serialize(&blocks[height]),
            "height {height}"
        );
    }
    let per_peer: Vec<usize> = peers
        .iter()
        .map(|peer| peer.getdata.load(Ordering::Acquire))
        .collect();
    assert_eq!(
        per_peer,
        vec![1, 1, 1, 1],
        "the first request asks the whole window at once, spread over every peer"
    );
}

#[test]
fn parallel_dials_reach_a_live_peer_behind_silent_listeners() {
    let blocks = Arc::new(regtest_chain(4));
    let silent: Vec<MockPeer> = (0..6)
        .map(|_index| mock_peer::spawn(blocks.clone(), Behaviour::Silent))
        .collect();
    let good = mock_peer::spawn(blocks.clone(), Behaviour::Serve);
    let mut handles: Vec<&MockPeer> = silent.iter().collect();
    handles.push(&good);
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let provider = provider(dir.path(), &blocks, &handles);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "six silent listeners each hold a 15 s handshake; parallel dialing took {elapsed:?}"
    );
    assert!(provider.ready());
    assert_eq!(provider.progress().headers_synced, 3);
    assert!(
        !dir.path().join("Bitcoin-regtest-peers.json").exists(),
        "a pinned run never writes the peer book"
    );
}

#[test]
fn an_idle_drop_is_detected_without_a_request() {
    let blocks = Arc::new(regtest_chain(4));
    let closing = mock_peer::spawn(
        blocks.clone(),
        Behaviour::CloseAfter(Duration::from_millis(1500)),
    );
    let good = mock_peer::spawn(blocks.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let provider = provider(dir.path(), &blocks, &[&closing, &good]);
    assert_eq!(provider.progress().peers_connected, 2);
    let started = Instant::now();
    while provider.progress().peers_connected != 1 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "idle drop not noticed: {:?}",
            provider.progress()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(provider.ready());
    assert_eq!(
        getblock(&provider, &blocks[2]).unwrap(),
        serialize(&blocks[2])
    );
    assert_eq!(
        closing.getdata.load(Ordering::Acquire),
        0,
        "a detected drop is never asked for a block"
    );
}

#[test]
fn a_silent_block_holder_gives_way_to_the_next_peer() {
    let blocks = Arc::new(regtest_chain(6));
    let silent = mock_peer::spawn(blocks.clone(), Behaviour::SilentOnGetData);
    let good = mock_peer::spawn(blocks.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let provider = provider(dir.path(), &blocks, &[&silent, &good]);
    assert_eq!(provider.progress().peers_connected, 2);
    let started = Instant::now();
    assert_eq!(
        getblock(&provider, &blocks[3]).unwrap(),
        serialize(&blocks[3])
    );
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(12), "{elapsed:?}");
    assert_eq!(silent.getdata.load(Ordering::Acquire), 1);
    assert!(good.getdata.load(Ordering::Acquire) >= 1);
    connected_within(&provider, 1, Duration::from_secs(12));
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
    let again = getblock(&provider, &blocks[3]).unwrap();
    assert_eq!(again, raw);
    assert_eq!(
        getblock(&provider, &blocks[4]).unwrap(),
        serialize(&blocks[4])
    );
    assert_eq!(dropping.getdata.load(Ordering::Acquire), 1);
    let asked = good.getdata.load(Ordering::Acquire);
    assert!(
        (1..=2).contains(&asked),
        "the window plus at most one re-request of the dropped peer's heights: {asked}"
    );
    connected_within(&provider, 1, Duration::from_secs(5));
    assert!(provider.ready());
    assert!(dropping.getheaders.load(Ordering::Acquire) >= 1);
    assert!(good.getheaders.load(Ordering::Acquire) >= 1);
}
