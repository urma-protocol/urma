use super::*;
use crate::config::{
    P2P_BLOCK_PEER_TIMEOUT_SECS, P2P_HEADERS_TIMEOUT_SECS, P2P_HEIGHT_SLACK, P2P_PIPELINE_PER_PEER,
};
use crate::p2p::headers::Anchor;
use bitcoin::Block;
use bitcoin::consensus::encode::serialize;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[allow(dead_code)]
#[path = "../../tests/support/mock_peer.rs"]
mod mock_peer;

use mock_peer::{Behaviour, MockPeer};

fn synced_shared(dir: &std::path::Path, chain: &[Block], known: usize) -> Shared {
    let anchor = Anchor {
        height: 0,
        header: chain[0].header,
        next_hash: chain[1].block_hash(),
    };
    let mut headers = HeaderChain::open_at(Chain::BitcoinRegtest, dir, anchor).unwrap();
    let held: Vec<_> = chain[1..=known].iter().map(|block| block.header).collect();
    headers
        .extend(&held, chain[known].header.time + 100)
        .unwrap();
    Shared {
        chain: Chain::BitcoinRegtest,
        pinned: Vec::new(),
        cache_dir: dir.to_owned(),
        headers: Mutex::new(headers),
        blocks: Mutex::new(BlockCache::new()),
        status: Mutex::new(Status {
            peers: 0,
            target: 0,
            synced: true,
            refreshed: Freshness::Never,
        }),
        stop: AtomicBool::new(false),
    }
}

fn connected(dir: &std::path::Path, mocks: &[&MockPeer]) -> Peers {
    let pinned = mocks.iter().map(|mock| mock.address).collect();
    let mut peers = Peers::new(Chain::BitcoinRegtest, pinned, dir);
    peers.discover();
    peers.top_up(0, Duration::from_secs(5));
    assert_eq!(peers.count(), mocks.len());
    peers
}

#[test]
fn a_refresh_walks_past_a_peer_at_our_height_to_the_tip() {
    let chain = Arc::new(mock_peer::regtest_chain(7));
    let lagging = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let ahead = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 2);
    let mut peers = connected(dir.path(), &[&lagging, &ahead]);
    assert_eq!(peers.connected[0].address, lagging.address);
    sync_round(&shared, &mut peers).unwrap();
    assert_eq!(locked(&shared.headers, "headers").tip_height(), 6);
    assert!(ahead.getheaders.load(Ordering::Acquire) >= 1);
    sync_round(&shared, &mut peers).unwrap();
    assert_eq!(peers.count(), 2, "an unchanged tip is not a failure");

    let lagging = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let ahead = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 2);
    let mut unpinned = Peers::new(Chain::BitcoinRegtest, Vec::new(), dir.path());
    for mock in [&lagging, &ahead] {
        let peer = Peer::connect(Chain::BitcoinRegtest, mock.address, 0).unwrap();
        unpinned.connected.push(peer);
    }
    assert_eq!(unpinned.connected[0].address, lagging.address);
    sync_round(&shared, &mut unpinned).unwrap();
    assert_eq!(locked(&shared.headers, "headers").tip_height(), 6);
    assert_eq!(
        lagging.getheaders.load(Ordering::Acquire),
        0,
        "unpinned refreshes ask the highest announced peer first and stop at the best height"
    );
}

#[test]
fn an_inflated_announcement_costs_one_question_and_then_ranks_by_proof() {
    let chain = Arc::new(mock_peer::regtest_chain(7));
    let liar = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Announce(i32::MAX));
    let honest = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 2);
    let mut peers = Peers::new(Chain::BitcoinRegtest, Vec::new(), dir.path());
    for mock in [&liar, &honest] {
        let peer = Peer::connect(Chain::BitcoinRegtest, mock.address, 0).unwrap();
        peers.connected.push(peer);
    }
    assert_eq!(peers.best_height(2), 2 + P2P_HEIGHT_SLACK);
    sync_round(&shared, &mut peers).unwrap();
    assert_eq!(locked(&shared.headers, "headers").tip_height(), 6);
    assert_eq!(
        peers.best_height(6),
        6,
        "the lie no longer outranks the tip"
    );
    let first = peers.order_for_headers(6)[0];
    assert_eq!(
        peers.connected[first].address, honest.address,
        "the proven peer ranks ahead of the inflated one"
    );
}

#[test]
fn a_quiet_refresh_skips_an_unproven_peer_announcing_less_than_our_tip() {
    let chain = Arc::new(mock_peer::regtest_chain(7));
    let syncing = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Trickle);
    let synced = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 6);
    let mut peers = Peers::new(Chain::BitcoinRegtest, Vec::new(), dir.path());
    for mock in [&syncing, &synced] {
        let peer = Peer::connect(Chain::BitcoinRegtest, mock.address, 0).unwrap();
        peers.connected.push(peer);
    }
    let started = Instant::now();
    sync_round(&shared, &mut peers).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(syncing.getheaders.load(Ordering::Acquire), 0);
    assert!(synced.getheaders.load(Ordering::Acquire) >= 1);
    assert_eq!(peers.count(), 2);
}

#[test]
fn an_empty_answer_proves_nothing_and_a_tip_answer_proves_the_tip() {
    let chain = Arc::new(mock_peer::regtest_chain(7));
    let lagging = mock_peer::spawn(Arc::new(chain[..4].to_vec()), Behaviour::Serve);
    let synced = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let inflated = mock_peer::spawn(Arc::new(chain[..4].to_vec()), Behaviour::Announce(i32::MAX));
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 6);
    let mut peers = Peers::new(Chain::BitcoinRegtest, Vec::new(), dir.path());
    for mock in [&lagging, &synced, &inflated] {
        let peer = Peer::connect(Chain::BitcoinRegtest, mock.address, 0).unwrap();
        peers.connected.push(peer);
    }
    assert!(!sync_from(&shared, &mut peers, 2).unwrap());
    assert_eq!(peers.connected[2].proven_height, None);
    assert_eq!(
        peers.connected[2].height_hint(6),
        5,
        "an empty answer to a tip-1 locator means the peer lacks our tip"
    );
    assert!(!peers.order_for_block(6, 6).contains(&2));
    assert!(!sync_from(&shared, &mut peers, 0).unwrap());
    assert_eq!(peers.connected[0].proven_height, None);
    assert_eq!(peers.connected[0].height_hint(6), 3);
    assert!(!sync_from(&shared, &mut peers, 1).unwrap());
    assert_eq!(peers.connected[1].proven_height, Some(6));
    let holders = peers.order_for_block(5, 6);
    assert_eq!(
        holders,
        vec![1, 2],
        "the lagging peer (index 0) holds nothing above its height; the inflated peer stays an unproven candidate up to tip-1"
    );
}

#[test]
fn a_refresh_ends_at_the_first_peer_that_reaches_the_best_height() {
    let chain = Arc::new(mock_peer::regtest_chain(5));
    let first = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let second = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 1);
    let mut peers = connected(dir.path(), &[&first, &second]);
    let asked = second.getheaders.load(Ordering::Acquire);
    sync_round(&shared, &mut peers).unwrap();
    assert_eq!(locked(&shared.headers, "headers").tip_height(), 4);
    assert_eq!(
        second.getheaders.load(Ordering::Acquire),
        asked,
        "the second peer is not asked once the first reached the best height"
    );
}

#[test]
fn a_silent_block_holder_is_dropped_for_redial_and_low_peers_are_skipped() {
    let chain = Arc::new(mock_peer::regtest_chain(6));
    let lagging = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let silent = mock_peer::spawn(chain.clone(), Behaviour::SilentOnGetData);
    let good = mock_peer::spawn(chain.clone(), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 5);
    let mut peers = connected(dir.path(), &[&lagging, &silent, &good]);
    let mut flight = InFlight::default();
    let started = Instant::now();
    let raw = fetch_block(&shared, &mut peers, &mut flight, chain[4].block_hash()).unwrap();
    assert_eq!(raw, serialize(&chain[4]));
    while peers.count() == 3 {
        assert!(
            started.elapsed() < Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS + 4),
            "the silent holder was never dropped"
        );
        std::thread::sleep(Duration::from_millis(50));
        pipeline::settle(&shared, &mut peers, &mut flight);
    }
    assert!(
        started.elapsed() < Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS + 4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        lagging.getdata.load(Ordering::Acquire),
        0,
        "a peer that announced a lower height is not asked"
    );
    assert_eq!(silent.getdata.load(Ordering::Acquire), 1);
    assert_eq!(peers.count(), 2);
    assert_eq!(
        peers.redial_pending(),
        1,
        "a silent peer is redialed, not banned"
    );
}

#[test]
fn a_prefetch_asks_a_lone_holder_once_and_keeps_the_other_peers() {
    let chain = Arc::new(mock_peer::regtest_chain(8));
    let first = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let second = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let holder = mock_peer::spawn(chain.clone(), Behaviour::SilentOnGetData);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 7);
    let mut peers = connected(dir.path(), &[&first, &second, &holder]);
    let mut flight = InFlight::default();
    let raw = fetch_block(&shared, &mut peers, &mut flight, chain[2].block_hash()).unwrap();
    assert_eq!(raw, serialize(&chain[2]));
    let started = Instant::now();
    while peers.count() == 3 {
        assert!(
            started.elapsed() < Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS + 4),
            "the silent holder was never dropped"
        );
        std::thread::sleep(Duration::from_millis(50));
        pipeline::settle(&shared, &mut peers, &mut flight);
    }
    assert_eq!(holder.getdata.load(Ordering::Acquire), 1);
    assert_eq!(peers.count(), 2);
    let kept: Vec<_> = peers.connected.iter().map(|peer| peer.address).collect();
    assert_eq!(kept, vec![first.address, second.address]);
}

#[test]
fn unsolicited_blocks_are_dropped_and_only_requested_blocks_are_stashed() {
    let chain = Arc::new(mock_peer::regtest_chain(120));
    let flood = mock_peer::spawn(chain.clone(), Behaviour::Flood);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 119);
    let mut peers = connected(dir.path(), &[&flood]);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        peers.poll_idle();
        assert!(peers.connected[0].arrived.is_empty());
        assert!(peers.connected[0].lacking.is_empty());
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(peers.count(), 1, "a flood is dropped, not the peer");
    let mut flight = InFlight::default();
    let raw = fetch_block(&shared, &mut peers, &mut flight, chain[5].block_hash()).unwrap();
    assert_eq!(raw, serialize(&chain[5]));
    for _round in 0..10 {
        peers.poll_idle();
        assert!(peers.connected[0].arrived.len() <= P2P_PIPELINE_PER_PEER + 1);
        assert!(peers.connected[0].outstanding() <= P2P_PIPELINE_PER_PEER + 1);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_prefetch_notfound_keeps_the_peer() {
    let chain = Arc::new(mock_peer::regtest_chain(6));
    let first = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let second = mock_peer::spawn(Arc::new(chain[..3].to_vec()), Behaviour::Serve);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 5);
    let mut peers = connected(dir.path(), &[&first, &second]);
    let mut flight = InFlight::default();
    fetch_block(&shared, &mut peers, &mut flight, chain[2].block_hash()).unwrap();
    let started = Instant::now();
    while second.getdata.load(Ordering::Acquire) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "prefetch never asked"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(200));
    peers.poll_idle();
    pipeline::settle(&shared, &mut peers, &mut flight);
    assert_eq!(peers.count(), 2, "notfound to a prefetch is not a drop");
    assert_eq!(peers.redial_pending(), 0);
}

#[test]
fn a_silent_headers_request_drops_and_redials_but_never_bans() {
    let chain = Arc::new(mock_peer::regtest_chain(4));
    let trickle = mock_peer::spawn(chain.clone(), Behaviour::Trickle);
    let dir = tempfile::tempdir().unwrap();
    let shared = synced_shared(dir.path(), &chain, 1);
    let mut peers = connected(dir.path(), &[&trickle]);
    let started = Instant::now();
    let error = sync_round(&shared, &mut peers).unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(P2P_HEADERS_TIMEOUT_SECS - 1)
            && elapsed < Duration::from_secs(P2P_HEADERS_TIMEOUT_SECS + 4),
        "{elapsed:?}"
    );
    assert!(!matches!(error, Error::Invalid(_)), "{error}");
    assert_eq!(peers.count(), 0);
    assert_eq!(
        peers.redial_pending(),
        1,
        "a slow peer is redialed, not banned"
    );
}
