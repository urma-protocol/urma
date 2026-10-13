//! Peer book cases discovery depends on, beyond tests/peerbook.rs: gossip
//! address classes, IPv6 groups, a full operator book, the whole backoff
//! series, seed backoff and the gossip export bounds. No sockets; only the
//! persisted seed ban case writes a temporary book file.
use bitcoin::{BlockHash, hashes::Hash};
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde_json::json;
use urma_node::{
    Error,
    peer_protocol::GossipPeer,
    peerbook::{BookEntry, Origin, PeerBook},
};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const LOCAL: u16 = 999;

fn genesis() -> BlockHash {
    BlockHash::from_byte_array([42; 32])
}

// Synthetic SHA-256 peer IDs are routing fixtures, not claims about keys.
fn peer(index: u16) -> PeerId {
    let mut bytes = [0_u8; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    bytes[2..4].copy_from_slice(&index.to_be_bytes());
    PeerId::from_bytes(&bytes).unwrap()
}

fn bare(text: &str) -> Multiaddr {
    text.parse().unwrap()
}

fn named(text: &str, id: PeerId) -> Multiaddr {
    bare(text).with(Protocol::P2p(id))
}

/// One public IPv4 per index, each in its own /24.
fn spread(index: u16) -> Multiaddr {
    let [high, low] = index.to_be_bytes();
    bare(&format!("/ip4/11.{high}.{low}.1/tcp/4001"))
}

fn gossip(id: PeerId, addrs: &[&str]) -> GossipPeer {
    GossipPeer {
        peer_id: id,
        addrs: addrs.iter().map(|text| bare(text)).collect(),
        last_seen: NOW,
    }
}

fn merge(book: &mut PeerBook, peers: &[GossipPeer]) -> usize {
    book.merge(peers, peer(LOCAL), &[])
}

fn find(book: &PeerBook, id: PeerId) -> BookEntry {
    book.entries()
        .iter()
        .find(|entry| entry.peer_id == Some(id))
        .unwrap_or_else(|| panic!("{id} not in book"))
        .clone()
}

fn count(book: &PeerBook, origin: Origin) -> usize {
    book.entries()
        .iter()
        .filter(|entry| entry.origin == origin)
        .count()
}

fn snapshot(book: &PeerBook) -> Vec<String> {
    let mut entries: Vec<String> = book
        .entries()
        .iter()
        .map(|entry| format!("{entry:?}"))
        .collect();
    entries.sort_unstable();
    entries
}

#[test]
fn gossip_rejects_names_mapped_reserved_private_and_link_local_addresses() {
    let refused = [
        "/dns4/peer.example/tcp/4001",
        "/dns6/peer.example/tcp/4001",
        "/dns/peer.example/tcp/4001",
        "/dnsaddr/peer.example",
        // A mapped address is judged as the IPv4 address it carries.
        "/ip6/::ffff:127.0.0.1/tcp/4001",
        "/ip6/::ffff:10.0.0.1/tcp/4001",
        "/ip4/240.0.0.1/tcp/4001",
        "/ip4/192.0.2.1/tcp/4001",
        "/ip4/100.64.0.1/tcp/4001",
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/10.1.2.3/tcp/4001",
        "/ip4/172.16.0.1/tcp/4001",
        "/ip4/192.168.1.1/tcp/4001",
        "/ip4/169.254.1.1/tcp/4001",
        "/ip6/::1/tcp/4001",
        "/ip6/fd00::1/tcp/4001",
        "/ip6/fe80::1/tcp/4001",
    ];
    let mut book = PeerBook::empty(genesis());
    for (index, text) in (1..).zip(refused) {
        let address = named(text, peer(index));
        assert!(book.add(address, Origin::Gossip).is_err(), "{text}");
        assert_eq!(
            merge(&mut book, &[gossip(peer(index), &[text])]),
            0,
            "{text}"
        );
    }
    assert!(book.entries().is_empty());
    let mixed = gossip(
        peer(50),
        &[
            "/dns4/peer.example/tcp/1",
            "/ip4/9.9.9.9/tcp/1",
            "/ip6/::ffff:192.168.1.1/tcp/1",
        ],
    );
    assert_eq!(merge(&mut book, &[mixed]), 1);
    assert_eq!(
        find(&book, peer(50)).addrs,
        vec![bare("/ip4/9.9.9.9/tcp/1")]
    );
    // An operator may configure every one of them.
    for (index, text) in (100..).zip(refused) {
        let added = book.add(named(text, peer(index)), Origin::Manual);
        assert!(added.unwrap(), "{text}");
    }
    assert_eq!(count(&book, Origin::Manual), refused.len());
}

#[test]
fn gossip_group_cap_covers_ipv6_48_and_ignores_operator_entries() {
    let mut book = PeerBook::empty(genesis());
    let v6 = [
        "/ip6/2a01:4f8:1::1/tcp/1",
        "/ip6/2a01:4f8:1:ff::2/tcp/1",
        "/ip6/2a01:4f8:1:abcd::3/tcp/1",
    ];
    for (index, text) in (1..).zip(v6) {
        merge(&mut book, &[gossip(peer(index), &[text])]);
    }
    assert_eq!(count(&book, Origin::Gossip), PeerBook::GROUP_LIMIT);
    let full = named("/ip6/2a01:4f8:1:1::4/tcp/1", peer(4));
    assert!(matches!(
        book.add(full, Origin::Gossip),
        Err(Error::Busy(_))
    ));
    let next = named("/ip6/2a01:4f8:2::1/tcp/1", peer(5));
    assert!(book.add(next, Origin::Gossip).unwrap());
    // Re-announcing a stored address is not a new member of its group.
    assert!(!book.add(named(v6[0], peer(1)), Origin::Gossip).unwrap());
    // Operator entries inside a full group are accepted and never counted.
    let manual = named("/ip6/2a01:4f8:1::9/tcp/1", peer(6));
    assert!(book.add(manual, Origin::Manual).unwrap());
    assert!(
        book.add(bare("/ip6/2a01:4f8:1::10/tcp/1"), Origin::Seed)
            .unwrap()
    );
    let still_full = named("/ip6/2a01:4f8:1::11/tcp/1", peer(7));
    assert!(book.add(still_full, Origin::Gossip).is_err());
    assert_eq!(count(&book, Origin::Gossip), 3);
}

#[test]
fn a_full_operator_book_refuses_instead_of_evicting() {
    let mut book = PeerBook::empty(genesis());
    for index in 0..1024 {
        let origin = if index % 2 == 0 {
            Origin::Manual
        } else {
            Origin::Seed
        };
        book.add(spread(index).with(Protocol::P2p(peer(index))), origin)
            .unwrap();
    }
    assert_eq!(book.entries().len(), PeerBook::CAPACITY);
    let before = snapshot(&book);
    let extra = spread(2000).with(Protocol::P2p(peer(2000)));
    assert!(matches!(
        book.add(extra.clone(), Origin::Gossip),
        Err(Error::Busy(_))
    ));
    assert!(matches!(
        book.add(extra, Origin::Manual),
        Err(Error::Busy(_))
    ));
    let peers = [GossipPeer {
        peer_id: peer(2001),
        addrs: vec![spread(2001)],
        last_seen: NOW,
    }];
    assert_eq!(merge(&mut book, &peers), 0);
    assert_eq!(snapshot(&book), before);
}

#[test]
fn backoff_series_reaches_the_day_cap_and_failures_keep_last_success() {
    let mut book = PeerBook::empty(genesis());
    let id = peer(1);
    let dial = named("/ip4/8.8.8.8/tcp/4001", id);
    book.add(dial.clone(), Origin::Manual).unwrap();
    book.succeeded(&dial, id, peer(LOCAL), NOW - 5);
    let mut delays = Vec::new();
    for _ in 0..40 {
        book.failed(&dial, NOW);
        let entry = find(&book, id);
        let delay = entry.banned_until.unwrap() - NOW;
        assert!(book.candidates(NOW + delay - 1, &[], &[], 8).is_empty());
        assert_eq!(
            book.candidates(NOW + delay, &[], &[], 8),
            vec![dial.clone()]
        );
        assert_eq!(entry.last_success, Some(NOW - 5));
        delays.push(delay);
    }
    // 60 s × 2^(failures − 1): 60, 120, 240 ... capped at one day for good.
    let expected: Vec<u64> = (0..40)
        .map(|step| 2_u64.checked_pow(step).map_or(DAY, |f| (60 * f).min(DAY)))
        .collect();
    assert_eq!(delays, expected);
    assert_eq!(find(&book, id).failures, 40);
}

#[test]
fn named_seeds_stay_unidentified_and_the_local_node_is_dropped() {
    let mut book = PeerBook::empty(genesis());
    let named_seed = bare("/dnsaddr/seed.example");
    book.add(named_seed.clone(), Origin::Seed).unwrap();
    book.succeeded(&named_seed, peer(2), peer(LOCAL), NOW);
    let entry = book.entries()[0].clone();
    assert_eq!(entry.peer_id, None, "a name may resolve to many peers");
    assert_eq!((entry.last_success, entry.failures), (Some(NOW), 0));
    let ourselves = bare("/ip4/127.0.0.1/tcp/4002");
    book.add(ourselves.clone(), Origin::Seed).unwrap();
    book.succeeded(&ourselves, peer(LOCAL), peer(LOCAL), NOW);
    assert_eq!(book.entries().len(), 1, "the book never holds this node");
    assert_eq!(book.seeds(&[], None), vec![named_seed]);
}

#[test]
fn gossip_export_is_bounded_newest_first_and_merge_takes_four_addresses() {
    let mut book = PeerBook::empty(genesis());
    for index in 1..=40 {
        let address = spread(index).with(Protocol::P2p(peer(index)));
        book.add(address.clone(), Origin::Manual).unwrap();
        book.succeeded(&address, peer(index), peer(LOCAL), NOW + u64::from(index));
    }
    let answer = book.gossip(32, &[]);
    assert_eq!(answer.len(), 32);
    let seen: Vec<u64> = answer.iter().map(|entry| entry.last_seen).collect();
    assert!(seen.windows(2).all(|pair| pair[0] >= pair[1]), "{seen:?}");
    assert_eq!(seen[0], NOW + 40);
    assert!(answer.iter().all(|entry| entry.addrs.len() == 1));
    let many: Vec<String> = (1..=8)
        .map(|n| format!("/ip4/{n}.{n}.{n}.{n}/tcp/1"))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    merge(&mut book, &[gossip(peer(100), &refs)]);
    assert_eq!(find(&book, peer(100)).addrs.len(), PeerBook::ADDRESSES);
    let stats = book.stats();
    let counts = (stats.book, stats.reached, stats.reached_ever, stats.gossip);
    assert_eq!(counts, (41, 40, 40, 1));
}

#[test]
fn seeds_retry_within_ten_minutes_after_any_failures_while_gossip_backs_off_a_day() {
    let mut book = PeerBook::empty(genesis());
    let seed = bare("/dnsaddr/seed.example");
    book.add(seed.clone(), Origin::Seed).unwrap();
    let gossiped = named("/ip4/8.8.8.8/tcp/4001", peer(1));
    merge(&mut book, &[gossip(peer(1), &["/ip4/8.8.8.8/tcp/4001"])]);
    for _ in 0..20 {
        book.failed(&seed, NOW);
        book.failed(&gossiped, NOW);
    }
    let seeded = book.entries()[0].clone();
    assert_eq!((seeded.origin, seeded.failures), (Origin::Seed, 20));
    assert_eq!(seeded.banned_until, Some(NOW + PeerBook::SEED_BACKOFF_CAP));
    let retry = NOW + PeerBook::SEED_BACKOFF_CAP;
    assert!(book.seeds(&[], Some(retry - 1)).is_empty());
    assert_eq!(book.seeds(&[], Some(retry)), vec![seed.clone()]);
    let backed_off = find(&book, peer(1));
    assert_eq!(
        (backed_off.failures, backed_off.banned_until),
        (20, Some(NOW + DAY))
    );
    assert!(book.candidates(retry, &[], &[], 8).is_empty());
    assert_eq!(book.candidates(NOW + DAY, &[], &[], 8), vec![gossiped]);
    // The first seed failures still double: 60 s, then 120 s.
    let mut fresh = PeerBook::empty(genesis());
    fresh.add(seed.clone(), Origin::Seed).unwrap();
    for delay in [60, 120, 240, 480, 600, 600] {
        fresh.failed(&seed, NOW);
        assert_eq!(fresh.entries()[0].banned_until, Some(NOW + delay));
    }
    book.succeeded(&seed, peer(2), peer(LOCAL), retry);
    let reset = book.entries()[0].clone();
    assert_eq!((reset.failures, reset.banned_until), (0, None));
}

#[test]
fn a_seed_ban_persisted_beyond_ten_minutes_does_not_hold_the_seed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let entry = |address: &str, origin: &str| {
        json!({"peer_id":null,"addrs":[address],"origin":origin,
            "last_success":null,"failures":11,"banned_until":NOW + 50_000})
    };
    let document = json!({"version":2,"chain_genesis":genesis().to_string(),"entries":[
        entry("/dnsaddr/seed.example", "seed"),
        entry("/ip4/127.0.0.1/tcp/4001", "manual"),
    ]});
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let book = PeerBook::load(&path, genesis()).unwrap();
    assert_eq!(
        book.seeds(&[], Some(NOW)),
        vec![bare("/dnsaddr/seed.example")]
    );
    assert!(
        book.candidates(NOW, &[], &[], 8).is_empty(),
        "manual keeps its ban"
    );
}
