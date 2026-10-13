//! Local owned files only: no sockets, name resolution or peer startup.
use bitcoin::{BlockHash, hashes::Hash};
use libp2p::{Multiaddr, PeerId};
use serde_json::{Value, json};
use std::{fs, path::Path};
use urma_node::{
    Error,
    peer_protocol::GossipPeer,
    peerbook::{Origin, PeerAddress, PeerBook},
};

const FILE_LIMIT: usize = 1024 * 1024;

fn genesis() -> BlockHash {
    BlockHash::from_byte_array([42; 32])
}

// Synthetic SHA-256 peer IDs are routing fixtures, not claims about keys or
// authenticated connections. No identity generation or networking is needed.
fn peer(index: u16) -> PeerId {
    let mut bytes = [0_u8; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    bytes[2..4].copy_from_slice(&index.to_be_bytes());
    PeerId::from_bytes(&bytes).unwrap()
}

fn addr(text: &str) -> Multiaddr {
    text.parse().unwrap()
}

// A public IPv4 in its own /24 per index, so the group cap never interferes.
fn public(index: u16, id: PeerId) -> Multiaddr {
    let [high, low] = index.to_be_bytes();
    addr(&format!("/ip4/11.{high}.{low}.1/tcp/4001/p2p/{id}"))
}

fn local(port: u16) -> Multiaddr {
    addr(&format!("/ip4/127.0.0.1/tcp/{port}"))
}

fn empty() -> PeerBook {
    PeerBook::empty(genesis())
}

fn entry(book: &PeerBook, id: PeerId) -> &urma_node::peerbook::BookEntry {
    book.entries()
        .iter()
        .find(|entry| entry.peer_id == Some(id))
        .unwrap()
}

fn saved(entries: Vec<Value>) -> Value {
    json!({"version": 2, "chain_genesis": genesis().to_string(), "entries": entries})
}

fn saved_entry(id: PeerId, address: &str, origin: &str) -> Value {
    json!({"peer_id": id.to_string(), "addrs": [address], "origin": origin,
        "last_success": null, "failures": 0, "banned_until": null})
}

fn refused_unchanged(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    assert!(PeerBook::load(path, genesis()).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn addresses_allow_ip_tcp_with_matching_terminal_identity() {
    let id = peer(1);
    for prefix in [
        "/ip4/127.0.0.1/tcp/1",
        "/ip4/192.168.1.2/tcp/65535",
        "/ip4/8.8.8.8/tcp/4001",
        "/ip6/::1/tcp/1",
        "/ip6/fd00::1/tcp/4001",
        "/ip6/2001:db8::1/tcp/65535",
    ] {
        let multiaddr = addr(&format!("{prefix}/p2p/{id}"));
        let validated = PeerAddress::new(id, multiaddr.clone()).unwrap();
        assert_eq!(validated.peer_id(), id);
        assert_eq!(validated.address(), &multiaddr);
    }
}

#[test]
fn addresses_reject_unusable_ips_dns_ports_and_other_protocol_shapes() {
    let id = peer(1);
    for prefix in [
        "/ip4/0.0.0.0/tcp/4001",
        "/ip4/224.0.0.1/tcp/4001",
        "/ip4/255.255.255.255/tcp/4001",
        "/ip6/::/tcp/4001",
        "/ip6/ff02::1/tcp/4001",
        "/ip4/127.0.0.1/tcp/0",
        "/dns/example.invalid/tcp/4001",
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/tcp/4001/ws",
    ] {
        let multiaddr = addr(&format!("{prefix}/p2p/{id}"));
        assert!(
            matches!(PeerAddress::new(id, multiaddr), Err(Error::Invalid(_))),
            "{prefix}"
        );
    }
    let other = addr(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer(2)));
    assert!(PeerAddress::new(id, other).is_err());
}

#[test]
fn book_addresses_accept_dialable_shapes_and_refuse_the_rest() {
    let mut book = empty();
    let id = peer(1);
    for (index, text) in [
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{id}"),
        "/ip6/::1/tcp/4002".into(),
        "/dns4/seed.example/tcp/4003".into(),
        "/dnsaddr/seed.example".into(),
    ]
    .iter()
    .enumerate()
    {
        assert!(
            book.add(addr(text), Origin::Seed).unwrap(),
            "{index}: {text}"
        );
    }
    for text in [
        "/ip4/127.0.0.1/tcp/0",
        "/ip4/0.0.0.0/tcp/4001",
        "/ip4/127.0.0.1/udp/4001",
        "/dnsaddr/seed.example/tcp/4001",
        "/ip4/127.0.0.1/tcp/4001/ws",
    ] {
        assert!(book.add(addr(text), Origin::Manual).is_err(), "{text}");
    }
    assert_eq!(book.entries().len(), 4);
    assert_eq!(book.stats().seeds, 4);
}

#[test]
fn missing_book_is_empty_without_creating_files_or_directories() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("missing");
    let book = PeerBook::load(&parent.join("peers.json"), genesis()).unwrap();
    assert!(book.entries().is_empty());
    assert!(!parent.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn origins_only_upgrade_and_ip_seeds_learn_their_identity_on_success() {
    let mut book = empty();
    let (id, local_id) = (peer(1), peer(99));
    let address = public(1, id);
    assert!(book.add(address.clone(), Origin::Gossip).unwrap());
    assert!(!book.add(address.clone(), Origin::Gossip).unwrap());
    assert!(book.add(address.clone(), Origin::Seed).unwrap());
    assert!(book.add(address.clone(), Origin::Manual).unwrap());
    assert!(!book.add(address, Origin::Gossip).unwrap());
    assert_eq!(entry(&book, id).origin, Origin::Manual);
    book.add(local(5000), Origin::Seed).unwrap();
    book.succeeded(&local(5000), peer(2), local_id, 100);
    let learned = entry(&book, peer(2));
    assert_eq!((learned.last_success, learned.failures), (Some(100), 0));
    let named = addr("/dnsaddr/seed.example");
    book.add(named.clone(), Origin::Seed).unwrap();
    book.succeeded(&named, peer(3), local_id, 200);
    let seed = book
        .entries()
        .iter()
        .find(|e| e.addrs == [named.clone()])
        .unwrap();
    assert_eq!((seed.peer_id, seed.last_success), (None, Some(200)));
    book.add(local(5001), Origin::Manual).unwrap();
    book.succeeded(&local(5001), local_id, local_id, 300);
    assert!(
        book.entries()
            .iter()
            .all(|e| !e.addrs.contains(&local(5001)))
    );
    assert!(book.entries().iter().all(|e| e.peer_id != Some(local_id)));
}

#[test]
fn gossip_accepts_only_public_literal_ips_under_the_group_cap() {
    let mut book = empty();
    for (index, text) in [
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/10.1.2.3/tcp/4001",
        "/ip4/192.168.1.2/tcp/4001",
        "/ip4/172.16.0.9/tcp/4001",
        "/ip4/100.64.0.1/tcp/4001",
        "/ip4/169.254.0.1/tcp/4001",
        "/ip6/::1/tcp/4001",
        "/ip6/fd00::1/tcp/4001",
        "/ip6/fe80::1/tcp/4001",
        "/dns4/peer.example/tcp/4001",
        "/dnsaddr/peer.example",
    ]
    .iter()
    .enumerate()
    {
        let id = peer(u16::try_from(index).unwrap());
        let text = format!("{text}/p2p/{id}");
        assert!(book.add(addr(&text), Origin::Gossip).is_err(), "{text}");
    }
    assert!(book.entries().is_empty());
    assert!(book.add(local(4001), Origin::Manual).unwrap());
    for (index, last) in (1u16..).zip([1, 2]) {
        let text = format!("/ip4/8.8.8.{last}/tcp/4001/p2p/{}", peer(100 + index));
        assert!(book.add(addr(&text), Origin::Gossip).unwrap());
    }
    let crowded = addr(&format!("/ip4/8.8.8.3/tcp/4001/p2p/{}", peer(200)));
    assert!(matches!(
        book.add(crowded, Origin::Gossip),
        Err(Error::Busy(_))
    ));
    for (index, segment) in (1u16..).zip(["1", "2"]) {
        let text = format!(
            "/ip6/2a01:4f8:1::{segment}/tcp/4001/p2p/{}",
            peer(300 + index)
        );
        assert!(book.add(addr(&text), Origin::Gossip).unwrap());
    }
    let crowded = addr(&format!("/ip6/2a01:4f8:1:ff::9/tcp/4001/p2p/{}", peer(400)));
    assert!(matches!(
        book.add(crowded, Origin::Gossip),
        Err(Error::Busy(_))
    ));
    let elsewhere = addr(&format!("/ip6/2a01:4f8:2::1/tcp/4001/p2p/{}", peer(401)));
    assert!(book.add(elsewhere, Origin::Gossip).unwrap());
}

#[test]
fn capacity_evicts_the_worst_gossip_and_never_manual_or_seed() {
    let mut book = empty();
    for index in 0..1024 {
        book.add(public(index, peer(index)), Origin::Gossip)
            .unwrap();
    }
    let worst = public(7, peer(7));
    book.failed(&worst, 1000);
    book.failed(&worst, 1000);
    book.failed(&public(8, peer(8)), 1000);
    assert!(book.add(local(6000), Origin::Manual).unwrap());
    assert_eq!(book.entries().len(), 1024);
    assert!(book.entries().iter().all(|e| e.peer_id != Some(peer(7))));
    assert!(book.entries().iter().any(|e| e.peer_id == Some(peer(8))));
    let mut operators = empty();
    for port in 1..=1024 {
        let origin = if port % 2 == 0 {
            Origin::Manual
        } else {
            Origin::Seed
        };
        operators.add(local(port), origin).unwrap();
    }
    let full = operators.entries().to_vec();
    let gossip = public(2000, peer(2000));
    assert!(matches!(
        operators.add(gossip, Origin::Gossip),
        Err(Error::Busy(_))
    ));
    assert!(matches!(
        operators.add(local(2000), Origin::Manual),
        Err(Error::Busy(_))
    ));
    assert_eq!(operators.entries(), full.as_slice());
}

#[test]
fn backoff_doubles_from_sixty_seconds_capped_at_a_day_and_success_resets() {
    let mut book = empty();
    let id = peer(1);
    let address = public(1, id);
    book.add(address.clone(), Origin::Gossip).unwrap();
    for (failures, delay) in [(1, 60), (2, 120), (3, 240), (10, 30_720)] {
        while entry(&book, id).failures < failures {
            book.failed(&address, 1_000);
        }
        assert_eq!(entry(&book, id).banned_until, Some(1_000 + delay));
    }
    for _ in 0..40 {
        book.failed(&address, 1_000);
    }
    assert_eq!(entry(&book, id).banned_until, Some(1_000 + 86_400));
    book.succeeded(&address, id, peer(99), 5_000);
    let reset = entry(&book, id);
    assert_eq!((reset.failures, reset.banned_until), (0, None));
    assert_eq!(reset.last_success, Some(5_000));
}

#[test]
fn candidates_prefer_untried_and_skip_banned_seed_connected_and_omitting() {
    let mut book = empty();
    let ids: Vec<PeerId> = (1..=6).map(peer).collect();
    for (index, id) in (1u16..).zip(&ids) {
        let origin = if index == 4 {
            Origin::Seed
        } else {
            Origin::Gossip
        };
        book.add(public(index, *id), origin).unwrap();
    }
    book.failed(&public(2, ids[1]), 0);
    book.failed(&public(3, ids[2]), 10_000);
    let omitting = vec![ids[5].to_string()];
    let picked = book.candidates(1_000, &[ids[4]], &omitting, 10);
    assert_eq!(picked, vec![public(1, ids[0]), public(2, ids[1])]);
    assert_eq!(book.candidates(1_000, &[ids[4]], &omitting, 1).len(), 1);
    assert_eq!(book.seeds(&[], Some(1_000)), vec![public(4, ids[3])]);
    assert!(book.seeds(&[ids[3].to_string()], None).is_empty());
    book.failed(&public(4, ids[3]), 1_000);
    assert!(book.seeds(&[], Some(1_059)).is_empty());
    assert_eq!(book.seeds(&[], Some(1_060)), vec![public(4, ids[3])]);
    assert_eq!(book.seeds(&[], None), vec![public(4, ids[3])]);
}

#[test]
fn candidates_alternate_fresh_and_tried_entries() {
    let mut book = empty();
    for index in 1..=6 {
        book.add(public(index, peer(index)), Origin::Gossip)
            .unwrap();
    }
    for index in 4..=6 {
        book.succeeded(&public(index, peer(index)), peer(index), peer(99), 10);
    }
    let fresh = |address: &Multiaddr| (1..=3).any(|index| *address == public(index, peer(index)));
    let picked = book.candidates(1_000, &[], &[], 2);
    assert!(fresh(&picked[0]));
    assert_eq!(picked[1], public(4, peer(4)));
    let all = book.candidates(1_000, &[], &[], 10);
    assert_eq!(all.len(), 6);
    for (slot, index) in [(1, 4), (3, 5), (5, 6)] {
        assert_eq!(all[slot], public(index, peer(index)));
        assert!(fresh(&all[slot - 1]));
    }
}

#[test]
fn gossip_never_relabels_or_extends_known_entries_but_identify_may_extend() {
    let mut book = empty();
    let (id, other, local_id) = (peer(1), peer(2), peer(99));
    book.add(addr("/ip4/11.0.1.1/tcp/4001"), Origin::Seed)
        .unwrap();
    assert!(!book.add(public(1, id), Origin::Gossip).unwrap());
    let seed = &book.entries()[0];
    assert_eq!((seed.peer_id, seed.origin), (None, Origin::Seed));
    let report = |address: Multiaddr| {
        [GossipPeer {
            peer_id: id,
            addrs: vec![address],
            last_seen: 1,
        }]
    };
    assert_eq!(
        book.merge_identified(&report(public(1, id)), local_id, &[]),
        0
    );
    assert_eq!(book.entries()[0].peer_id, None);
    book.add(public(2, other), Origin::Gossip).unwrap();
    let second = addr(&format!("/ip4/11.0.3.1/tcp/4001/p2p/{other}"));
    assert!(!book.add(second.clone(), Origin::Gossip).unwrap());
    let claim = [GossipPeer {
        peer_id: other,
        addrs: vec![second],
        last_seen: 1,
    }];
    assert_eq!(book.merge(&claim, local_id, &[]), 0);
    assert_eq!(entry(&book, other).addrs.len(), 1);
    assert_eq!(book.merge_identified(&claim, local_id, &[]), 1);
    assert_eq!(entry(&book, other).addrs.len(), 2);
}

#[test]
fn sync_and_gossip_exports_use_identified_verified_public_entries_only() {
    let mut book = empty();
    let (verified, fresh, hidden) = (peer(1), peer(2), peer(3));
    book.add(public(1, verified), Origin::Gossip).unwrap();
    book.add(public(2, fresh), Origin::Gossip).unwrap();
    book.add(public(3, hidden), Origin::Gossip).unwrap();
    book.add(local(4000), Origin::Seed).unwrap();
    book.succeeded(&public(1, verified), verified, peer(99), 50);
    book.succeeded(&public(3, hidden), hidden, peer(99), 60);
    let omitting = vec![hidden.to_string()];
    let sync: Vec<PeerId> = book
        .sync_addresses(&omitting)
        .iter()
        .map(PeerAddress::peer_id)
        .collect();
    assert_eq!(sync, vec![verified, fresh]);
    let gossip = book.gossip(32, &omitting);
    assert_eq!(gossip.len(), 1);
    assert_eq!(gossip[0].peer_id, verified);
    assert_eq!(gossip[0].last_seen, 50);
    assert_eq!(gossip[0].addrs, vec![addr("/ip4/11.0.1.1/tcp/4001")]);
    assert_eq!((book.stats().reached, book.stats().reached_ever), (2, 2));
    book.failed(&public(3, hidden), 70);
    assert_eq!((book.stats().reached, book.stats().reached_ever), (1, 2));
}

#[test]
fn merge_skips_self_omitting_and_mismatched_identities() {
    let mut book = empty();
    let (local_id, omitter, good, liar) = (peer(90), peer(91), peer(92), peer(93));
    let announce = |id: PeerId, address: Multiaddr| GossipPeer {
        peer_id: id,
        addrs: vec![address],
        last_seen: 1,
    };
    let peers = [
        announce(local_id, public(1, local_id)),
        announce(omitter, public(2, omitter)),
        announce(good, public(3, good)),
        announce(liar, public(4, peer(94))),
        announce(peer(95), local(4001)),
    ];
    let added = book.merge(&peers, local_id, &[omitter.to_string()]);
    assert_eq!(added, 1);
    assert_eq!(book.entries().len(), 1);
    assert_eq!(entry(&book, good).origin, Origin::Gossip);
    assert_eq!(entry(&book, good).last_success, None);
}

#[test]
fn merge_stores_every_admissible_address_of_a_new_peer_in_one_entry() {
    let mut book = empty();
    let (id, local_id) = (peer(1), peer(99));
    book.add(addr("/ip4/11.0.9.1/tcp/4001"), Origin::Seed)
        .unwrap();
    let addrs = [
        "/ip4/11.0.1.1/tcp/4001",
        "/ip4/11.0.2.1/tcp/4001",
        "/ip4/11.0.2.1/tcp/4001",
        "/ip4/11.0.9.1/tcp/4001",
        "/ip4/10.0.0.1/tcp/4001",
    ];
    let claim = [GossipPeer {
        peer_id: id,
        addrs: addrs.iter().map(|text| addr(text)).collect(),
        last_seen: 1,
    }];
    assert_eq!(book.merge(&claim, local_id, &[]), 2);
    assert_eq!(
        entry(&book, id).addrs,
        vec![
            addr("/ip4/11.0.1.1/tcp/4001"),
            addr("/ip4/11.0.2.1/tcp/4001")
        ]
    );
    assert_eq!(book.entries().len(), 2);
    assert_eq!(book.merge(&claim, local_id, &[]), 0);
}

#[test]
fn saved_book_round_trips_sorted_with_every_field() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut book = empty();
    for index in [50, 3, 256, 1] {
        book.add(public(index, peer(index)), Origin::Gossip)
            .unwrap();
    }
    book.add(addr("/dnsaddr/seed.example"), Origin::Seed)
        .unwrap();
    book.failed(&public(3, peer(3)), 77);
    book.succeeded(&public(1, peer(1)), peer(1), peer(99), 88);
    book.save(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["version"], 2);
    assert_eq!(saved["chain_genesis"], genesis().to_string());
    let entries = saved["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 5);
    assert!(
        entries[0]["peer_id"].is_null(),
        "unidentified seeds sort first"
    );
    let keys: Vec<String> = entries[1..]
        .iter()
        .map(|e| e["peer_id"].to_string())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let reloaded = PeerBook::load(&path, genesis()).unwrap();
    assert_eq!(entry(&reloaded, peer(3)).banned_until, Some(77 + 60));
    assert_eq!(entry(&reloaded, peer(1)).last_success, Some(88));
    reloaded.save(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn load_rejects_old_version_bad_schema_and_network_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let id = peer(1);
    let good = saved(vec![saved_entry(id, "/ip4/127.0.0.1/tcp/4001", "manual")]);
    let mut fixtures = Vec::new();
    for (field, value) in [
        ("version", json!(1)),
        (
            "chain_genesis",
            json!(BlockHash::from_byte_array([43; 32]).to_string()),
        ),
        ("chain_genesis", json!("bad")),
        ("extra", json!(true)),
    ] {
        let mut changed = good.clone();
        changed[field] = value;
        fixtures.push(changed);
    }
    for (field, value) in [
        ("extra", json!(true)),
        ("peer_id", json!("bad")),
        ("addrs", json!([])),
        ("addrs", json!(["bad"])),
        (
            "addrs",
            json!([format!("/ip4/127.0.0.1/tcp/4001/p2p/{id}")]),
        ),
        (
            "addrs",
            json!(["/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/tcp/4001"]),
        ),
        ("origin", json!("learned")),
        ("failures", json!(-1)),
    ] {
        let mut changed = good.clone();
        changed["entries"][0][field] = value;
        fixtures.push(changed);
    }
    let mut gossip = good.clone();
    gossip["entries"][0]["origin"] = json!("gossip");
    fixtures.push(gossip);
    for value in fixtures {
        refused_unchanged(&path, &serde_json::to_vec(&value).unwrap());
    }
    for bytes in [b"".as_slice(), b"{", b"null", b"[]"] {
        refused_unchanged(&path, bytes);
    }
}

#[test]
fn load_rejects_duplicate_peers_addresses_and_capacity_overflow() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let id = peer(1);
    for value in [
        saved(vec![
            saved_entry(id, "/ip4/127.0.0.1/tcp/4001", "manual"),
            saved_entry(id, "/ip4/127.0.0.1/tcp/4002", "seed"),
        ]),
        saved(vec![
            saved_entry(id, "/ip4/127.0.0.1/tcp/4001", "manual"),
            saved_entry(peer(2), "/ip4/127.0.0.1/tcp/4001", "manual"),
        ]),
        saved(
            (0..1025)
                .map(|port| {
                    saved_entry(
                        peer(port),
                        &format!("/ip4/127.0.0.1/tcp/{}", port + 1),
                        "seed",
                    )
                })
                .collect(),
        ),
    ] {
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() <= FILE_LIMIT);
        refused_unchanged(&path, &bytes);
    }
    let mut five = saved_entry(id, "/ip4/127.0.0.1/tcp/1", "manual");
    five["addrs"] = json!(
        (1..=5)
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect::<Vec<_>>()
    );
    refused_unchanged(&path, &serde_json::to_vec(&saved(vec![five])).unwrap());
}

#[test]
fn load_byte_limit_is_exact_and_precedes_json_decode() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut bytes = serde_json::to_vec(&saved(Vec::new())).unwrap();
    bytes.resize(FILE_LIMIT, b' ');
    fs::write(&path, &bytes).unwrap();
    assert!(
        PeerBook::load(&path, genesis())
            .unwrap()
            .entries()
            .is_empty()
    );
    bytes.push(b' ');
    refused_unchanged(&path, &bytes);
}

#[test]
fn load_refuses_nonregular_and_non_notfound_errors() {
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        PeerBook::load(temp.path(), genesis()),
        Err(Error::Invalid(_))
    ));
    let file = temp.path().join("file");
    fs::write(&file, b"untouched").unwrap();
    assert!(matches!(
        PeerBook::load(&file.join("peers.json"), genesis()),
        Err(Error::Io(_))
    ));
    assert_eq!(fs::read(file).unwrap(), b"untouched");
}

#[test]
fn save_requires_existing_directory_and_propagates_io_source_errors() {
    let temp = tempfile::tempdir().unwrap();
    let mut book = empty();
    book.add(local(4001), Origin::Manual).unwrap();
    let missing = temp.path().join("missing");
    assert!(matches!(
        book.save(&missing.join("peers.json")),
        Err(Error::Source(_))
    ));
    assert!(!missing.exists());
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(matches!(book.save(&directory), Err(Error::Source(_))));
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_and_new_saved_files_use_private_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    empty().save(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let linked = temp.path().join("link");
    symlink(&path, &linked).unwrap();
    assert!(matches!(
        PeerBook::load(&linked, genesis()),
        Err(Error::Invalid(_))
    ));
}
