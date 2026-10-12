//! Local owned files only: no sockets, name resolution or peer startup.
use bitcoin::{BlockHash, hashes::Hash};
use libp2p::{Multiaddr, PeerId};
use serde_json::{Value, json};
use std::{fs, path::Path};
use urma_node::{
    Error,
    peerbook::{Origin, PeerAddress, PeerBook},
};

const FILE_LIMIT: usize = 256 * 1024;

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

fn address(id: PeerId, port: u16) -> PeerAddress {
    PeerAddress::new(
        id,
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{id}")
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn snapshot(book: &PeerBook) -> Vec<(String, String, Origin)> {
    book.entries()
        .into_iter()
        .map(|(address, origin)| {
            (
                address.peer_id().to_string(),
                address.address().to_string(),
                origin,
            )
        })
        .collect()
}

fn entry(id: PeerId, port: u16, origin: &str) -> Value {
    json!({
        "peer_id": id.to_string(),
        "address": address(id, port).address().to_string(),
        "origin": origin,
    })
}

fn document(entries: Vec<Value>) -> Value {
    json!({"version": 1, "chain_genesis": genesis().to_string(), "entries": entries})
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
        let multiaddr: Multiaddr = format!("{prefix}/p2p/{id}").parse().unwrap();
        let validated = PeerAddress::new(id, multiaddr.clone()).unwrap();
        assert_eq!(validated.peer_id(), id);
        assert_eq!(validated.address(), &multiaddr);
        assert_eq!(validated.clone().address(), &multiaddr);
    }
}

#[test]
fn addresses_reject_unusable_ips_dns_ports_and_other_protocol_shapes() {
    let id = peer(1);
    for prefix in [
        "/ip4/0.0.0.0/tcp/4001",
        "/ip4/224.0.0.1/tcp/4001",
        "/ip4/239.255.255.255/tcp/4001",
        "/ip4/255.255.255.255/tcp/4001",
        "/ip6/::/tcp/4001",
        "/ip6/ff02::1/tcp/4001",
        "/ip4/127.0.0.1/tcp/0",
        "/ip6/::1/tcp/0",
        "/dns/example.invalid/tcp/4001",
        "/dns4/example.invalid/tcp/4001",
        "/dns6/example.invalid/tcp/4001",
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/udp/4001/quic-v1",
        "/ip4/127.0.0.1/tcp/4001/ws",
    ] {
        let multiaddr = format!("{prefix}/p2p/{id}").parse().unwrap();
        assert!(
            matches!(PeerAddress::new(id, multiaddr), Err(Error::Invalid(_))),
            "{prefix}"
        );
    }
    for text in [
        String::new(),
        "/ip4/127.0.0.1/tcp/4001".into(),
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer(2)),
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{id}/tcp/4002"),
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{id}/p2p/{id}"),
        format!("/p2p/{id}/ip4/127.0.0.1/tcp/4001"),
    ] {
        assert!(
            PeerAddress::new(id, text.parse().unwrap()).is_err(),
            "{text}"
        );
    }
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
fn origin_is_per_address_and_only_manual_upgrades_change_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut book = PeerBook::load(&path, genesis()).unwrap();
    let first = address(peer(1), 4001);
    assert!(book.insert(first.clone(), Origin::Learned).unwrap());
    assert!(!book.insert(first.clone(), Origin::Learned).unwrap());
    assert!(book.insert(first.clone(), Origin::Manual).unwrap());
    assert!(!book.insert(first.clone(), Origin::Manual).unwrap());
    assert!(!book.insert(first, Origin::Learned).unwrap());
    assert!(
        book.insert(address(peer(1), 4002), Origin::Learned)
            .unwrap()
    );
    assert_eq!(book.entries()[0].1, Origin::Manual);
    assert_eq!(book.entries()[1].1, Origin::Learned);
    assert!(!path.exists());
    book.save(&path).unwrap();
    let saved = snapshot(&PeerBook::load(&path, genesis()).unwrap());
    assert_eq!(snapshot(&book), saved);
    assert!(book.remove(peer(1)));
    assert!(!book.remove(peer(1)));
    assert!(book.entries().is_empty());
    assert_eq!(snapshot(&PeerBook::load(&path, genesis()).unwrap()), saved);
    book.save(&path).unwrap();
    assert!(
        PeerBook::load(&path, genesis())
            .unwrap()
            .entries()
            .is_empty()
    );
}

#[test]
fn snapshot_and_saved_entries_sort_by_peer_and_address_strings() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut book = PeerBook::load(&path, genesis()).unwrap();
    for index in [50, 3, 256, 1] {
        for port in [9000, 1000] {
            book.insert(address(peer(index), port), Origin::Manual)
                .unwrap();
        }
    }
    let ordered = snapshot(&book);
    let mut expected = ordered.clone();
    expected.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(ordered, expected);
    book.save(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["chain_genesis"], genesis().to_string());
    for (entry, (id, addr, _)) in saved["entries"].as_array().unwrap().iter().zip(&ordered) {
        assert_eq!(entry["peer_id"], *id);
        assert_eq!(entry["address"], *addr);
        assert_eq!(entry["origin"], "manual");
    }
    assert_eq!(
        snapshot(&PeerBook::load(&path, genesis()).unwrap()),
        ordered
    );
    book.save(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn capacity_refuses_without_eviction_and_duplicates_work_when_full() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut book = PeerBook::load(&path, genesis()).unwrap();
    for index in 0..256 {
        for port in 4001..4005 {
            book.insert(address(peer(index), port), Origin::Learned)
                .unwrap();
        }
    }
    let full = snapshot(&book);
    assert!(matches!(
        book.insert(address(peer(256), 4001), Origin::Manual),
        Err(Error::Busy(_))
    ));
    assert!(matches!(
        book.insert(address(peer(1), 4005), Origin::Manual),
        Err(Error::Busy(_))
    ));
    assert_eq!(snapshot(&book), full);
    assert!(
        !book
            .insert(address(peer(1), 4001), Origin::Learned)
            .unwrap()
    );
    assert!(book.insert(address(peer(1), 4001), Origin::Manual).unwrap());
    let upgraded = snapshot(&book);
    assert!(
        !book
            .insert(address(peer(1), 4001), Origin::Learned)
            .unwrap()
    );
    assert_eq!(snapshot(&book), upgraded);
    book.save(&path).unwrap();
    assert!(fs::metadata(&path).unwrap().len() <= FILE_LIMIT as u64);
    assert_eq!(
        snapshot(&PeerBook::load(&path, genesis()).unwrap()),
        upgraded
    );
    assert!(book.remove(peer(1)));
    assert!(
        book.insert(address(peer(256), 4001), Origin::Manual)
            .unwrap()
    );
    assert_eq!(book.entries().len(), 1021);
}

#[test]
fn load_rejects_bad_schema_identity_address_version_and_network_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let good = document(vec![entry(peer(1), 4001, "manual")]);
    let mut fixtures = Vec::new();
    let mut value = good.clone();
    value["version"] = json!(2);
    fixtures.push(value);
    let mut value = good.clone();
    value["chain_genesis"] = json!(BlockHash::from_byte_array([43; 32]).to_string());
    fixtures.push(value);
    let mut value = good.clone();
    value["chain_genesis"] = json!("bad");
    fixtures.push(value);
    let mut value = good.clone();
    value["extra"] = json!(true);
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["extra"] = json!(true);
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["peer_id"] = json!("bad");
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["address"] = json!("bad");
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["address"] = json!(address(peer(2), 4001).address().to_string());
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["address"] =
        json!(format!("/dns/example.invalid/tcp/4001/p2p/{}", peer(1)));
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]["origin"] = json!("other");
    fixtures.push(value);
    let mut value = good.clone();
    value.as_object_mut().unwrap().remove("entries");
    fixtures.push(value);
    let mut value = good.clone();
    value["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("origin");
    fixtures.push(value);
    for value in fixtures {
        refused_unchanged(&path, &serde_json::to_vec(&value).unwrap());
    }
    for bytes in [
        b"".as_slice(),
        b"{",
        b"null",
        b"[]",
        b"{\"version\":1,\"version\":1}",
    ] {
        refused_unchanged(&path, bytes);
    }
}

#[test]
fn load_rejects_duplicate_addresses_even_with_upgrade_or_canonical_alias() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    for origins in [
        ("manual", "manual"),
        ("learned", "manual"),
        ("manual", "learned"),
    ] {
        let value = document(vec![
            entry(peer(1), 4001, origins.0),
            entry(peer(1), 4001, origins.1),
        ]);
        refused_unchanged(&path, &serde_json::to_vec(&value).unwrap());
    }
    let id = peer(1);
    let value = document(vec![
        json!({"peer_id":id.to_string(), "address":format!("/ip6/::1/tcp/4001/p2p/{id}"), "origin":"manual"}),
        json!({"peer_id":id.to_string(), "address":format!("/ip6/0:0:0:0:0:0:0:1/tcp/4001/p2p/{id}"), "origin":"learned"}),
    ]);
    refused_unchanged(&path, &serde_json::to_vec(&value).unwrap());
}

#[test]
fn load_rejects_capacity_overflow_without_rewriting() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let fixtures = [
        document(
            (0..257)
                .map(|index| entry(peer(index), 4001, "manual"))
                .collect(),
        ),
        document(
            (4001..4006)
                .map(|port| entry(peer(1), port, "manual"))
                .collect(),
        ),
        document(vec![entry(peer(1), 4001, "manual"); 1025]),
    ];
    for value in fixtures {
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() <= FILE_LIMIT);
        refused_unchanged(&path, &bytes);
    }
}

#[test]
fn load_byte_limit_is_exact_and_precedes_json_decode() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let mut bytes = serde_json::to_vec(&document(Vec::new())).unwrap();
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
    refused_unchanged(&path, &vec![b'{'; FILE_LIMIT + 1]);
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
    let mut book = PeerBook::load(&temp.path().join("peers.json"), genesis()).unwrap();
    book.insert(address(peer(1), 4001), Origin::Manual).unwrap();
    let before = snapshot(&book);
    let missing = temp.path().join("missing");
    assert!(matches!(
        book.save(&missing.join("peers.json")),
        Err(Error::Source(_))
    ));
    assert!(!missing.exists());
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("marker"), b"untouched").unwrap();
    assert!(matches!(book.save(&directory), Err(Error::Source(_))));
    assert_eq!(fs::read(directory.join("marker")).unwrap(), b"untouched");
    assert_eq!(snapshot(&book), before);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_and_new_saved_files_use_private_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("peers.json");
    let book = PeerBook::load(&path, genesis()).unwrap();
    book.save(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = fs::read(&path).unwrap();
    let linked = temp.path().join("link");
    symlink(&path, &linked).unwrap();
    assert!(matches!(
        PeerBook::load(&linked, genesis()),
        Err(Error::Invalid(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    let dangling = temp.path().join("dangling");
    symlink(temp.path().join("absent"), &dangling).unwrap();
    assert!(matches!(
        PeerBook::load(&dangling, genesis()),
        Err(Error::Invalid(_))
    ));
}
