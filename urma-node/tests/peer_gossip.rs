//! Protocol v4 gossip between two actual TCP/Noise/Yamux endpoints on owned
//! loopback: explicit dial with the Peers chain probe, gossip filtering, and
//! the address classes discovery relies on. Hints are untrusted routing data.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use common::{config, profile, witness_block};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use std::{
    fs,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use urma_node::{
    Error,
    engine::Engine,
    model::Retention,
    peer::PeerNetwork,
    peer_gossip::{ObservedAddrs, is_public, validate_dial, validate_gossip_address},
    peer_protocol::GossipPeer,
};

fn node(root: &Path, name: &str, nonce: u32) -> (Arc<Engine>, PeerNetwork) {
    announcing(root, name, nonce, &[]).unwrap()
}

fn announcing(
    root: &Path,
    name: &str,
    nonce: u32,
    announce: &[&str],
) -> Result<(Arc<Engine>, PeerNetwork), Error> {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    let pair = profile();
    let block = witness_block(&[pair.commit, pair.reveal], None, nonce);
    let engine =
        Arc::new(Engine::open(&directory, config(&block, Retention::Unpruned), None).unwrap());
    let listen = Some("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    let announce = announce.iter().map(|text| text.parse().unwrap()).collect();
    let network = PeerNetwork::start(
        engine.clone(),
        Keypair::generate_ed25519(),
        listen,
        announce,
    )?;
    Ok((engine, network))
}

#[test]
fn identify_carries_announced_public_addresses_but_not_private_listeners() {
    let root = tempfile::tempdir().unwrap();
    let announced = "/ip4/8.8.8.8/tcp/28332";
    let (_engine_a, network_a) = node(root.path(), "a", 1);
    let (_engine_b, network_b) = announcing(root.path(), "b", 2, &[announced]).unwrap();
    let idle = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    let listen_b = network_b.listen_address().unwrap();
    let dialed = network_a.dial(listen_b, &idle, deadline).unwrap();
    let mut identified = Vec::new();
    while identified.is_empty() && Instant::now() < deadline {
        identified = network_a.drain_identified();
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(identified, vec![(dialed, vec![announced.parse().unwrap()])]);
    assert!(
        network_a.drain_identified().is_empty(),
        "draining empties the queue"
    );
    for rejected in [
        "/dns4/me.example.org/tcp/1",
        "/ip4/8.8.8.8/udp/1",
        "/ip4/127.0.0.1/tcp/1",
        "/ip4/10.0.0.1/tcp/1",
    ] {
        assert!(
            announcing(root.path(), "c", 3, &[rejected]).is_err(),
            "{rejected}"
        );
    }
    network_a.shutdown().unwrap();
    network_b.shutdown().unwrap();
}

fn without_peer(address: &Multiaddr) -> Multiaddr {
    address
        .iter()
        .filter(|part| !matches!(part, Protocol::P2p(_)))
        .collect()
}

fn hint(peer: PeerId, addresses: &[&str]) -> GossipPeer {
    GossipPeer {
        peer_id: peer,
        addrs: addresses
            .iter()
            .map(|address| format!("{address}/p2p/{peer}").parse().unwrap())
            .collect(),
        last_seen: 1_760_000_000,
    }
}

#[test]
fn dial_probes_the_chain_and_loopback_requesters_receive_private_gossip() {
    let root = tempfile::tempdir().unwrap();
    let (_engine_a, network_a) = node(root.path(), "a", 1);
    let (_engine_b, network_b) = node(root.path(), "b", 2);
    let deadline = || Instant::now() + Duration::from_secs(10);
    let idle = AtomicBool::new(false);
    let other = Keypair::generate_ed25519().public().to_peer_id();
    let private = hint(other, &["/ip4/10.0.0.1/tcp/8333", "/ip4/8.8.8.8/tcp/8333"]);
    let requester = hint(network_a.peer_id(), &["/ip4/8.8.4.4/tcp/1"]);
    let itself = hint(network_b.peer_id(), &["/ip4/8.8.4.4/tcp/2"]);
    let named_only = hint(
        Keypair::generate_ed25519().public().to_peer_id(),
        &["/dns4/seed.example.org/tcp/8333"],
    );
    let mut future = hint(
        Keypair::generate_ed25519().public().to_peer_id(),
        &["/ip4/9.9.9.9/tcp/1"],
    );
    future.last_seen = u64::MAX;
    network_b.set_gossip(vec![
        requester,
        itself,
        named_only,
        private.clone(),
        future.clone(),
    ]);
    let listen_b = network_b.listen_address().unwrap();
    let dialed = network_a
        .dial(without_peer(&listen_b), &idle, deadline())
        .unwrap();
    assert_eq!(dialed, network_b.peer_id());
    assert_eq!(network_a.connected_peer_ids(), vec![dialed]);
    assert_eq!(network_a.connected_peers(), 1);
    assert_eq!(
        network_a.dial(listen_b.clone(), &idle, deadline()).unwrap(),
        dialed
    );
    let gossip = network_a.peers_of(dialed, 32, &idle, deadline()).unwrap();
    assert_eq!(
        gossip.len(),
        2,
        "no requester, no server, no DNS-only entry"
    );
    assert_eq!(
        gossip[0], private,
        "loopback requesters get private literals"
    );
    assert_eq!(gossip[1].peer_id, future.peer_id);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(gossip[1].last_seen <= now, "future last_seen is clamped");
    assert!(
        network_a
            .peers_of(dialed, 0, &idle, deadline())
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        network_a.peers_of(dialed, 33, &idle, deadline()),
        Err(Error::Invalid(_))
    ));
    let mut impostor = without_peer(&listen_b);
    impostor.push(Protocol::P2p(other));
    assert!(network_a.dial(impostor, &idle, deadline()).is_err());
    assert!(
        network_a.observed_addrs().is_empty(),
        "loopback is not public"
    );
    assert!(network_b.observed_addrs().is_empty());
    network_a.shutdown().unwrap();
    network_b.shutdown().unwrap();
}

#[test]
fn dial_addresses_and_public_classes_are_explicit() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    for (text, named) in [
        ("/ip4/1.2.3.4/tcp/8333".to_owned(), None),
        (
            format!("/dns4/seed.example.org/tcp/1/p2p/{peer}"),
            Some(peer),
        ),
        (
            format!("/dnsaddr/bootstrap.example.org/p2p/{peer}"),
            Some(peer),
        ),
        ("/ip6/2001:4860::1/tcp/9".to_owned(), None),
    ] {
        assert_eq!(
            validate_dial(&text.parse().unwrap()).unwrap(),
            named,
            "{text}"
        );
    }
    for text in [
        "/ip4/1.2.3.4/udp/1",
        "/ip4/1.2.3.4/tcp/0",
        "/ip4/1.2.3.4",
        "/dnsaddr/x.example/tcp/1",
        "/ip4/1.2.3.4/tcp/1/ws",
    ] {
        assert!(validate_dial(&text.parse().unwrap()).is_err(), "{text}");
    }
    for (text, public) in [
        ("/ip4/8.8.8.8/tcp/1", true),
        ("/ip4/0.1.2.3/tcp/1", false),
        ("/ip4/192.0.0.8/tcp/1", false),
        ("/ip4/198.19.255.1/tcp/1", false),
        ("/ip4/198.20.0.1/tcp/1", true),
        ("/ip4/240.0.0.1/tcp/1", false),
        ("/ip6/::ffff:10.0.0.1/tcp/1", false),
        ("/ip6/::ffff:127.0.0.1/tcp/1", false),
        ("/ip6/::ffff:8.8.8.8/tcp/1", true),
        ("/ip6/2001:db8::1/tcp/1", false),
        ("/ip4/127.0.0.1/tcp/1", false),
        ("/ip4/192.168.1.1/tcp/1", false),
        ("/ip4/100.64.0.1/tcp/1", false),
        ("/ip6/::1/tcp/1", false),
        ("/ip6/fd00::1/tcp/1", false),
        ("/ip6/2001:4860::1/tcp/1", true),
        ("/dns4/localhost/tcp/1", false),
        ("/dnsaddr/bootstrap.example.org", true),
    ] {
        assert_eq!(is_public(&text.parse().unwrap()), public, "{text}");
    }
    for text in [
        "/dns4/seed.example.org/tcp/1",
        "/dns/seed.example.org/tcp/1",
        "/dnsaddr/bootstrap.example.org",
    ] {
        let address = text.parse().unwrap();
        assert!(validate_dial(&address).is_ok(), "operators may name {text}");
        assert!(
            validate_gossip_address(&address).is_err(),
            "gossip never names {text}"
        );
    }
    assert!(validate_gossip_address(&"/ip6/2001:4860::1/tcp/9".parse().unwrap()).is_ok());
}

#[test]
fn observed_addresses_need_two_distinct_witnesses() {
    let witness = || Keypair::generate_ed25519().public().to_peer_id();
    let (first, second) = (witness(), witness());
    let public: Multiaddr = "/ip4/8.8.8.8/tcp/28332".parse().unwrap();
    let mut observed = ObservedAddrs::default();
    observed.observe(public.clone(), first);
    observed.observe(public.clone(), first);
    assert!(
        observed.confirmed().is_empty(),
        "one witness repeating is not two"
    );
    for rejected in ["/ip4/10.0.0.1/tcp/1", "/dns4/me.example.org/tcp/1"] {
        observed.observe(rejected.parse().unwrap(), first);
        observed.observe(rejected.parse().unwrap(), second);
    }
    assert!(
        observed.confirmed().is_empty(),
        "private and named never confirm"
    );
    observed.observe(public.clone(), second);
    assert_eq!(observed.confirmed(), vec![public.clone()]);
    observed.observe(public.clone(), witness());
    assert_eq!(observed.confirmed(), vec![public]);
}
