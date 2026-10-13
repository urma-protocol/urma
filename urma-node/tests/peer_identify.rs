//! Identify between real PeerNetworks in a private namespace (see
//! common/discovery_host.rs): an address peers observed for this node is
//! confirmed only after two distinct outbound peers report it, and a peer
//! that announces its address is learned by the node it dials. Outbound dials
//! reuse the listener port, so every witness sees the same public address.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
#[path = "common/discovery_host.rs"]
mod discovery_host;
#[allow(dead_code)]
#[path = "common/inventory_peer.rs"]
mod inventory_peer;
use discovery_host::{
    PUBLIC, announcing_node, bare, discover, entry_of, host, node, report, rounds, run, saved_book,
    stage, until,
};
use inventory_peer::RawPeer;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use urma_node::{
    peer_protocol::{Kind, Reply, VERSION},
    peerbook::{Origin, PeerAddress, PeerBook},
};

const HOST: &str = "peer_identify_host";
/// Long enough for identify to exchange on a fresh loopback connection.
const SETTLE: Duration = Duration::from_secs(3);
const IDLE_CLOSE: Duration = Duration::from_secs(40);

fn witnesses(root: &Path) -> Value {
    let a = node(root, "a", Some(PUBLIC[0]));
    let b = node(root, "b", Some(PUBLIC[1]));
    let c = node(root, "c", Some(PUBLIC[2]));
    let own = bare(&a.listening());
    stage(root, "one outbound witness, reporting twice");
    assert_eq!(a.dial(b.listening()), b.id);
    // One connection per peer: B reports again only on a fresh connection,
    // after the idle one (20 s idle timeout) has closed.
    let closed = until(IDLE_CLOSE, || !a.connected().contains(&b.id));
    assert!(closed, "idle connection to B never closed");
    assert_eq!(a.dial(bare(&b.listening())), b.id);
    let confirmed = until(SETTLE, || !a.network.observed_addrs().is_empty());
    assert!(!confirmed, "{:?}", a.network.observed_addrs());
    stage(root, "an inbound connection is no witness");
    let d = node(root, "d", None);
    assert_eq!(d.dial(a.listening()), a.id);
    let confirmed = until(SETTLE, || !a.network.observed_addrs().is_empty());
    assert!(!confirmed, "{:?}", a.network.observed_addrs());
    stage(root, "a second distinct outbound witness confirms");
    assert_eq!(a.dial(c.listening()), c.id);
    let confirmed = until(Duration::from_secs(10), || {
        a.network.observed_addrs() == vec![own.clone()]
    });
    assert!(confirmed, "{:?} != [{own}]", a.network.observed_addrs());
    json!({"confirmed":a.network.observed_addrs().len()})
}

/// X announces its listener and dials Y. Y's next round drains identify and
/// stores X as gossip with the announced address; Y never gossips itself.
fn identified(root: &Path) -> Value {
    let y = announcing_node(root, "y", PUBLIC[2]);
    let (discovery, path) = discover(root, "y", &y, PeerBook::empty(y.genesis()));
    let x = announcing_node(root, "x", PUBLIC[1]);
    stage(
        root,
        "X announces itself and dials Y; Y learns X through identify",
    );
    assert_eq!(x.dial(y.listening()), y.id);
    let learned = until(Duration::from_secs(10), || {
        rounds(&discovery, &y, 1);
        path.exists()
            && saved_book(&path, &y)
                .entries()
                .iter()
                .any(|entry| entry.peer_id == Some(x.id))
    });
    assert!(learned, "Y never stored X");
    let entry = entry_of(&saved_book(&path, &y), x.id);
    assert_eq!(entry.origin, Origin::Gossip);
    assert_eq!(entry.addrs, vec![bare(&x.listening())]);
    stage(root, "Y's Peers answer never names Y itself");
    let client = RawPeer::start(None);
    let to = PeerAddress::new(y.id, y.listening()).unwrap();
    let Reply::Peers(listed) = client.call(&to, VERSION, Kind::Peers { limit: 32 }) else {
        panic!("Peers refused");
    };
    assert!(listed.iter().all(|peer| peer.peer_id != y.id), "{listed:?}");
    json!({"learned":true,"self_gossiped":false})
}

#[test]
#[ignore = "owned namespaced subprocess host, invoked only by the identify cases"]
fn peer_identify_host() {
    let (root, scenario) = host();
    let checks = match scenario.as_str() {
        "witnesses" => witnesses(&root),
        "identified" => identified(&root),
        _ => panic!("unknown owned scenario"),
    };
    report(&root, &scenario, checks);
}

#[test]
fn observed_address_needs_two_distinct_outbound_witnesses() {
    let checks = run(HOST, "witnesses");
    assert_eq!(checks["confirmed"], 1);
}

#[test]
fn an_announcing_dialer_is_learned_through_identify_as_gossip() {
    let checks = run(HOST, "identified");
    assert_eq!(checks["learned"], true);
    assert_eq!(checks["self_gossiped"], false);
}
