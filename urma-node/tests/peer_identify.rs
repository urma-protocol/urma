//! Identify between real PeerNetworks in a private namespace (see
//! common/discovery_host.rs): an address peers observed for this node is
//! confirmed only after two distinct outbound peers report it. Outbound dials
//! reuse the listener port, so every witness sees the same public address.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[allow(dead_code)]
#[path = "common/discovery_host.rs"]
mod discovery_host;
use discovery_host::{PUBLIC, bare, host, node, report, run, stage, until};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

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

#[test]
#[ignore = "owned namespaced subprocess host, invoked only by the identify cases"]
fn peer_identify_host() {
    let (root, scenario) = host();
    let checks = match scenario.as_str() {
        "witnesses" => witnesses(&root),
        _ => panic!("unknown owned scenario"),
    };
    report(&root, &scenario, checks);
}

#[test]
fn observed_address_needs_two_distinct_outbound_witnesses() {
    let checks = run(HOST, "witnesses");
    assert_eq!(checks["confirmed"], 1);
}
