use std::net::SocketAddr;
use std::time::{Duration, Instant};
use urma_runtime::config::{P2P_ADDRESS_POOL, P2P_SEED_INTERVAL_SECS};
use urma_runtime::p2p::{Discovery, Next};

fn v4(last: u8) -> SocketAddr {
    format!("10.0.0.{last}:9333").parse().unwrap()
}

fn v6(last: u16) -> SocketAddr {
    format!("[2001:db8::{last:x}]:9333").parse().unwrap()
}

#[test]
fn seeding_is_due_only_for_an_empty_pool_and_once_per_interval() {
    let mut discovery = Discovery::new();
    let start = Instant::now();
    assert!(discovery.seeding_due(start));
    discovery.mark_seeded(start);
    assert!(!discovery.seeding_due(start + Duration::from_secs(1)));
    assert!(!discovery.seeding_due(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS - 1)));
    assert!(discovery.seeding_due(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS)));
    discovery.offer_gossip(v4(1));
    assert!(!discovery.seeding_due(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 3)));
    assert_eq!(discovery.next(), Next::Address(v4(1)));
    assert_eq!(discovery.next(), Next::Exhausted);
    assert!(discovery.seeding_due(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 3)));
}

#[test]
fn seeded_addresses_come_before_gossip_and_tried_or_banned_ones_never_return() {
    let mut discovery = Discovery::new();
    discovery.offer_gossip(v4(9));
    discovery.offer_seeded(vec![v4(1), v4(2)]);
    discovery.offer_gossip(v4(9));
    assert_eq!(discovery.len(), 3);
    assert_eq!(discovery.next(), Next::Address(v4(1)));
    assert_eq!(discovery.next(), Next::Address(v4(2)));
    discovery.offer_seeded(vec![v4(1)]);
    assert_eq!(discovery.next(), Next::Address(v4(9)));
    assert_eq!(discovery.next(), Next::Exhausted);
    discovery.offer_gossip(v4(3));
    discovery.offer_gossip(v4(4));
    discovery.ban(v4(3).ip());
    assert_eq!(discovery.next(), Next::Address(v4(4)));
    discovery.offer_gossip(v4(3));
    assert_eq!(discovery.next(), Next::Exhausted);
    for last in 0..=255u8 {
        discovery.offer_gossip(format!("10.1.0.{last}:9333").parse().unwrap());
        discovery.offer_gossip(format!("10.1.1.{last}:9333").parse().unwrap());
        discovery.offer_gossip(format!("10.1.2.{last}:9333").parse().unwrap());
        discovery.offer_gossip(format!("10.1.3.{last}:9333").parse().unwrap());
        discovery.offer_gossip(format!("10.1.4.{last}:9333").parse().unwrap());
    }
    assert_eq!(discovery.len(), P2P_ADDRESS_POOL);
}

#[test]
fn ipv6_is_skipped_for_the_session_after_the_network_proves_unreachable() {
    let mut discovery = Discovery::new();
    discovery.offer_seeded(vec![v6(1), v4(1), v6(2)]);
    assert_eq!(discovery.len(), 3);
    assert!(!discovery.skips_v6());
    discovery.unreachable_v6();
    assert!(discovery.skips_v6());
    assert_eq!(discovery.len(), 1);
    discovery.offer_gossip(v6(3));
    discovery.offer_seeded(vec![v6(4)]);
    assert_eq!(discovery.next(), Next::Address(v4(1)));
    assert_eq!(discovery.next(), Next::Exhausted);
}

#[test]
fn a_drought_warns_once_per_interval_and_clears_when_addresses_arrive() {
    let mut discovery = Discovery::new();
    let start = Instant::now();
    assert!(!discovery.drought_warns(start));
    assert!(!discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS / 2)));
    assert!(discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS)));
    assert!(!discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS + 1)));
    assert!(discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 2)));
    discovery.offer_gossip(v4(1));
    assert!(!discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 9)));
    assert_eq!(discovery.next(), Next::Address(v4(1)));
    assert!(!discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 9)));
    assert!(discovery.drought_warns(start + Duration::from_secs(P2P_SEED_INTERVAL_SECS * 10)));
}
