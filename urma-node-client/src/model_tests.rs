use super::{OverlayPeerStatus, OverlayStatus, PeerLink, Reachability, ServiceStatus};
use serde_json::{Value, json};

fn status_without(field: &str) -> Value {
    let mut value = serde_json::to_value(ServiceStatus::default()).unwrap();
    value.as_object_mut().unwrap().remove(field).unwrap();
    value
}

#[test]
fn chain_target_absent_reads_as_unknown() {
    let status: ServiceStatus = serde_json::from_value(status_without("chain_target")).unwrap();
    assert_eq!(status.chain_target, None);
}

#[test]
fn chain_target_round_trips_absolute_height() {
    let mut status = ServiceStatus::default();
    status.chain_target = Some(4_913_600);
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(value["chain_target"], 4_913_600);
    let back: ServiceStatus = serde_json::from_value(value).unwrap();
    assert_eq!(back.chain_target, Some(4_913_600));
}

#[test]
fn nat_fields_absent_read_as_unknown_and_empty() {
    let mut overlay = serde_json::to_value(OverlayStatus::default()).unwrap();
    let object = overlay.as_object_mut().unwrap();
    for field in ["reachability", "relays", "hole_punch"] {
        object.remove(field).unwrap();
    }
    let overlay: OverlayStatus = serde_json::from_value(overlay).unwrap();
    assert_eq!(overlay, OverlayStatus::default());
    assert_eq!(overlay.reachability, Reachability::Unknown);
    let mut peer = serde_json::to_value(OverlayPeerStatus::default()).unwrap();
    peer.as_object_mut().unwrap().remove("link").unwrap();
    let peer: OverlayPeerStatus = serde_json::from_value(peer).unwrap();
    assert_eq!(peer.link, None);
}

#[test]
fn nat_fields_serialize_as_lowercase_names() {
    let mut overlay = OverlayStatus::default();
    overlay.reachability = Reachability::Private;
    overlay.relays = vec!["12D3KooWrelay".into()];
    overlay.hole_punch.attempts = 2;
    overlay.hole_punch.successes = 1;
    let mut peer = OverlayPeerStatus::default();
    peer.link = Some(PeerLink::Relayed);
    overlay.peers = vec![peer];
    let value = serde_json::to_value(&overlay).unwrap();
    assert_eq!(value["reachability"], "private");
    assert_eq!(value["relays"], json!(["12D3KooWrelay"]));
    assert_eq!(
        value["hole_punch"],
        json!({"attempts": 2, "successes": 1, "last_error": null, "last_error_at": null})
    );
    assert_eq!(value["peers"][0]["link"], "relayed");
    let back: OverlayStatus = serde_json::from_value(value).unwrap();
    assert_eq!(back, overlay);
}

#[test]
fn chain_peers_absent_reads_as_zero() {
    let status: ServiceStatus = serde_json::from_value(status_without("chain_peers")).unwrap();
    assert_eq!(status.chain_peers, 0);
}
