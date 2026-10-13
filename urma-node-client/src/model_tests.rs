use super::ServiceStatus;
use serde_json::Value;

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
fn chain_peers_absent_reads_as_zero() {
    let status: ServiceStatus = serde_json::from_value(status_without("chain_peers")).unwrap();
    assert_eq!(status.chain_peers, 0);
}
