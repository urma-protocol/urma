#[path = "support/publication_node.rs"]
mod publication_node;
use publication_node::{Mock, txid};
use urma_core::format::PublicRecord;
use urma_runtime::{
    plan::{PlanLimits, PublicationPlan, prepare_atomic},
    publish::publish,
};

#[test]
fn atomic_mempool_restart_and_confirmation() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = prepare_atomic(
        &mock.node(),
        &mock.signer,
        &PublicRecord::Post("fixture".into()),
        PlanLimits {
            fee_rate: 1,
            max_fee: 10_000,
            max_records: 1,
        },
    )
    .unwrap();
    let path = directory.path().join("plan.json");
    plan.save_new(&path).unwrap();
    let journal = directory.path().join("progress.json");
    let id = plan.id().unwrap();
    // A lost accepted commit reply must not fund another plan on restart.
    mock.state.lock().unwrap().send_response_lost = true;
    assert!(publish(&mock.node(), &plan, &id, &journal).is_err());
    assert_eq!(
        mock.state.lock().unwrap().submissions,
        [plan.records[0].commit.clone()]
    );
    {
        let mut state = mock.state.lock().unwrap();
        state.send_response_lost = false;
        state.unavailable = false;
    }
    let restarted = PublicationPlan::load(&path).unwrap();
    let pending = publish(&mock.node(), &restarted, &id, &journal).unwrap();
    assert!(!pending.complete && !pending.confirmed);
    assert_eq!(pending.transactions.len(), 2);
    assert_eq!(
        mock.state.lock().unwrap().submissions,
        [
            plan.records[0].commit.clone(),
            plan.records[0].reveal.clone()
        ]
    );
    mock.state
        .lock()
        .unwrap()
        .transactions
        .insert(txid(&plan.records[0].commit), true);
    assert!(
        !publish(&mock.node(), &restarted, &id, &journal)
            .unwrap()
            .complete
    );
    mock.confirm_all();
    assert!(
        publish(&mock.node(), &restarted, &id, &journal)
            .unwrap()
            .complete
    );
    // A disappeared parent is retransmitted with identical bytes before its child.
    mock.state.lock().unwrap().transactions.clear();
    let pending = publish(&mock.node(), &restarted, &id, &journal).unwrap();
    assert!(!pending.complete);
    assert_eq!(
        &mock.state.lock().unwrap().submissions[2..],
        &[
            plan.records[0].commit.clone(),
            plan.records[0].reveal.clone()
        ]
    );
}

#[test]
fn rejected_or_unavailable_parent_never_submits_reveal() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = prepare_atomic(
        &mock.node(),
        &mock.signer,
        &PublicRecord::Post("fixture".into()),
        PlanLimits {
            fee_rate: 1,
            max_fee: 10_000,
            max_records: 1,
        },
    )
    .unwrap();
    let journal = directory.path().join("progress.json");
    mock.state.lock().unwrap().preflight = Some("fixture rejected".into());
    let report = publish(&mock.node(), &plan, &plan.id().unwrap(), &journal).unwrap();
    assert!(!report.complete);
    assert_eq!(report.blocked_reason, "fixture rejected");
    mock.state.lock().unwrap().unavailable = true;
    assert!(publish(&mock.node(), &plan, &plan.id().unwrap(), &journal).is_err());
    assert!(mock.state.lock().unwrap().submissions.is_empty());
    {
        let mut state = mock.state.lock().unwrap();
        state.unavailable = false;
        state.preflight = None;
        state.drop_after_send = true;
    }
    let report = publish(&mock.node(), &plan, &plan.id().unwrap(), &journal).unwrap();
    assert!(!report.complete && !report.confirmed);
    assert_eq!(report.transactions.len(), 1);
    assert!(report.blocked_reason.contains("missing after submission"));
    assert_eq!(
        mock.state.lock().unwrap().submissions,
        [plan.records[0].commit.clone()]
    );
}
