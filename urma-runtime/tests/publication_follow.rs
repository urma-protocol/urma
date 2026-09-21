#[path = "support/publication_node.rs"]
mod publication_node;
use publication_node::{Mock, txid};
use urma_runtime::{
    disk_plan::DiskPlan,
    disk_publish,
    publication_progress::{Progress, State, Target},
};

impl Mock {
    fn plan(&self, directory: &std::path::Path, payload: &[u8]) -> DiskPlan {
        DiskPlan::prepare_multipart(
            &self.node(),
            &self.signer,
            &mut &*payload,
            payload.len() as u64,
            *b"RUNTIME0",
            urma_runtime::plan::PlanLimits {
                fee_rate: 1,
                max_fee: 2_000_000,
                max_records: 20,
            },
            directory,
        )
        .unwrap()
    }
}

fn observe(mock: &Mock, plan: &DiskPlan, journal: &std::path::Path) -> Progress {
    disk_publish::watch(&mock.node(), plan, journal, &mut |_| Ok(())).unwrap()
}

fn publish(mock: &Mock, plan: &DiskPlan, journal: &std::path::Path) -> Progress {
    disk_publish::publish_progress(
        &mock.node(),
        plan,
        &plan.id().unwrap(),
        journal,
        &mut |_| Ok(()),
    )
    .unwrap()
}

#[test]
fn watch_is_read_only_and_requires_every_transaction_with_fresh_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = mock.plan(&directory.path().join("publication"), b"public fixture");
    let journal = directory.path().join("progress.json");
    let pending = observe(&mock, &plan, &journal);
    assert_eq!(pending.total, 6);
    assert!(
        pending
            .observations
            .iter()
            .all(|row| row.state == State::Prepared)
    );
    assert!(!pending.reached(Target::Mempool));
    assert!(!journal.exists());
    assert!(!journal.with_extension("observations.jsonl").exists());
    for index in 0..plan.record_count {
        let pair = plan.record(index).unwrap();
        for raw in [pair.commit, pair.reveal] {
            mock.state
                .lock()
                .unwrap()
                .transactions
                .insert(txid(&raw), false);
        }
    }
    let mempool = observe(&mock, &plan, &journal);
    assert!(mempool.reached(Target::Mempool));
    assert!(!mempool.reached(Target::Confirmed));
    mock.confirm_all();
    assert!(observe(&mock, &plan, &journal).reached(Target::Confirmed));
    mock.state.lock().unwrap().reorg = true;
    let reorg = observe(&mock, &plan, &journal);
    assert!(!reorg.reached(Target::Confirmed));
    assert!(reorg.retryable);
    assert!(reorg.observations.is_empty());
    assert!(reorg.report.blocked_reason.contains("chain changed"));
    mock.state.lock().unwrap().reorg = false;
    let first = txid(&plan.record(0).unwrap().reveal);
    mock.state.lock().unwrap().transactions.remove(&first);
    assert!(!observe(&mock, &plan, &journal).reached(Target::Mempool));
    mock.state.lock().unwrap().unavailable = true;
    let unavailable = observe(&mock, &plan, &journal);
    assert!(!unavailable.retryable);
    assert!(unavailable.summary().contains("1 source unavailable"));
    let state = mock.state.lock().unwrap();
    assert!(state.submissions.is_empty());
    assert!(
        !state
            .methods
            .iter()
            .any(|method| ["sendrawtransaction", "testmempoolaccept"].contains(&method.as_str()))
    );
}

#[test]
fn restart_preserves_bytes_and_dependencies_and_reconciles_disappearances() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan_path = directory.path().join("publication");
    let plan = mock.plan(&plan_path, b"public fixture");
    let immutable = std::fs::read(plan_path.join("records.bin")).unwrap();
    let journal = directory.path().join("progress.json");
    let first = publish(&mock, &plan, &journal);
    assert_eq!(
        first
            .observations
            .iter()
            .filter(|row| row.state == State::Mempool)
            .count(),
        3
    );
    assert!(!first.report.complete);
    let restarted = DiskPlan::load(&plan_path).unwrap();
    publish(&mock, &restarted, &journal);
    assert_eq!(mock.state.lock().unwrap().submissions.len(), 3);
    for expected in [4, 5, 6] {
        mock.confirm_all();
        let report = publish(&mock, &restarted, &journal);
        assert_eq!(mock.state.lock().unwrap().submissions.len(), expected);
        assert_eq!(report.reached(Target::Mempool), expected == 6);
        assert!(!report.reached(Target::Confirmed));
    }
    mock.confirm_all();
    assert!(publish(&mock, &restarted, &journal).report.complete);
    let missing = txid(&plan.record(0).unwrap().reveal);
    mock.state.lock().unwrap().transactions.remove(&missing);
    let removed = observe(&mock, &restarted, &journal);
    assert!(
        removed
            .observations
            .iter()
            .any(|row| row.txid == missing && row.state == State::Missing)
    );
    assert!(!removed.reached(Target::Mempool));
    publish(&mock, &restarted, &journal);
    assert_eq!(mock.state.lock().unwrap().submissions.len(), 7);
    assert_eq!(
        mock.state.lock().unwrap().submissions.last().unwrap(),
        &plan.record(0).unwrap().reveal
    );
    assert_eq!(
        std::fs::read(plan_path.join("records.bin")).unwrap(),
        immutable
    );
}

#[test]
fn only_exact_congestion_is_retryable_and_rejection_is_durable() {
    for (reason, retryable) in [
        ("mempool full", true),
        ("mempool min fee not met", false),
        ("min relay fee not met", false),
        ("txn-mempool-conflict", false),
        ("bad-txns-inputs-missingorspent", false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mock = Mock::new(directory.path());
        let plan = mock.plan(&directory.path().join("publication"), b"public fixture");
        let journal = directory.path().join("progress.json");
        mock.state.lock().unwrap().preflight = Some(reason.into());
        let report = publish(&mock, &plan, &journal);
        assert_eq!(report.retryable, retryable, "{reason}");
        assert!(report.report.blocked_reason.contains(reason));
        assert!(mock.state.lock().unwrap().submissions.is_empty());
        assert!(journal.exists());
        assert_eq!(
            observe(&mock, &plan, &journal).observations[0].state,
            State::Missing
        );
        mock.state.lock().unwrap().preflight = None;
        mock.state.lock().unwrap().send_rejection = Some(reason.into());
        let sent = disk_publish::publish_progress(
            &mock.node(),
            &plan,
            &plan.id().unwrap(),
            &journal,
            &mut |_| Ok(()),
        );
        if retryable {
            assert!(sent.unwrap().retryable);
        } else {
            assert!(sent.is_err());
        }
    }
}

#[test]
fn eight_commit_window_and_cancellation_checkpoint_bound_the_pipeline() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let payload = vec![17; urma_core::multipart::Geometry::DATA_BYTES * 8];
    let plan = mock.plan(&directory.path().join("publication"), &payload);
    let journal = directory.path().join("progress.json");
    let mut counts = Vec::new();
    let report = disk_publish::publish_progress(
        &mock.node(),
        &plan,
        &plan.id().unwrap(),
        &journal,
        &mut |progress| {
            counts.push(progress.observations.len());
            Ok(())
        },
    )
    .unwrap();
    assert!(counts.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(report.observations.len(), 20);
    assert_eq!(mock.state.lock().unwrap().submissions.len(), 8);
    assert!(
        report
            .report
            .blocked_reason
            .contains("eight funding commits")
    );
    let result = disk_publish::publish_progress(
        &mock.node(),
        &plan,
        &plan.id().unwrap(),
        &journal,
        &mut |progress| {
            if progress.observations.len() >= 2 {
                Err(urma_runtime::error::Error::Invalid(
                    "interrupted fixture".into(),
                ))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(mock.state.lock().unwrap().submissions.len(), 8);
}
