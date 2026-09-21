#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;

use bitcoin::{Transaction, consensus::deserialize};
use std::{
    collections::HashMap,
    io::Read,
    process::Command,
    sync::{Arc, Mutex},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};
use urma_runtime::{
    disk_plan::DiskPlan,
    multipart::{self, FetchError, MultipartSource, RecordRequest, VerifiedRecord},
    plan::PlanLimits,
};

#[derive(Clone, Debug, Default)]
struct Update {
    phase: String,
    done: u64,
    total: Option<u64>,
}

impl Visit for Update {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "phase" {
            self.phase = value.into();
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "done" => self.done = value,
            "total" => self.total = Some(value),
            _ => {}
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Update>>>);

impl<S: Subscriber> Layer<S> for Events {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "urma_ui" {
            let mut update = Update::default();
            event.record(&mut update);
            self.0.lock().unwrap().push(update);
        }
    }
}

impl Events {
    fn counts(&self, phase: &str) -> Vec<(u64, u64)> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.phase == phase)
            .map(|event| (event.done, event.total.unwrap()))
            .collect()
    }
}

struct Source(HashMap<bitcoin::Txid, VerifiedRecord>);
impl MultipartSource for Source {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        self.0
            .get(&request.reference.txid)
            .cloned()
            .ok_or(FetchError::Unavailable)
    }
}

#[test]
fn signed_and_recovered_progress_counts_real_work_without_changing_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let mock = publication_node::Mock::new(temp.path());
    mock.confirm_all();
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let payload = vec![42; 300_000];
    let prepare = |name: &str| {
        DiskPlan::prepare_multipart(
            &mock.node(),
            &mock.signer,
            &mut payload.as_slice(),
            payload.len() as u64,
            *b"RUNTIME0",
            PlanLimits {
                fee_rate: 1,
                max_fee: 2_000_000,
                max_records: 20,
            },
            &temp.path().join(name),
        )
        .unwrap()
    };
    let plan = tracing::subscriber::with_default(subscriber, || prepare("observed"));
    let baseline = prepare("unobserved");
    assert_eq!(plan.id().unwrap(), baseline.id().unwrap());
    assert_eq!(
        std::fs::read(plan.directory().join("records.bin")).unwrap(),
        std::fs::read(baseline.directory().join("records.bin")).unwrap()
    );
    let counts = events.counts("Signing records");
    assert_eq!(
        counts,
        (0..=u64::from(plan.record_count))
            .map(|done| (done, u64::from(plan.record_count)))
            .collect::<Vec<_>>()
    );
    let mut source = Source(HashMap::new());
    for index in 0..plan.record_count {
        let pair = plan.record(index).unwrap();
        let commit: Transaction = deserialize(&hex::decode(pair.commit).unwrap()).unwrap();
        let reveal: Transaction = deserialize(&hex::decode(pair.reveal).unwrap()).unwrap();
        let record = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
        source.0.insert(record.txid(), record);
    }
    let root = source.0[&plan.root_txid.parse::<bitcoin::Txid>().unwrap()].clone();
    let events = Events::default();
    let limits = multipart::RecoveryLimits {
        max_payload_bytes: 1_000_000,
        max_nodes: 20,
    };
    let mut recovered = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(events.clone()),
        || multipart::reconstruct(&root, &mut source, limits, temp.path()).unwrap(),
    );
    let mut bytes = Vec::new();
    recovered.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, payload);
    let counts = events.counts("Receiving payload bytes");
    assert_eq!(counts.first(), Some(&(0, payload.len() as u64)));
    assert_eq!(
        counts.last(),
        Some(&(payload.len() as u64, payload.len() as u64))
    );
    assert!(counts.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert!(counts.iter().all(|(done, total)| done <= total));
    let missing = source
        .0
        .iter()
        .find(|(_, record)| {
            matches!(
                record.decode().unwrap(),
                multipart::MultipartRecord::Data(_)
            )
        })
        .unwrap()
        .0
        .to_owned();
    source.0.remove(&missing);
    let failed = Events::default();
    let result = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(failed.clone()),
        || multipart::reconstruct(&root, &mut source, limits, temp.path()),
    );
    assert!(matches!(
        result,
        Err(multipart::RecoveryError::Incomplete { .. })
    ));
    assert!(
        failed
            .counts("Receiving payload bytes")
            .iter()
            .all(|(done, total)| done < total)
    );
    assert!(mock.state.lock().unwrap().submissions.is_empty());
}

#[test]
fn scan_and_validation_events_preserve_snapshot_results() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    std::fs::write(repo.join("README"), "Public fixture\n").unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "README"],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .current_dir(&repo)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let events = Events::default();
    let limits = urma_git::inventory::Limits::default();
    let observed = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(events.clone()),
        || urma_git::snapshot::prepare(&repo, &temp.path().join("observed"), &limits).unwrap(),
    );
    let baseline =
        urma_git::snapshot::prepare(&repo, &temp.path().join("baseline"), &limits).unwrap();
    assert_eq!(
        serde_json::to_value(&observed).unwrap(),
        serde_json::to_value(&baseline).unwrap()
    );
    let scan = events.counts("Scanning public objects");
    let total = observed.inventory.objects.len() as u64;
    assert_eq!(
        scan,
        (0..=total).map(|done| (done, total)).collect::<Vec<_>>()
    );
    assert_eq!(events.counts("Validating blobs"), vec![(0, 1), (1, 1)]);
}
