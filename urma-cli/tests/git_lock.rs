#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;
use publication_node::Mock;
use std::{
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use urma_git::{inventory::Limits, workflows};
use urma_runtime::plan::PlanLimits;

fn repository(directory: &Path) -> std::path::PathBuf {
    let repo = directory.join("repo");
    std::fs::create_dir(&repo).unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "README"],
        vec![
            "-c",
            "user.name=Public Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Public fixture",
        ],
    ] {
        std::fs::write(repo.join("README"), "Public non-sensitive test fixture.\n").unwrap();
        assert!(
            Command::new("git")
                .current_dir(&repo)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    repo
}

#[test]
fn hold_plan_lock_helper() {
    let Ok(plan) = std::env::var("URMA_TEST_HOLD_PLAN_LOCK") else {
        return;
    };
    let held = urma_git::workspace::lock(Path::new(&plan)).unwrap();
    thread::sleep(std::time::Duration::from_millis(1500));
    drop(held);
}

#[test]
fn another_process_holding_the_plan_lock_is_refused_until_it_lets_go() {
    let directory = tempfile::tempdir().unwrap();
    let plan = directory.path().join("plan");
    std::fs::create_dir(&plan).unwrap();
    let mut holder = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hold_plan_lock_helper", "--nocapture"])
        .env("URMA_TEST_HOLD_PLAN_LOCK", &plan)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(500));
    let refused = urma_git::workspace::lock(&plan).unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("another operation is using this plan")
    );
    assert!(holder.wait().unwrap().success());
    drop(urma_git::workspace::lock(&plan).unwrap());
}

#[test]
fn prepare_then_review_never_trips_over_its_own_lock_while_processes_spawn() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let repo = repository(directory.path());
    let stop = Arc::new(AtomicBool::new(false));
    let spawning = stop.clone();
    let forker = thread::spawn(move || {
        let mut spawned = 0_u64;
        while !spawning.load(Ordering::Acquire) {
            Command::new("/usr/bin/true").status().unwrap();
            spawned += 1;
        }
        spawned
    });
    for round in 0..50 {
        let plan = directory.path().join(format!("plan-{round}"));
        workflows::prepare(
            &mock.node(),
            &mock.signer,
            &repo,
            &plan,
            &Limits {
                scan_secrets: false,
                ..Limits::default()
            },
            PlanLimits {
                fee_rate: 1,
                max_fee: 2_000_000,
                max_records: 20,
            },
        )
        .unwrap_or_else(|error| panic!("prepare round {round}: {error}"));
        workflows::record_review(&plan, &[])
            .unwrap_or_else(|error| panic!("record_review round {round}: {error}"));
    }
    stop.store(true, Ordering::Release);
    let spawned = forker.join().unwrap();
    assert!(spawned > 0);
}
