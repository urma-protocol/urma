#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;
use publication_node::{Mock, txid};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use urma_git::{inventory::Limits, workflows};
use urma_runtime::{disk_plan::DiskPlan, plan::PlanLimits};

#[test]
fn persist_retries_after_bounded_poll_and_independent_watch_observes_completion() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let repo = directory.path().join("repo");
    let plan_path = directory.path().join("plan");
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
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    workflows::prepare(
        &mock.node(),
        &mock.signer,
        &repo,
        &plan_path,
        &Limits::default(),
        PlanLimits {
            fee_rate: 1,
            max_fee: 100_000,
            max_records: 20,
        },
    )
    .unwrap();
    workflows::record_review(&plan_path, &[]).unwrap();
    let plan = DiskPlan::load(&plan_path.join("publication")).unwrap();
    let mut children = Vec::new();
    mock.state.lock().unwrap().preflight = Some("mempool full".into());
    mock.state.lock().unwrap().methods.clear();
    let start = Instant::now();
    for args in [
        vec!["git", "resume", "--yes", "--persist"],
        vec!["git", "watch"],
    ] {
        children.push(
            Command::new(env!("CARGO_BIN_EXE_urma"))
                .env("URMA_CONFIG", directory.path().join("absent"))
                .env("URMA_NETWORK", "bitcoin-regtest")
                .env("URMA_RPC_URL", &mock.config.rpc_url)
                .env("URMA_NODE_AUTH_FILE", &mock.config.cookie_file)
                .env("URMA_VAULT", directory.path().join("absent-vault"))
                .env("URMA_UNLOCK_FILE", directory.path().join("absent-unlock"))
                .args(args)
                .arg("--plan")
                .arg(&plan_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    while !mock
        .state
        .lock()
        .unwrap()
        .methods
        .iter()
        .any(|method| method == "testmempoolaccept")
    {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(250));
    mock.confirm_all();
    mock.state.lock().unwrap().preflight = None;
    mock.state.lock().unwrap().auto_confirm = true;
    for mut child in children {
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(75) {
                child.kill().unwrap();
                panic!("foreground polling did not finish");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Target Confirmed reached for all 6")
        );
    }
    assert!(start.elapsed() >= Duration::from_secs(29));
    let state = mock.state.lock().unwrap();
    assert_eq!(state.submissions.len(), 6);
    assert_eq!(
        state
            .methods
            .iter()
            .filter(|method| *method == "testmempoolaccept")
            .count(),
        7
    );
    assert_eq!(txid(state.submissions.last().unwrap()), plan.root_txid);
}
