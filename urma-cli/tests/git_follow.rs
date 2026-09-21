#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;
use publication_node::{Mock, txid};
use std::{
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use urma_git::{inventory::Limits, workflows};
use urma_runtime::{disk_plan::DiskPlan, plan::PlanLimits};

fn command(mock: &Mock, directory: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
    command
        .env("URMA_CONFIG", directory.join("absent-config"))
        .env("URMA_NETWORK", "bitcoin-regtest")
        .env("URMA_RPC_URL", &mock.config.rpc_url)
        .env("URMA_NODE_AUTH_FILE", &mock.config.cookie_file)
        .env("URMA_VAULT", directory.join("absent-vault"))
        .env("URMA_UNLOCK_FILE", directory.join("absent-unlock"))
        .args(args)
        .arg("--plan")
        .arg(directory.join("plan"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn fixture(directory: &Path, mock: &Mock) -> DiskPlan {
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
    let directory = directory.join("plan");
    workflows::prepare(
        &mock.node(),
        &mock.signer,
        &repo,
        &directory,
        &Limits::default(),
        PlanLimits {
            fee_rate: 1,
            max_fee: 2_000_000,
            max_records: 20,
        },
    )
    .unwrap();
    workflows::record_review(&directory, &[]).unwrap();
    DiskPlan::load(&directory.join("publication")).unwrap()
}

fn wait_for_reads(mock: &Mock) {
    let start = Instant::now();
    while !mock
        .state
        .lock()
        .unwrap()
        .methods
        .iter()
        .any(|method| method == "getrawtransaction")
    {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(200));
}

fn interrupt(mut child: Child) -> Output {
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            panic!("Ctrl-C did not stop foreground loop");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn watch_default_is_confirmed_no_unlock_no_writes_and_verbosity_is_cumulative() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = fixture(directory.path(), &mock);
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
    mock.state.lock().unwrap().methods.clear();
    let child = command(&mock, directory.path(), &["git", "watch"])
        .spawn()
        .unwrap();
    wait_for_reads(&mock);
    let stopped = interrupt(child);
    let text = String::from_utf8(stopped.stderr).unwrap();
    assert!(!stopped.status.success());
    assert!(text.contains("6 mempool"), "{text}");
    assert!(text.contains("interrupted; target not reached"), "{text}");
    assert!(!text.contains("Target Confirmed reached"));
    let pooled = command(
        &mock,
        directory.path(),
        &["git", "watch", "--until", "mempool"],
    )
    .output()
    .unwrap();
    assert!(
        pooled.status.success(),
        "{}",
        String::from_utf8_lossy(&pooled.stderr)
    );
    mock.confirm_all();
    for verbosity in ["0", "2", "3"] {
        let output = command(&mock, directory.path(), &["-v", verbosity, "git", "watch"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("6/6 checked: 6 confirmed"), "{text}");
        assert_eq!(text.contains("commit: 3 observed"), verbosity != "0");
        assert_eq!(
            text.contains(&txid(&plan.record(0).unwrap().commit)),
            verbosity == "3"
        );
    }
    assert!(!directory.path().join("plan/progress.json").exists());
    assert!(
        !directory
            .path()
            .join("plan/progress.observations.jsonl")
            .exists()
    );
    assert!(mock.state.lock().unwrap().submissions.is_empty());
    assert!(
        !mock.state.lock().unwrap().methods.iter().any(|method| [
            "testmempoolaccept",
            "sendrawtransaction"
        ]
        .contains(&method.as_str()))
    );
}

#[test]
fn persist_waits_for_congestion_ctrl_c_preserves_plan_resume_completes_and_fatal_exits() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = fixture(directory.path(), &mock);
    let before = std::fs::read(plan.directory().join("records.bin")).unwrap();
    mock.state.lock().unwrap().preflight = Some("mempool full".into());
    mock.state.lock().unwrap().methods.clear();
    let child = command(
        &mock,
        directory.path(),
        &["git", "publish", "--persist", "--yes"],
    )
    .spawn()
    .unwrap();
    wait_for_reads(&mock);
    let stopped = interrupt(child);
    assert!(!stopped.status.success());
    let text = String::from_utf8(stopped.stderr).unwrap();
    assert!(text.contains("mempool full"), "{text}");
    assert!(text.contains("interrupted"), "{text}");
    assert_eq!(
        mock.state
            .lock()
            .unwrap()
            .methods
            .iter()
            .filter(|method| *method == "testmempoolaccept")
            .count(),
        1
    );
    assert!(directory.path().join("plan/progress.json").exists());
    mock.state.lock().unwrap().preflight = Some("mempool min fee not met".into());
    let fatal = command(
        &mock,
        directory.path(),
        &["git", "resume", "--persist", "--yes"],
    )
    .output()
    .unwrap();
    assert!(!fatal.status.success());
    let text = String::from_utf8(fatal.stderr).unwrap();
    assert!(text.contains("needs attention"), "{text}");
    assert!(text.contains("requires intervention"), "{text}");
    mock.state.lock().unwrap().preflight = None;
    mock.state.lock().unwrap().auto_confirm = true;
    let resumed = command(
        &mock,
        directory.path(),
        &["git", "resume", "--persist", "--yes"],
    )
    .output()
    .unwrap();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(
        String::from_utf8(resumed.stderr)
            .unwrap()
            .contains("Target Confirmed reached for all 6")
    );
    assert_eq!(mock.state.lock().unwrap().submissions.len(), 6);
    assert_eq!(
        std::fs::read(plan.directory().join("records.bin")).unwrap(),
        before
    );
}

#[test]
fn help_separates_target_persistence_and_verbosity_and_watch_has_no_approval() {
    for verb in ["publish", "resume", "watch"] {
        let output = Command::new(env!("CARGO_BIN_EXE_urma"))
            .args(["git", verb, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--until"));
        assert!(help.contains("[default: confirmed]"));
        assert!(help.contains("mempool, confirmed"));
        assert_eq!(help.contains("--persist"), verb != "watch");
        assert_eq!(help.contains("--watch <WATCH>"), verb != "watch");
        assert_eq!(help.contains("[default: true]"), verb != "watch");
        assert_eq!(help.contains("--yes"), verb != "watch");
    }
}

fn bounded_output(mut command: Command) -> Output {
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("single reconciliation unexpectedly waited");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn watch_false_is_one_pass_independent_of_persist_and_rejections_remain_errors() {
    for verb in ["publish", "resume"] {
        for persist in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mock = Mock::new(directory.path());
            let _plan = fixture(directory.path(), &mock);
            let mut args = vec!["git", verb, "--yes", "--watch", "false"];
            if persist {
                args.push("--persist");
            }
            let output = bounded_output(command(&mock, directory.path(), &args));
            assert!(output.status.success());
            let text = String::from_utf8(output.stderr).unwrap();
            assert!(text.contains("Pending/incomplete"), "{text}");
            assert!(!text.contains("Target Confirmed reached"));
            assert!(!mock.state.lock().unwrap().submissions.is_empty());
            mock.state.lock().unwrap().preflight = Some("mempool full".into());
            mock.confirm_all();
            let output = bounded_output(command(&mock, directory.path(), &args));
            assert_eq!(output.status.success(), persist);
            let text = String::from_utf8(output.stderr).unwrap();
            assert!(text.contains("mempool full"), "{text}");
            assert_eq!(text.contains("Pending/incomplete"), persist);
        }
    }
}

#[test]
fn default_watch_waits_without_persist_but_congestion_exits() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let _plan = fixture(directory.path(), &mock);
    let child = command(&mock, directory.path(), &["git", "publish", "--yes"])
        .spawn()
        .unwrap();
    wait_for_reads(&mock);
    let output = interrupt(child);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("interrupted")
    );
    mock.confirm_all();
    mock.state.lock().unwrap().preflight = Some("mempool full".into());
    let output = bounded_output(command(
        &mock,
        directory.path(),
        &["git", "resume", "--yes", "--watch=true"],
    ));
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("mempool full")
    );
}
