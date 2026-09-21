#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;
use publication_node::{Mock, txid};
use std::{
    path::Path,
    process::{Command, Stdio},
};
use urma_git::{inventory::Limits, workflows};
use urma_runtime::{disk_plan::DiskPlan, plan::PlanLimits};

fn command(mock: &Mock, directory: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
    command
        .env("XDG_STATE_HOME", directory.join("state"))
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

#[test]
fn approval_in_non_terminal_requires_yes_flag() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let _plan = fixture(directory.path(), &mock);
    let output = command(&mock, directory.path(), &["git", "resume"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(
            "publication needs approval; review the plan, then run this command with --yes"
        )
    );
}

#[test]
fn pipe_output_has_no_ansi_escapes() {
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
    mock.confirm_all();
    for args in [
        vec!["git", "watch", "--until", "mempool"],
        vec!["-v", "2", "git", "watch"],
        vec!["-v", "3", "git", "watch"],
        vec!["git", "resume", "--yes"],
    ] {
        let output = command(&mock, directory.path(), &args)
            .env("CLICOLOR_FORCE", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("\x1b["));
        assert!(stderr.contains("6 confirmed"));
    }
    let cli = command(&mock, directory.path(), &["git", "watch"]);
    let result = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/git_ui_demo.py"))
        .arg(cli.get_program())
        .arg("--machine-check")
        .args(cli.get_args())
        .envs(cli.get_envs().map(|(key, value)| (key, value.unwrap())))
        .env("URMA_OUTPUT", "json")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn watch_ctrl_c_clears_pty_and_remains_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let mock = Mock::new(directory.path());
    let plan = fixture(directory.path(), &mock);
    let immutable = std::fs::read(plan.directory().join("records.bin")).unwrap();
    let cli = command(&mock, directory.path(), &["git", "watch"]);
    let result = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/git_ui_demo.py"))
        .arg(cli.get_program())
        .arg("--watch-check")
        .args(cli.get_args())
        .envs(cli.get_envs().map(|(key, value)| (key, value.unwrap())))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(plan.directory().join("records.bin")).unwrap(),
        immutable
    );
    assert!(!directory.path().join("plan/progress.json").exists());
    assert!(mock.state.lock().unwrap().submissions.is_empty());
}

#[test]
fn json_output_mode_is_clean_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["wallet", "quote", "100", "--rate", "1", "--max-fee", "200"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["fee_base_units"], 100);
    assert_eq!(json["estimate_only"], true);
}
