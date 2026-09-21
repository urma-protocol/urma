#[path = "../../urma-runtime/tests/support/publication_node.rs"]
mod publication_node;

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use urma_git::{descriptor::Descriptor, inventory::Limits, snapshot};
use urma_runtime::{disk_plan::DiskPlan, plan::PlanLimits};

fn logs(directory: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[test]
fn clone_logs_timestamps_stages_and_configured_levels_without_verbosity_or_wallet() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("README"), "public-file-content-not-for-logs\n").unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
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
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let artifact = temp.path().join("artifact");
    snapshot::prepare(&repo, &artifact, &Limits::default()).unwrap();
    let mock = publication_node::Mock::new(temp.path());
    let mut payload = fs::File::open(artifact.join("object.bin")).unwrap();
    let length = payload.metadata().unwrap().len();
    let plan = DiskPlan::prepare_multipart(
        &mock.node(),
        &mock.signer,
        &mut payload,
        length,
        Descriptor::PROFILE,
        PlanLimits {
            fee_rate: 1,
            max_fee: 10_000,
            max_records: 10,
        },
        &temp.path().join("signed"),
    )
    .unwrap();
    for index in 0..plan.record_count {
        let pair = plan.record(index).unwrap();
        for raw in [pair.commit, pair.reveal] {
            let id = publication_node::txid(&raw);
            let mut state = mock.state.lock().unwrap();
            state.transactions.insert(id.clone(), false);
            state.raw_transactions.insert(id, raw);
        }
    }
    mock.confirm_all();
    for level in ["info", "warn", "debug"] {
        let state = temp.path().join(level);
        let config = temp.path().join(format!("{level}.json"));
        fs::write(
            &config,
            if level == "info" {
                "{}".to_owned()
            } else {
                format!("{{\"log_level\":\"{level}\"}}")
            },
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_urma"))
            .env("URMA_CONFIG", config)
            .env("XDG_STATE_HOME", &state)
            .env("URMA_NETWORK", "bitcoin-regtest")
            .env("URMA_RPC_URL", &mock.config.rpc_url)
            .env("URMA_NODE_AUTH_FILE", &mock.config.cookie_file)
            .env("URMA_VAULT", temp.path().join("absent-vault"))
            .env("URMA_UNLOCK_FILE", temp.path().join("absent-unlock"))
            .args(["git", "clone", &plan.root_txid])
            .arg(temp.path().join(format!("clone-{level}")))
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("Log: "));
        assert!(
            stderr
                .lines()
                .any(|line| line.contains("Validating Git PACK:")
                    && line.as_bytes().get(10) == Some(&b'T'))
        );
        assert!(stderr.contains("Installing and checking out verified snapshot:"));
        let files = logs(&state.join("urma/logs"));
        assert_eq!(files.len(), 1);
        assert_eq!(
            fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = fs::read_to_string(&files[0]).unwrap();
        assert!(!text.contains("public-fixture:public-fixture"));
        assert!(!text.contains("public-file-content-not-for-logs"));
        assert!(!text.contains('\u{1b}'));
        if level == "warn" {
            assert!(!text.contains(" INFO ") && !text.contains("DEBUG"));
        } else {
            assert!(text.contains("Command started") && text.contains("Command completed"));
            assert!(
                text.contains("Validating Git PACK:") && text.contains("Materializing checkout")
            );
            assert!(text.contains("done=1 total=1"));
            assert!(
                text.lines()
                    .all(|line| line.as_bytes().get(10) == Some(&b'T'))
            );
            assert_eq!(text.contains("Requested root:"), level == "debug");
        }
    }
    assert!(mock.state.lock().unwrap().submissions.is_empty());
}

#[test]
fn default_state_path_unique_logs_and_errors_are_retained() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("config.json");
    fs::write(&config, "{}").unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_urma"))
            .env("HOME", home.path())
            .env_remove("XDG_STATE_HOME")
            .env("URMA_CONFIG", &config)
            .args(["git", "inspect", "--plan"])
            .arg(home.path().join("absent-plan"))
            .output()
            .unwrap()
    };
    for _ in 0..2 {
        assert!(!invoke().status.success());
    }
    let files = logs(&home.path().join(".local/state/urma/logs"));
    assert_eq!(files.len(), 2);
    for path in files {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("ERROR") && text.contains("Command failed"));
    }
    fs::write(&config, "{\"log_level\":\"trace\"}").unwrap();
    let invalid = invoke();
    assert!(!invalid.status.success());
    let error = String::from_utf8(invalid.stderr).unwrap();
    assert!(
        error.contains("unknown variant")
            && error.contains("info")
            && error.contains("warn")
            && error.contains("debug")
    );
}
