use std::{fs, process::Command};

#[test]
fn publication_scanning_is_opt_in_and_reuse_respects_the_flag() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(
        repo.join("README"),
        "Public fake scanner fixture: ghp_ABCDEFGHIJKLMNOPQRST\n",
    )
    .unwrap();
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
    let plan = temp.path().join("plan");
    for scan in [false, true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env("URMA_CONFIG", temp.path().join("absent-config"))
            .env("URMA_VAULT", temp.path().join("absent-vault"))
            .env("URMA_UNLOCK_FILE", temp.path().join("absent-unlock"))
            .env_remove("URMA_GIT_LIMITS")
            .args(["git", "publish", "--testnet", "--output"])
            .arg(&plan)
            .arg(&repo);
        if scan {
            command.arg("--scan-secrets");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("no identity vault")
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(plan.join("scan.json")).unwrap()).unwrap();
        assert_eq!(report["complete"], scan);
        assert_eq!(report["findings"].as_array().unwrap().is_empty(), !scan);
        assert_eq!(report["scanner"] == "disabled", !scan);
        assert!(!plan.join("publication").exists());
    }
    for verb in ["prepare", "publish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_urma"))
            .args(["git", verb, "--help"])
            .output()
            .unwrap();
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("--scan-secrets")
        );
    }
}
