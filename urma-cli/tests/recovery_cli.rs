use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir};

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors")
}

fn cases() -> Vec<Value> {
    let manifest: Value =
        serde_json::from_slice(&fs::read(vectors().join("recovery/manifest.json")).unwrap())
            .unwrap();
    manifest["cases"].as_array().unwrap().clone()
}

fn artifact(value: &Value) -> Vec<u8> {
    let bytes = fs::read(vectors().join(value["file"].as_str().unwrap())).unwrap();
    assert_eq!(
        u64::try_from(bytes.len()).unwrap(),
        value["bytes"].as_u64().unwrap()
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        value["sha256"].as_str().unwrap()
    );
    bytes
}

struct Lab {
    directory: TempDir,
    input: Vec<u8>,
    key: Vec<u8>,
}

impl Lab {
    fn new(case: &Value) -> Self {
        let directory = tempdir().unwrap();
        let input = artifact(&case["container"]);
        let key = fs::read(vectors().join(case["root"].as_str().unwrap())).unwrap();
        fs::write(directory.path().join("input.urma"), &input).unwrap();
        fs::write(directory.path().join("recovery.key"), &key).unwrap();
        fs::set_permissions(
            directory.path().join("recovery.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self {
            directory,
            input,
            key,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
        command
            .env_clear()
            .current_dir(self.directory.path())
            .env("URMA_OUTPUT", "json")
            .env("URMA_LOG_OUTPUT", "stderr")
            .env(
                "URMA_CONFIG",
                self.directory.path().join("missing-config.json"),
            )
            .env("URMA_RPC_URL", "offline-no-node")
            .env("URMA_NODE_AUTH_FILE", "missing-node-auth")
            .env("URMA_VAULT", "missing-vault")
            .env("URMA_UNLOCK_FILE", "missing-unlock");
        command
    }

    fn run(&self, operation: &str) -> Output {
        self.command()
            .args([
                "expert",
                operation,
                "--key",
                "recovery.key",
                "--input",
                "input.urma",
                "--output",
                "recovered.bin",
            ])
            .output()
            .unwrap()
    }

    fn unchanged(&self) {
        assert_eq!(
            fs::read(self.directory.path().join("input.urma")).unwrap(),
            self.input
        );
        assert_eq!(
            fs::read(self.directory.path().join("recovery.key")).unwrap(),
            self.key
        );
    }

    fn files(&self) -> BTreeSet<String> {
        fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }
}

fn succeeded(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8(output.stderr).unwrap()
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn failed(output: Output) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap()
}

fn complete_case() -> Value {
    cases()
        .into_iter()
        .find(|case| case["expected"]["status"] == "complete")
        .unwrap()
}

#[test]
fn independent_complete_cases_recover_exact_bytes_and_report_object_not_source_validity() {
    let mut seen = 0;
    for case in cases() {
        if case["expected"]["status"] != "complete" {
            continue;
        }
        let lab = Lab::new(&case);
        let report = succeeded(lab.run("recover-container"));
        let object = &case["expected"]["object"];
        assert_eq!(report["status"], "recovered-object");
        assert_eq!(report["object_id"], object["id"]);
        assert_eq!(report["chunks"], object["count"]);
        assert_eq!(report["bytes"], object["total"]);
        assert_eq!(report["sha256"], object["digest"]);
        assert_eq!(report["content_type"], object["content_type"]);
        assert_eq!(
            report["skipped_unrelated"],
            case["expected"]["skipped_unrelated"]
        );
        assert_eq!(
            report["rejected_records"],
            case["expected"]["rejected_records"]
        );
        assert!(report.get("container_valid").is_none());
        assert_eq!(
            fs::read(lab.directory.path().join("recovered.bin")).unwrap(),
            artifact(&object["original"]),
        );
        assert_eq!(
            lab.files(),
            BTreeSet::from([
                "input.urma".into(),
                "recovery.key".into(),
                "recovered.bin".into()
            ])
        );
        lab.unchanged();
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn independent_terminal_failures_exit_nonzero_without_any_partial_output() {
    let mut seen = BTreeSet::new();
    for case in cases() {
        let status = case["expected"]["status"].as_str().unwrap();
        if status == "complete" {
            continue;
        }
        let lab = Lab::new(&case);
        let message = failed(lab.run("recover-container"));
        let reason = match status {
            "no-object" => "no authenticated object",
            "mixed" => "multiple authenticated objects",
            "conflict" => "conflicting authenticated",
            "incomplete" => "incomplete object",
            "hash-mismatch" => "whole-file integrity failed",
            "framing" => "",
            other => panic!("unhandled independent status {other}"),
        };
        assert!(message.contains(reason), "{}: {message}", case["name"]);
        if status == "framing" {
            assert!(
                ["container", "URMA", "record marker"]
                    .iter()
                    .any(|cause| message.contains(cause)),
                "{}: {message}",
                case["name"],
            );
        }
        assert_eq!(
            lab.files(),
            BTreeSet::from(["input.urma".into(), "recovery.key".into()])
        );
        lab.unchanged();
        seen.insert(status.to_owned());
    }
    for required in [
        "no-object",
        "mixed",
        "conflict",
        "incomplete",
        "hash-mismatch",
        "framing",
    ] {
        assert!(
            seen.contains(required),
            "missing corpus coverage: {required}"
        );
    }
}

#[test]
fn strict_open_keeps_the_independent_corpus_outcomes() {
    for case in cases() {
        let lab = Lab::new(&case);
        if case["strict_status"] == "complete" {
            succeeded(lab.run("open"));
            assert_eq!(
                fs::read(lab.directory.path().join("recovered.bin")).unwrap(),
                artifact(&case["expected"]["object"]["original"])
            );
        } else {
            assert_eq!(case["strict_status"], "invalid");
            failed(lab.run("open"));
            assert!(!lab.directory.path().join("recovered.bin").exists());
        }
        lab.unchanged();
    }
}

#[test]
fn existing_directory_store_and_recovery_keep_their_contracts() {
    let case = complete_case();
    let lab = Lab::new(&case);
    let stored = succeeded(
        lab.command()
            .args([
                "expert",
                "store-local",
                "--input",
                "input.urma",
                "--directory",
                "records",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(stored["status"], "stored");
    let report = succeeded(
        lab.command()
            .args([
                "expert",
                "recover-local",
                "--directory",
                "records",
                "--key",
                "recovery.key",
                "--output-dir",
                "discovered",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(report["status"], "complete");
    let object = &case["expected"]["object"];
    let path = lab
        .directory
        .path()
        .join("discovered")
        .join(format!("{}.bin", object["id"].as_str().unwrap()));
    assert_eq!(fs::read(path).unwrap(), artifact(&object["original"]));
    let before = fs::read_dir(lab.directory.path().join("records"))
        .unwrap()
        .count();
    assert!(before > 0);
    lab.unchanged();
}

#[test]
fn existing_destination_and_symlink_target_are_never_replaced() {
    let case = complete_case();
    for link in [false, true] {
        let lab = Lab::new(&case);
        let output = lab.directory.path().join("recovered.bin");
        let retained = b"retain existing operator bytes";
        if link {
            fs::write(lab.directory.path().join("retained.bin"), retained).unwrap();
            symlink("retained.bin", &output).unwrap();
        } else {
            fs::write(&output, retained).unwrap();
        }
        let files = lab.files();
        failed(lab.run("recover-container"));
        assert_eq!(fs::read(&output).unwrap(), retained);
        if link {
            assert_eq!(fs::read_link(&output).unwrap(), Path::new("retained.bin"));
        }
        assert_eq!(lab.files(), files);
        lab.unchanged();
        let message = failed(lab.run("open"));
        assert!(message.contains("without overwrite"), "{message}");
        assert_eq!(fs::read(&output).unwrap(), retained);
        assert_eq!(lab.files(), files);
        lab.unchanged();
    }
}

#[test]
fn invalid_output_config_input_key_and_capacity_fail_before_write() {
    let case = complete_case();
    let lab = Lab::new(&case);
    let output = lab
        .command()
        .env("URMA_OUTPUT", "invalid")
        .args([
            "expert",
            "recover-container",
            "--key",
            "recovery.key",
            "--input",
            "input.urma",
            "--output",
            "recovered.bin",
        ])
        .output()
        .unwrap();
    assert!(failed(output).contains("unsupported URMA_OUTPUT"));
    assert!(!lab.directory.path().join("recovered.bin").exists());
    lab.unchanged();
    let lab = Lab::new(&case);
    fs::remove_file(lab.directory.path().join("input.urma")).unwrap();
    failed(lab.run("recover-container"));
    assert!(!lab.directory.path().join("recovered.bin").exists());
    let lab = Lab::new(&case);
    fs::set_permissions(
        lab.directory.path().join("recovery.key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(failed(lab.run("recover-container")).contains("recovery key must be private"));
    assert!(!lab.directory.path().join("recovered.bin").exists());
    for size in [0, 31, 33] {
        let lab = Lab::new(&case);
        fs::write(lab.directory.path().join("recovery.key"), vec![7; size]).unwrap();
        assert!(failed(lab.run("recover-container")).contains("exactly 32 raw bytes"));
        assert!(!lab.directory.path().join("recovered.bin").exists());
    }
    let lab = Lab::new(&case);
    fs::OpenOptions::new()
        .write(true)
        .open(lab.directory.path().join("input.urma"))
        .unwrap()
        .set_len(u64::try_from(urma_runtime::config::Limits::CONTAINER_BYTES + 1).unwrap())
        .unwrap();
    failed(lab.run("recover-container"));
    assert!(!lab.directory.path().join("recovered.bin").exists());
}

#[test]
fn help_names_explicit_offline_mode_strict_framing_and_no_salvage() {
    let lab = Lab::new(&complete_case());
    let output = lab
        .command()
        .args(["expert", "recover-container", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for text in [
        "Explicit offline recovery mode",
        "framing remains strict",
        "no magic-byte salvage",
        "--key",
        "--input",
        "--output",
    ] {
        assert!(help.contains(text), "{help}");
    }
}
