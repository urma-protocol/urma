use std::{fs, path::Path, process::Command};

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
    command
        .env_clear()
        .current_dir(directory)
        .env("URMA_CONFIG", directory.join("missing-config.json"))
        .env("URMA_LOG_OUTPUT", "stderr")
        .env("URMA_OUTPUT", "json");
    command
}

#[test]
fn profile_cli_preserves_valid_bytes_and_refuses_oversize_without_output() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("profile.txt");
    let output = directory.path().join("profile.record");
    for text in [
        "".to_owned(),
        "a".repeat(127),
        "a".repeat(128),
        "ț".repeat(64),
        "😀".repeat(32),
        " \0e\u{301}\r\n ".into(),
    ] {
        fs::write(&input, text.as_bytes()).unwrap();
        let encoded = command(directory.path())
            .args(["wire", "expert", "encode", "--kind", "profile", "--input"])
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            encoded.status.success(),
            "{}",
            String::from_utf8_lossy(&encoded.stderr)
        );
        let bytes = fs::read(&output).unwrap();
        assert_eq!(&bytes[..8], b"URMA\x00\x05\x00\x00");
        assert_eq!(&bytes[8..], text.as_bytes());
        assert_eq!(fs::read(&input).unwrap(), text.as_bytes());
        fs::remove_file(&output).unwrap();
    }
    for text in [
        "a".repeat(129),
        "a".repeat(32760),
        format!("{}a", "ț".repeat(64)),
        "ț".repeat(65),
    ] {
        fs::write(&input, text.as_bytes()).unwrap();
        let encoded = command(directory.path())
            .args(["wire", "expert", "encode", "--kind", "profile", "--input"])
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!encoded.status.success());
        assert!(String::from_utf8_lossy(&encoded.stderr).contains("128 UTF-8 bytes"));
        assert!(!output.exists());
        assert_eq!(fs::read(&input).unwrap(), text.as_bytes());
    }
    fs::write(&input, [0xFF; 128]).unwrap();
    let encoded = command(directory.path())
        .args(["wire", "expert", "encode", "--kind", "profile", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!encoded.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), [0xFF; 128]);
}

#[test]
fn profile_cli_refusal_preserves_an_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("profile.txt");
    let output = directory.path().join("existing.record");
    fs::write(&input, "ț".repeat(65)).unwrap();
    fs::write(&output, b"original destination").unwrap();
    let encoded = command(directory.path())
        .args(["wire", "expert", "encode", "--kind", "profile", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!encoded.status.success());
    assert!(String::from_utf8_lossy(&encoded.stderr).contains("128 UTF-8 bytes"));
    assert_eq!(fs::read(&input).unwrap(), "ț".repeat(65).as_bytes());
    assert_eq!(fs::read(&output).unwrap(), b"original destination");
}
