use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn archive_intake_requires_a_private_exactly_32_byte_recovery_key() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("recovery.key");
    let input = directory.path().join("original.txt");
    fs::write(&input, b"private original").unwrap();
    for (size, mode, expected_error) in [
        (32, 0o644, Some("recovery key must be private")),
        (
            31,
            0o600,
            Some("recovery key must contain exactly 32 raw bytes"),
        ),
        (
            33,
            0o600,
            Some("recovery key must contain exactly 32 raw bytes"),
        ),
        (32, 0o600, None),
    ] {
        fs::write(&key, vec![7; size]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(mode)).unwrap();
        let bundle = directory.path().join(format!("bundle-{size}-{mode}"));
        let result = Command::new(env!("CARGO_BIN_EXE_urma"))
            .env("URMA_ARCHIVE_KEY", &key)
            .env("URMA_CONFIG", directory.path().join("missing-config.json"))
            .args(["archive", "ingest"])
            .arg(&input)
            .arg("--output")
            .arg(&bundle)
            .output()
            .unwrap();
        match expected_error {
            Some(message) => {
                assert!(!result.status.success());
                assert!(String::from_utf8_lossy(&result.stderr).contains(message));
                assert!(!bundle.exists());
            }
            None => {
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert!(bundle.is_dir());
            }
        }
    }
}
