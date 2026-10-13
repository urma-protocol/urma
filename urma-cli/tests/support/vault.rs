use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

/// A vault recovered from the public test phrase that also derives the
/// publication_node mock's funder, so plans the mock funded pass
/// `require_funder` on publish and resume. Public test values: never fund.
pub fn mock_funder_vault(directory: &Path) -> (PathBuf, PathBuf) {
    let vault = directory.join("funder.vault");
    let unlock = directory.join("funder-unlock");
    if vault.exists() {
        return (vault, unlock);
    }
    let phrase = directory.join("funder-phrase");
    for (path, text) in [
        (&phrase, format!("{}about", "abandon ".repeat(11))),
        (&unlock, "private funder test password".to_owned()),
    ] {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_CONFIG", directory.join("absent-config"))
        .env("URMA_OUTPUT", "json")
        .args(["key", "recover", "--phrase-file"])
        .arg(&phrase)
        .arg("--password-file")
        .arg(&unlock)
        .arg("--output")
        .arg(&vault)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (vault, unlock)
}
