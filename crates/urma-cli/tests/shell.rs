//! Independent decoder checks. Child PATH contains only standard utilities and
//! OpenSSL, never urma, Cargo, Python, jq, xxd or a custom crypto helper.
use aes::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use urma::{container, storage};

struct Lab {
    work: tempfile::TempDir,
    path: PathBuf,
}

const TOOLS: &[&str] = &[
    "openssl", "tr", "wc", "mkdir", "rm", "rmdir", "dd", "od", "awk", "mv", "cmp", "cat", "ln",
    "ls",
];

impl Lab {
    fn new() -> Self {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("tools");
        fs::create_dir(&path).unwrap();
        for name in TOOLS {
            let real = Path::new("/usr/bin").join(name);
            assert!(real.is_file(), "missing test dependency: {name}");
            symlink(real, path.join(name)).unwrap();
        }
        Self { work, path }
    }

    fn decode(&self, shell: &str, key: &[u8], bundle: &[u8], case: &str) -> (Output, PathBuf) {
        let base = self.work.path().join(case);
        fs::create_dir(&base).unwrap();
        let key_path = base.join("private key");
        let bundle_path = base.join("encrypted bundle");
        let output = base.join("decoded photo.jpg");
        storage::write_new(&key_path, key).unwrap();
        storage::write_new(&bundle_path, bundle).unwrap();
        let mut command = Command::new(shell);
        if shell.ends_with("busybox") {
            command.arg("sh");
        }
        let result = command
            .arg(concat!(
                concat!(env!("CARGO_MANIFEST_DIR"), "/../.."),
                "/scripts/open-bundle.sh"
            ))
            .arg(&key_path)
            .arg(&bundle_path)
            .arg(&output)
            .env_clear()
            .env("PATH", &self.path)
            .output()
            .unwrap();
        for entry in fs::read_dir(&base).unwrap() {
            assert!(
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".urma-open-"),
                "temporary plaintext not cleaned up"
            );
        }
        (result, output)
    }
}

fn must_fail(result: Output, output: &Path) {
    assert!(!result.status.success(), "invalid input succeeded");
    assert!(!output.exists(), "failure exported plaintext");
}

#[test]
fn real_jpeg_roundtrip_in_sh_dash_and_busybox_without_our_binary() {
    let lab = Lab::new();
    let key = [42; 32];
    let jpeg = include_bytes!("../../../tests/fixtures/sample.jpg");
    let records = container::seal(&key, jpeg, urma::format::ContentType::Opaque).unwrap();
    let bundle = container::pack(&records).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records.iter().map(Vec::len).sum::<usize>(), 98_784);
    for (i, shell) in ["/bin/sh", "/usr/bin/dash", "/usr/bin/busybox"]
        .iter()
        .enumerate()
    {
        if !Path::new(shell).exists() {
            eprintln!("optional shell not installed: {shell}");
            continue;
        }
        if shell.ends_with("busybox") {
            // Also exercise BusyBox's awk/od/dd/etc, not just its shell parser.
            for name in TOOLS.iter().filter(|name| **name != "openssl") {
                fs::remove_file(lab.path.join(name)).unwrap();
                symlink("/usr/bin/busybox", lab.path.join(name)).unwrap();
            }
        }
        let (result, output) = lab.decode(shell, &key, &bundle, &format!("jpeg-{i}"));
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&output).unwrap(), jpeg);
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn boundaries_shuffle_and_identical_duplicates() {
    let lab = Lab::new();
    let key = [0; 32];
    for length in [1, 32767, 32768, 32769, 65536, 1_048_577] {
        let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut records = container::seal(&key, &bytes, urma::format::ContentType::Opaque).unwrap();
        records.reverse();
        if records.len() < urma::config::Limits::RECORDS {
            records.push(records[0].clone());
        }
        let (result, output) = lab.decode(
            "/bin/sh",
            &key,
            &container::pack(&records).unwrap(),
            &format!("size-{length}"),
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(output).unwrap(), bytes);
    }
}

#[test]
fn malformed_and_forged_inputs_never_export_plaintext() {
    let lab = Lab::new();
    let key = [7; 32];
    let records = container::seal(&key, &[9; 32769], urma::format::ContentType::Opaque).unwrap();
    let bundle = container::pack(&records).unwrap();
    for offset in [
        0, 4, 8, 12, 16, 48, 64, 68, 72, 87, 88, 120, 128, 528, 32895, 32927,
    ] {
        let mut corrupt = bundle.clone();
        corrupt[offset] ^= 1;
        let (result, output) = lab.decode("/bin/sh", &key, &corrupt, &format!("mutate-{offset}"));
        must_fail(result, &output);
    }
    for length in [0, 7, 8, 12, bundle.len() - 1] {
        let (result, output) = lab.decode(
            "/bin/sh",
            &key,
            &bundle[..length],
            &format!("truncate-{length}"),
        );
        must_fail(result, &output);
    }
    let mut trailing = bundle.clone();
    trailing.push(0);
    let (result, output) = lab.decode("/bin/sh", &key, &trailing, "trailing");
    must_fail(result, &output);
    for length in [0, 31, 33] {
        let (result, output) = lab.decode(
            "/bin/sh",
            &vec![7; length],
            &bundle,
            &format!("key-length-{length}"),
        );
        must_fail(result, &output);
    }
    let (result, output) = lab.decode("/bin/sh", &[8; 32], &bundle, "wrong-key");
    must_fail(result, &output);
    let (result, output) = lab.decode(
        "/bin/sh",
        &key,
        &container::pack(&records[..1]).unwrap(),
        "missing",
    );
    must_fail(result, &output);
    let repeated = vec![records[0].clone(), records[0].clone()];
    let (result, output) = lab.decode(
        "/bin/sh",
        &key,
        &container::pack(&repeated).unwrap(),
        "repeated-as-missing",
    );
    must_fail(result, &output);
    let other = container::seal(&key, &[9; 32769], urma::format::ContentType::Opaque).unwrap();
    let mut mixed = container::pack(&records).unwrap();
    let second_offset = 12 + 4 + urma::format::Urma::PRIVATE_RECORD_BYTES + 4;
    mixed[second_offset..].copy_from_slice(&other[1]);
    assert!(container::unpack(&mixed).is_err());
    let (result, output) = lab.decode("/bin/sh", &key, &mixed, "mixed");
    must_fail(result, &output);
}

fn rewrite_record(key: &[u8; 32], record: &mut Vec<u8>, edit: impl FnOnce(&mut [u8])) {
    let hkdf = Hkdf::<Sha256>::new(Some(&record[8..40]), key);
    let mut enc = [0; 32];
    let mut mac_key = [0; 32];
    hkdf.expand(b"URMA/V0/private/content", &mut enc).unwrap();
    hkdf.expand(b"URMA/V0/private/authentication", &mut mac_key)
        .unwrap();
    let iv: [u8; 16] = record[64..80].try_into().unwrap();
    let end = record.len() - 32;
    let mut body = record[80..end].to_vec();
    ctr::Ctr128BE::<aes::Aes256>::new((&enc).into(), (&iv).into()).apply_keystream(&mut body);
    edit(&mut body);
    ctr::Ctr128BE::<aes::Aes256>::new((&enc).into(), (&iv).into()).apply_keystream(&mut body);
    record.truncate(80);
    record.extend(body);
    let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
    mac.update(record);
    record.extend_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn authenticated_but_inconsistent_metadata_is_rejected() {
    let lab = Lab::new();
    let key = [8; 32];
    let records = container::seal(&key, &[1; 32769], urma::format::ContentType::Opaque).unwrap();
    for total in [0u64, 32768, 1048577, u64::MAX] {
        let mut changed = records.clone();
        rewrite_record(&key, &mut changed[0], |body| {
            body[32..40].copy_from_slice(&total.to_le_bytes())
        });
        let (result, output) = lab.decode(
            "/bin/sh",
            &key,
            &container::pack(&changed).unwrap(),
            &format!("bad-length-{total}"),
        );
        must_fail(result, &output);
    }
    for (name, offset) in [("digest", 0), ("content", 48)] {
        let mut changed = records.clone();
        rewrite_record(&key, &mut changed[1], |body| body[offset] ^= 1);
        let (result, output) =
            lab.decode("/bin/sh", &key, &container::pack(&changed).unwrap(), name);
        must_fail(result, &output);
    }
}

#[test]
fn a_forged_record_never_reaches_openssl_decryption() {
    let lab = Lab::new();
    let marker = lab.work.path().join("decryption-called");
    // Replace only the test-owned symlink; log a boolean, never secret arguments.
    fs::remove_file(lab.path.join("openssl")).unwrap();
    fs::write(
        lab.path.join("openssl"),
        format!(
            "#!/bin/sh\nif [ \"$1\" = enc ]; then : > '{}'; fi\nexec /usr/bin/openssl \"$@\"\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(lab.path.join("openssl"), fs::Permissions::from_mode(0o700)).unwrap();
    let key = [21; 32];
    let mut records = container::seal(
        &key,
        b"MAC must be checked first",
        urma::format::ContentType::Opaque,
    )
    .unwrap();
    let original = container::pack(&records).unwrap();
    records[0][urma::format::Urma::BODY_OFFSET + 43] ^= 1;
    let (result, output) = lab.decode(
        "/bin/sh",
        &key,
        &container::pack(&records).unwrap(),
        "forged-before-decrypt",
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("record authentication failed"));
    must_fail(result, &output);
    assert!(!marker.exists());
    let (result, _) = lab.decode("/bin/sh", &key, &original, "authentic-reaches-decrypt");
    assert!(result.status.success());
    assert!(marker.exists());
}

#[test]
fn existing_output_and_symlinks_are_never_overwritten() {
    let lab = Lab::new();
    let key = [9; 32];
    let bundle = container::pack(
        &container::seal(&key, b"test", urma::format::ContentType::Opaque).unwrap(),
    )
    .unwrap();
    let base = lab.work.path();
    storage::write_new(&base.join("key"), &key).unwrap();
    storage::write_new(&base.join("bundle"), &bundle).unwrap();
    storage::write_new(&base.join("existing"), b"keep").unwrap();
    symlink(base.join("existing"), base.join("link")).unwrap();
    fs::create_dir(base.join("directory")).unwrap();
    for name in ["existing", "link", "directory"] {
        let result = Command::new("/bin/sh")
            .arg(concat!(
                concat!(env!("CARGO_MANIFEST_DIR"), "/../.."),
                "/scripts/open-bundle.sh"
            ))
            .arg(base.join("key"))
            .arg(base.join("bundle"))
            .arg(base.join(name))
            .env_clear()
            .env("PATH", &lab.path)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(fs::read(base.join("existing")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(base.join("directory")).unwrap().count(), 0);
    }
}
