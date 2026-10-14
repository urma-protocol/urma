#![cfg(any(unix, windows))]
use std::io::Write;
use urma_io::{Access, Error, create_file, open_private_append};

fn private(path: &std::path::Path, bytes: &[u8]) {
    create_file(path, Access::Private)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
fn private_logs_reopen_for_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("observations.jsonl");
    private(&path, b"first\n");
    open_private_append(&path)
        .unwrap()
        .write_all(b"second\n")
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
    assert!(open_private_append(dir.path()).is_err());
    assert!(open_private_append(&dir.path().join("absent")).is_err());
}

#[test]
fn hard_linked_logs_are_refused_under_both_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("observations.jsonl");
    private(&path, b"log\n");
    let alias = dir.path().join("alias.jsonl");
    std::fs::hard_link(&path, &alias).unwrap();
    for name in [&path, &alias] {
        assert!(matches!(
            open_private_append(name),
            Err(Error::PrivatePermissions)
        ));
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"log\n");
}

#[test]
#[cfg(unix)]
fn planted_links_fifos_and_open_modes_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.jsonl");
    private(&target, b"target\n");
    let link = dir.path().join("link.jsonl");
    symlink(&target, &link).unwrap();
    assert!(open_private_append(&link).is_err());
    let fifo = dir.path().join("fifo.jsonl");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `name` is a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(
        open_private_append(&fifo).is_err(),
        "a fifo never blocks the open"
    );
    for mode in [0o644, 0o640, 0o604, 0o620] {
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            open_private_append(&target),
            Err(Error::PrivatePermissions)
        ));
    }
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut appended = open_private_append(&target).unwrap();
    appended.write_all(b"blocking writes work\n").unwrap();
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"target\nblocking writes work\n"
    );
}
