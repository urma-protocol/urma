use std::error::Error as _;
use std::{fs::File, path::Path};
use urma_io::*;

#[test]
fn bounded_reads_accept_exact_limit_and_reject_one_more() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    std::fs::write(&path, []).unwrap();
    assert_eq!(read_bounded(&path, 0).unwrap(), b"");
    std::fs::write(&path, b"abc").unwrap();
    assert_eq!(read_bounded(&path, 3).unwrap(), b"abc");
    assert!(matches!(
        read_bounded(&path, 2),
        Err(Error::TooLarge { limit: 2 })
    ));
    assert!(matches!(
        read_bounded(&path, 0),
        Err(Error::TooLarge { limit: 0 })
    ));
    // A sparse large file must be rejected without allocating its size.
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    assert!(matches!(
        read_bounded(&path, 16),
        Err(Error::TooLarge { limit: 16 })
    ));
}

#[test]
fn read_errors_preserve_context_and_cause() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing");
    let error = read_bounded(&path, 10).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("open {}", path.display()))
    );
    let io = error
        .source()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
}

#[test]
#[cfg(target_pointer_width = "64")]
fn read_limit_overflow_is_rejected() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        read_bounded(file.path(), usize::MAX),
        Err(Error::LimitOverflow)
    ));
}

#[test]
fn atomic_modes_preserve_existing_file_or_replace_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output");
    write_new(&path, b"first").unwrap();
    let error = write_new(&path, b"second").unwrap_err();
    match &error {
        Error::Context { cause, .. } => match cause.as_ref() {
            Error::Persist(cause) => {
                assert_eq!(cause.error.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("unexpected cause: {other:?}"),
        },
        other => panic!("unexpected error: {other:?}"),
    }
    drop(error); // Releases the failed persistence temporary file.
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    write_replace(&path, b"second").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    write_replace(&path, b"").unwrap();
    assert!(std::fs::read(&path).unwrap().is_empty());
    write_replace(&dir.path().join("new"), b"created").unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn output_parent_handles_bare_paths() {
    assert_eq!(output_parent(Path::new("file")), Path::new("."));
    assert_eq!(output_parent(Path::new("")), Path::new("."));
    assert_eq!(output_parent(Path::new("/")), Path::new("."));
    assert_eq!(output_parent(Path::new("dir/file")), Path::new("dir"));
}

#[test]
fn stream_digest_consumes_from_current_position_without_rewinding() {
    use std::io::{Cursor, Seek};
    let mut input = Cursor::new(b"prefixabc".to_vec());
    input.set_position(6);
    assert_eq!(
        digest(&mut input).unwrap(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(input.stream_position().unwrap(), 9);
}

#[test]
fn regular_reads_reject_symlinks_directories_and_fifo() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data");
    std::fs::write(&file, b"abc").unwrap();
    assert_eq!(&**read_regular(&file, 3).unwrap(), b"abc");
    assert!(matches!(
        read_regular(&file, 2),
        Err(Error::TooLarge { limit: 2 })
    ));
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(read_regular(&link, 3).is_err());
    assert!(read_regular(dir.path(), 3).is_err());
    let fifo = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(read_regular(&fifo, 3).is_err());
}

#[test]
fn private_directory_refuses_existing_paths_and_has_no_group_access() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("private");
    create_private_directory(&target).unwrap();
    assert_eq!(target.metadata().unwrap().permissions().mode() & 0o077, 0);
    assert_eq!(
        create_private_directory(&target).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
}

#[test]
fn private_reads_check_permissions_and_bounds_on_the_open_file() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    std::fs::write(&path, b"abc").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(&**read_private(&path, 3).unwrap(), b"abc");
    assert!(matches!(
        read_private(&path, 2),
        Err(Error::TooLarge { limit: 2 })
    ));
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert_eq!(&**read_private(&link, 3).unwrap(), b"abc");
    for mode in [0o640, 0o604, 0o601] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            read_private(&link, 3),
            Err(Error::PrivatePermissions)
        ));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, []).unwrap();
    assert!(read_private(&path, 0).unwrap().is_empty());
}
