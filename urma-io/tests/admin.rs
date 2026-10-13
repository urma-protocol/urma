#![cfg(any(unix, windows))]
use urma_io::{Error, check_admin, read_admin};

#[test]
#[cfg(unix)]
fn admin_files_refuse_group_or_other_writers_and_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("service.json");
    std::fs::write(&path, b"{}").unwrap();
    for mode in [0o644, 0o640, 0o600, 0o444] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(&**read_admin(&path, 2).unwrap(), b"{}");
        check_admin(&path).unwrap();
    }
    assert!(matches!(
        read_admin(&path, 1),
        Err(Error::TooLarge { limit: 1 })
    ));
    for mode in [0o664, 0o646, 0o666, 0o622] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            read_admin(&path, 2),
            Err(Error::PrivatePermissions)
        ));
        assert!(matches!(check_admin(&path), Err(Error::PrivatePermissions)));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(read_admin(&link, 2).is_err());
    assert!(check_admin(&link).is_err());
    assert!(read_admin(dir.path(), 2).is_err());
    let settings = dir.path().join("etc");
    std::fs::create_dir(&settings).unwrap();
    for (mode, admin) in [(0o755, true), (0o750, true), (0o775, false), (0o777, false)] {
        std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(check_admin(&settings).is_ok(), admin, "{mode:o}");
    }
}

#[test]
#[cfg(windows)]
fn admin_checks_accept_files_and_directories_the_caller_owns() {
    use urma_io::{Access, create_file, create_private_directory};
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("URMA Node");
    create_private_directory(&settings).unwrap();
    check_admin(&settings).unwrap();
    let path = settings.join("service.json");
    std::io::Write::write_all(&mut create_file(&path, Access::Shared).unwrap(), b"{}").unwrap();
    assert_eq!(&**read_admin(&path, 2).unwrap(), b"{}");
    check_admin(&path).unwrap();
    assert!(matches!(
        read_admin(&path, 1),
        Err(Error::TooLarge { limit: 1 })
    ));
    assert!(read_admin(&settings, 2).is_err());
}
