use std::{io::ErrorKind, path::Path};
use urma_io::{Access, Error};

#[path = "../src/wasm.rs"]
mod wasm;

#[test]
fn browser_native_file_helpers_fail_explicitly() {
    let path = Path::new("browser-does-not-have-this-native-file");
    assert_eq!(
        wasm::create_private_directory(path).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    for access in [Access::Private, Access::Shared] {
        match wasm::create_file(path, access) {
            Err(cause) => assert_eq!(cause.kind(), ErrorKind::Unsupported),
            Ok(file) => panic!("expected unsupported file creation, got {file:?}"),
        }
    }
    for result in [
        wasm::read_private(path, 1024),
        wasm::read_regular(path, 1024),
        wasm::read_shared(path, 1024),
    ] {
        match result {
            Err(Error::Io(cause)) => assert_eq!(cause.kind(), ErrorKind::Unsupported),
            other => panic!("expected unsupported filesystem operation, got {other:?}"),
        }
    }
}
