use std::{io::ErrorKind, path::Path};
use urma_io::Error;

#[path = "../src/wasm.rs"]
mod wasm;

#[test]
fn browser_native_file_helpers_fail_explicitly() {
    let path = Path::new("browser-does-not-have-this-native-file");
    assert_eq!(
        wasm::create_private_directory(path).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    for result in [
        wasm::read_private(path, 1024),
        wasm::read_regular(path, 1024),
    ] {
        match result {
            Err(Error::Io(cause)) => assert_eq!(cause.kind(), ErrorKind::Unsupported),
            other => panic!("expected unsupported filesystem operation, got {other:?}"),
        }
    }
}
