use crate::Error;
use std::{io, path::Path};
use zeroize::Zeroizing;

pub fn create_private_directory(path: &Path) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native private directory creation is unavailable on WASM: {}",
            path.display()
        ),
    ))
}

pub fn read_regular(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native regular file read is unavailable on WASM: {} (limit {limit})",
            path.display()
        ),
    )
    .into())
}

pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native private file read is unavailable on WASM: {} (limit {limit})",
            path.display()
        ),
    )
    .into())
}
