use crate::{Access, Error};
use std::{fs::File, io, path::Path};
use zeroize::Zeroizing;

pub fn create_file(path: &Path, access: Access) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native {access:?} file creation is unavailable on WASM: {}",
            path.display()
        ),
    ))
}

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

pub fn read_admin(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native administrator file read is unavailable on WASM: {} (limit {limit})",
            path.display()
        ),
    )
    .into())
}

pub fn check_admin(path: &Path) -> Result<(), Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native administrator check is unavailable on WASM: {}",
            path.display()
        ),
    )
    .into())
}

pub fn read_shared(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native shared file read is unavailable on WASM: {} (limit {limit})",
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
