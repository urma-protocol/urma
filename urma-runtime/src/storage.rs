use crate::error::Error;
use std::path::Path;

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    urma_io::read_bounded(path, limit).map_err(Error::from)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    urma_io::write_new(path, bytes).map_err(Error::from)
}
