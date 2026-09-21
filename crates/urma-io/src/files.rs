use crate::{Error, output_parent};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let file = File::open(path).map_err(|cause| Error::Context {
        message: format!("open {}", path.display()),
        cause: Box::new(Error::Io(cause)),
    })?;
    let mut bytes = Vec::new();
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn read_into(input: impl Read, limit: usize, bytes: &mut Vec<u8>) -> Result<(), Error> {
    let bound = u64::try_from(limit)
        .map_err(Error::Integer)?
        .checked_add(1)
        .ok_or(Error::LimitOverflow)?;
    input.take(bound).read_to_end(bytes)?;
    if bytes.len() > limit {
        return Err(Error::TooLarge { limit });
    }
    Ok(())
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    write_atomic(path, bytes, false)
}

pub fn write_replace(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    write_atomic(path, bytes, true)
}

fn write_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<(), Error> {
    let parent = output_parent(path);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if replace {
        temporary.persist(path).map_err(Error::Persist)?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|cause| Error::Context {
                message: format!("create {} without overwrite", path.display()),
                cause: Box::new(Error::Persist(cause)),
            })?;
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}
