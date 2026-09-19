use crate::config::output_parent;
use crate::error::{Context, Error, ensure};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(
            u64::try_from(limit)?
                .checked_add(1)
                .context("file read limit overflow")?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Capacity(format!(
            "file exceeds {limit} byte client capacity"
        )));
    }
    Ok(bytes)
}

pub fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.permissions().mode() & 0o077 == 0,
        "recovery key must be private: chmod 600 {}",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == 32,
        "recovery key must contain exactly 32 raw bytes"
    );
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = output_parent(path);
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .with_context(|| format!("create {} without overwrite", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
