use crate::{Error, files::read_into};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub fn digest(input: &mut impl Read) -> Result<[u8; 32], io::Error> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

pub fn create_private_directory(path: &Path) -> Result<(), io::Error> {
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

pub fn read_regular(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only regular input files are supported",
        )
        .into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}

pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = File::open(path)?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(Error::PrivatePermissions);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}
