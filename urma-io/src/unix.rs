use crate::{Access, Error, files::read_into};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub fn create_private_directory(path: &Path) -> Result<(), io::Error> {
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

pub fn create_file(path: &Path, access: Access) -> Result<File, io::Error> {
    let mode = match access {
        Access::Private => 0o600,
        Access::Shared => 0o640,
    };
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn open_regular(path: &Path) -> Result<File, Error> {
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
    Ok(file)
}

pub fn read_regular(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = open_regular(path)?;
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

fn admin_owned(metadata: &std::fs::Metadata) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner_trusted = metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() };
    match owner_trusted && metadata.mode() & 0o022 == 0 {
        true => Ok(()),
        false => Err(Error::PrivatePermissions),
    }
}

pub fn read_admin(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = open_regular(path)?;
    admin_owned(&file.metadata()?)?;
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}

pub fn check_admin(path: &Path) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrator-owned paths must not be symlinks",
        )
        .into());
    }
    admin_owned(&metadata)
}

pub fn read_shared(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = open_regular(path)?;
    if file.metadata()?.permissions().mode() & 0o027 != 0 {
        return Err(Error::PrivatePermissions);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}
