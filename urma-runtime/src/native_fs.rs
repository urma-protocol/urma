use crate::error::Error;
use std::{fs::File, io, path::Path};
use urma_io::Access;

/// Volume and file identity: two paths naming the same file compare equal.
#[cfg(unix)]
pub(crate) fn file_identity(path: &Path) -> Result<(u64, u128), Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), u128::from(metadata.ino())))
}

/// 64-bit volume serial and 128-bit file id, exact on ReFS as well as NTFS.
#[cfg(windows)]
pub(crate) fn file_identity(path: &Path) -> Result<(u64, u128), Error> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let file = File::open(path)?;
    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(size_of::<FILE_ID_INFO>()).map_err(io::Error::other)?;
    // SAFETY: the handle is open for the call and `info` is exactly `size` bytes.
    let filled = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            std::ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if filled == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

/// An append-only log that is private from its first byte: created through
/// `urma_io::create_file`, reopened only if it is still a private regular
/// file with one link (no symlink, fifo, device or planted alias).
pub(crate) fn append_private(path: &Path) -> Result<File, Error> {
    match urma_io::create_file(path, Access::Private) {
        Ok(file) => Ok(file),
        Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => {
            Ok(urma_io::open_private_append(path)?)
        }
        Err(cause) => Err(cause.into()),
    }
}

/// Flushes a directory after data in it landed. On Windows some filesystems
/// (network shares, FAT, older ReFS) refuse the flush; the data is already
/// durable there, so the refusal is logged instead of failing the caller.
#[cfg(not(windows))]
pub(crate) fn sync_landed(directory: &Path) -> Result<(), Error> {
    urma_io::sync_directory(directory)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn sync_landed(directory: &Path) -> Result<(), Error> {
    match urma_io::sync_directory(directory) {
        Ok(()) => {}
        Err(cause) => tracing::warn!(
            error = %cause,
            directory = %directory.display(),
            "data landed; directory flush unsupported here"
        ),
    }
    Ok(())
}
