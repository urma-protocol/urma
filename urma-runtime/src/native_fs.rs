use crate::error::Error;
use std::path::Path;

#[cfg(unix)]
pub(crate) fn file_identity(path: &Path) -> Result<(u64, u64), Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub(crate) fn file_identity(path: &Path) -> Result<(u64, u64), Error> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let file = std::fs::File::open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the call and `info` is a valid out pointer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}
