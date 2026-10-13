mod acl;

use crate::{Access, Error, files::read_into, output_parent};
use acl::{Descriptor, Grant, User, last_error, refuse_untrusted, wide};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::FromRawHandle,
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW,
    },
};
use zeroize::Zeroizing;

struct Policy;

impl Policy {
    const DIRECTORY_INHERIT: &str = "OICI";
    const FILE_INHERIT: &str = "";
    const SHARED_READ: &str = "(A;;FR;;;BU)";
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
}

fn private_sddl(inherit: &str) -> Result<String, io::Error> {
    let user = User::current()?.sddl()?;
    Ok(["OW", "SY", "BA", user.as_str()]
        .iter()
        .fold(String::from("D:P"), |sddl, sid| {
            sddl + &format!("(A;{inherit};FA;;;{sid})")
        }))
}

pub fn create_private_directory(path: &Path) -> Result<(), io::Error> {
    let descriptor = Descriptor::parse(&private_sddl(Policy::DIRECTORY_INHERIT)?)?;
    let attributes = descriptor.attributes()?;
    let path = wide(path.as_os_str());
    // SAFETY: `path` is NUL-terminated and `attributes` outlives the call.
    match unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } {
        0 => Err(last_error()),
        _ => Ok(()),
    }
}

pub fn create_file(path: &Path, access: Access) -> Result<File, io::Error> {
    let private = private_sddl(Policy::FILE_INHERIT)?;
    let descriptor = Descriptor::parse(&match access {
        Access::Private => private,
        Access::Shared => private + Policy::SHARED_READ,
    })?;
    let attributes = descriptor.attributes()?;
    let path = wide(path.as_os_str());
    // SAFETY: `path` is NUL-terminated and `attributes` outlives the call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            Policy::GENERIC_READ | Policy::GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    match handle {
        INVALID_HANDLE_VALUE => Err(last_error()),
        // SAFETY: CreateFileW returned a fresh handle that the File now owns.
        _ => Ok(unsafe { File::from_raw_handle(handle) }),
    }
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<(), Error> {
    let parent = output_parent(path);
    let (mut file, mut temporary) = tempfile::Builder::new()
        .make_in(parent, |candidate| create_file(candidate, Access::Private))?
        .into_parts();
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let flags = match replace {
        true => MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING,
        false => MOVEFILE_WRITE_THROUGH,
    };
    let from = wide(temporary.as_os_str());
    let to = wide(path.as_os_str());
    // SAFETY: both paths are NUL-terminated and the temporary file is closed.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(Error::Context {
            message: format!("move into {}", path.display()),
            cause: Box::new(Error::Io(last_error())),
        });
    }
    temporary.disable_cleanup(true);
    match sync_directory(parent) {
        Ok(()) => {}
        Err(cause) => tracing::warn!(
            target: "urma_io",
            error = %cause,
            directory = %parent.display(),
            "file landed; directory flush unsupported here"
        ),
    }
    Ok(())
}

pub fn sync_directory(path: &Path) -> Result<(), io::Error> {
    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

fn open_regular(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only regular input files are supported",
        )
        .into());
    }
    Ok(file)
}

fn read_checked(path: &Path, limit: usize, grant: Grant) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = open_regular(path)?;
    refuse_untrusted(&file, grant)?;
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}

pub fn read_regular(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = open_regular(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    read_into(file, limit, &mut bytes)?;
    Ok(bytes)
}

pub fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    read_checked(path, limit, Grant::Any)
}

pub fn read_shared(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    read_checked(path, limit, Grant::Write)
}
