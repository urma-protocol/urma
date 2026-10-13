use crate::Error;
use std::{
    ffi::OsStr,
    fs::File,
    io,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
        WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct Policy;

impl Policy {
    const TRUSTED: [&str; 3] = ["S-1-5-18", "S-1-5-32-544", "S-1-3-4"];
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const ACCESS_ALLOWED: u8 = 0;
    const ACCESS_DENIED: u8 = 1;
}

pub(super) fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

pub(super) fn last_error() -> io::Error {
    io::Error::last_os_error()
}

pub(super) struct Local<T>(*mut T);

impl<T> Drop for Local<T> {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Win32 call that allocates with LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) struct Descriptor(Local<core::ffi::c_void>);

impl Descriptor {
    pub(super) fn parse(sddl: &str) -> Result<Self, io::Error> {
        let text = wide(OsStr::new(sddl));
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated; the descriptor is freed by `Local`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        match converted {
            0 => Err(last_error()),
            _ => Ok(Self(Local(descriptor))),
        }
    }

    pub(super) fn attributes(&self) -> Result<SECURITY_ATTRIBUTES, io::Error> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        })
    }
}

fn sid(text: &str) -> Result<Local<core::ffi::c_void>, io::Error> {
    let text = wide(OsStr::new(text));
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `text` is NUL-terminated; the SID is freed by `Local`.
    match unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } {
        0 => Err(last_error()),
        _ => Ok(Local(sid)),
    }
}

pub(super) struct User(Vec<u64>);

impl User {
    pub(super) fn current() -> Result<Self, io::Error> {
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: the pseudo handle of the current process needs no closing.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(last_error());
        }
        let token = Token(handle);
        let mut needed = 0_u32;
        // SAFETY: a size query with no buffer only writes `needed`.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
        let words = usize::try_from(needed).map_err(io::Error::other)? / 8 + 1;
        let mut buffer = vec![0_u64; words];
        let size = u32::try_from(words * 8).map_err(io::Error::other)?;
        // SAFETY: the buffer is 8-byte aligned and `size` bytes long.
        let filled = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut needed,
            )
        };
        match filled {
            0 => Err(last_error()),
            _ => Ok(Self(buffer)),
        }
    }

    fn sid(&self) -> PSID {
        // SAFETY: the buffer holds a TOKEN_USER filled by GetTokenInformation.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    pub(super) fn sddl(&self) -> Result<String, io::Error> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: the SID is valid; the string is freed by `Local`.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err(last_error());
        }
        let owned = Local(text);
        let mut units = Vec::new();
        // SAFETY: the string is NUL-terminated and lives until `owned` drops.
        while unsafe { *owned.0.add(units.len()) } != 0 {
            units.push(unsafe { *owned.0.add(units.len()) });
        }
        String::from_utf16(&units).map_err(io::Error::other)
    }
}

pub(super) enum Grant {
    Any,
    Write,
}

fn grants(mask: u32, grant: &Grant) -> bool {
    let write = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | Policy::GENERIC_WRITE
        | Policy::GENERIC_ALL;
    match grant {
        Grant::Any => mask != 0,
        Grant::Write => mask & write != 0,
    }
}

pub(super) fn refuse_untrusted(file: &File, grant: Grant) -> Result<(), Error> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut security: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `owner` and `dacl` point into `security`, which `Local` frees after use.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut security,
        )
    };
    if status != 0 {
        let code = i32::try_from(status).map_err(io::Error::other)?;
        return Err(io::Error::from_raw_os_error(code).into());
    }
    let security = Local(security);
    check_dacl(owner, dacl, &grant)?;
    drop(security);
    Ok(())
}

fn check_dacl(owner: PSID, dacl: *mut ACL, grant: &Grant) -> Result<(), Error> {
    let fixed = Policy::TRUSTED
        .iter()
        .map(|text| sid(text))
        .collect::<Result<Vec<_>, _>>()?;
    let user = User::current()?;
    let mut trusted: Vec<PSID> = fixed.iter().map(|sid| sid.0).collect();
    trusted.push(user.sid());
    let owner_trusted = !owner.is_null() && contains(&trusted, owner);
    match grant {
        Grant::Write if !owner.is_null() => trusted.push(owner),
        Grant::Write => {}
        Grant::Any if owner_trusted => {}
        Grant::Any => return Err(Error::PrivatePermissions),
    }
    if dacl.is_null() {
        return Err(Error::PrivatePermissions);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    let size = u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(io::Error::other)?;
    let out = ptr::from_mut(&mut info).cast();
    // SAFETY: `info` is exactly the queried class's size.
    if unsafe { GetAclInformation(dacl, out, size, AclSizeInformation) } == 0 {
        return Err(last_error().into());
    }
    for index in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = ptr::null_mut();
        // SAFETY: `index` is below the DACL's ACE count.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(last_error().into());
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        let inherit_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0;
        if inherit_only || header.AceType == Policy::ACCESS_DENIED {
            continue;
        }
        if header.AceType != Policy::ACCESS_ALLOWED {
            return Err(Error::PrivatePermissions);
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: an ACCESS_ALLOWED_ACE stores its SID at SidStart.
        let mask = unsafe { (*allowed).Mask };
        // SAFETY: as above; the SID lives as long as the descriptor holding `dacl`.
        let sid: PSID = unsafe { ptr::addr_of_mut!((*allowed).SidStart) }.cast();
        if grants(mask, grant) && !contains(&trusted, sid) {
            return Err(Error::PrivatePermissions);
        }
    }
    Ok(())
}

fn contains(trusted: &[PSID], sid: PSID) -> bool {
    // SAFETY: every SID comes from a live descriptor or allocation.
    trusted
        .iter()
        .any(|other| unsafe { EqualSid(sid, *other) } != 0)
}

#[cfg(test)]
mod tests {
    use super::{Descriptor, Grant, User, check_dacl};
    use crate::Error;
    use std::ptr;
    use windows_sys::Win32::Security::{
        ACL, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, PSID,
    };

    fn check(sddl: &str, grant: Grant) -> Result<(), Error> {
        let descriptor = Descriptor::parse(sddl).unwrap();
        let (mut owner, mut dacl): (PSID, *mut ACL) = (ptr::null_mut(), ptr::null_mut());
        let (mut defaulted, mut present) = (0, 0);
        // SAFETY: the descriptor is a live self-relative descriptor.
        unsafe {
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.0.0, &mut owner, &mut defaulted),
                0
            );
            assert_ne!(
                GetSecurityDescriptorDacl(descriptor.0.0, &mut present, &mut dacl, &mut defaulted),
                0
            );
        }
        check_dacl(owner, dacl, &grant)
    }

    #[test]
    fn a_foreign_owner_may_write_while_other_readers_stay_read_only() {
        let daemon = "S-1-5-80-1-2-3-4-5";
        let me = User::current().unwrap().sddl().unwrap();
        assert_ne!(me, daemon);
        let token = format!("O:{daemon}D:P(A;;FA;;;{daemon})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
        check(&token, Grant::Write).unwrap();
        assert!(matches!(
            check(&token, Grant::Any),
            Err(Error::PrivatePermissions)
        ));
        let stranger = format!("O:{daemon}D:P(A;;FA;;;{daemon})(A;;FW;;;S-1-5-21-9-9-9-1001)");
        assert!(matches!(
            check(&stranger, Grant::Write),
            Err(Error::PrivatePermissions)
        ));
        let owned = format!("O:{daemon}D:P(A;;FA;;;{daemon})(A;;FA;;;SY)");
        assert!(matches!(
            check(&owned, Grant::Any),
            Err(Error::PrivatePermissions)
        ));
        let planted = format!("O:{daemon}D:P(A;;FA;;;{daemon})(A;;FR;;;{me})");
        assert!(matches!(
            check(&planted, Grant::Any),
            Err(Error::PrivatePermissions)
        ));
        for owner in [me.as_str(), "SY", "BA"] {
            let mine = format!("O:{owner}D:P(A;;FA;;;{me})(A;;FA;;;SY)(A;;FA;;;BA)");
            check(&mine, Grant::Any).unwrap();
        }
        let unowned = "O:S-1-5-21-9-9-9-1001D:P(A;;FA;;;S-1-5-80-1-2-3-4-5)";
        assert!(matches!(
            check(unowned, Grant::Write),
            Err(Error::PrivatePermissions)
        ));
    }
}
