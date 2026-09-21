use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use urma_profiles::git::GitProfile;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub repository_name: String,
    pub object_format: u8,
    pub head: Vec<u8>,
    pub branch: Vec<u8>,
    pub pack_length: u64,
    pub pack_sha256: [u8; 32],
    pub first_root: [u8; 32],
    pub previous_root: [u8; 32],
}

impl Descriptor {
    pub const PROFILE: [u8; 8] = GitProfile::NAMED_IDENTIFIER;
    pub const UNNAMED_PROFILE: [u8; 8] = GitProfile::UNNAMED_IDENTIFIER;
    pub const MAX_PREFIX_BYTES: u64 = 65_777;

    pub fn profile(&self) -> [u8; 8] {
        GitProfile::for_name(&self.repository_name).identifier()
    }

    pub fn require_profile(&self, profile: [u8; 8]) -> Result<(), Error> {
        if self.profile() != profile {
            return Err(Error::Invalid(
                "Git profile and descriptor revision disagree".into(),
            ));
        }
        Ok(())
    }
    pub fn object_format_name(&self) -> Result<&'static str, Error> {
        match self.object_format {
            1 => Ok("sha1"),
            2 => Ok("sha256"),
            value => Err(Error::Invalid(format!("object format {value}"))),
        }
    }

    pub fn encode(&self, output: &mut impl Write) -> Result<(), Error> {
        self.validate()?;
        output.write_all(&[
            self.object_format,
            GitProfile::for_name(&self.repository_name).revision(),
        ])?;
        output.write_all(&u16::try_from(self.branch.len())?.to_le_bytes())?;
        output.write_all(&self.pack_length.to_le_bytes())?;
        output.write_all(&self.pack_sha256)?;
        output.write_all(&self.first_root)?;
        output.write_all(&self.previous_root)?;
        output.write_all(&self.head)?;
        output.write_all(&self.branch)?;
        if !self.repository_name.is_empty() {
            output.write_all(&u16::try_from(self.repository_name.len())?.to_le_bytes())?;
            output.write_all(self.repository_name.as_bytes())?;
        }
        Ok(())
    }

    pub fn decode(input: &mut (impl Read + Seek)) -> Result<Self, Error> {
        let mut prefix = [0_u8; 108];
        input.read_exact(&mut prefix)?;
        let head_length = match prefix[0] {
            1 => 20,
            2 => 32,
            other => return Err(Error::Invalid(format!("object format {other}"))),
        };
        GitProfile::from_revision(prefix[1])?;
        let branch_length = usize::from(u16::from_le_bytes([prefix[2], prefix[3]]));
        let mut head = vec![0; head_length];
        let mut branch = vec![0; branch_length];
        input.read_exact(&mut head)?;
        input.read_exact(&mut branch)?;
        let mut pack_length = [0; 8];
        let mut pack_sha256 = [0; 32];
        let mut first_root = [0; 32];
        let mut previous_root = [0; 32];
        pack_length.copy_from_slice(&prefix[4..12]);
        pack_sha256.copy_from_slice(&prefix[12..44]);
        first_root.copy_from_slice(&prefix[44..76]);
        previous_root.copy_from_slice(&prefix[76..108]);
        let repository_name = read_name(input, prefix[1])?;
        let descriptor = Self {
            repository_name,
            object_format: prefix[0],
            head,
            branch,
            pack_length: u64::from_le_bytes(pack_length),
            pack_sha256,
            first_root,
            previous_root,
        };
        descriptor.validate()?;
        let offset = input.stream_position()?;
        let length = input.seek(SeekFrom::End(0))?;
        if descriptor
            .pack_length
            .checked_add(offset)
            .ok_or_else(|| Error::Invalid("descriptor length overflow".into()))?
            != length
        {
            return Err(Error::Invalid("descriptor length or trailing bytes".into()));
        }
        input.seek(SeekFrom::Start(offset))?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if !self.repository_name.is_empty() {
            validate_name(&self.repository_name)?;
        }
        let expected = match self.object_format {
            1 => 20,
            2 => 32,
            other => return Err(Error::Invalid(format!("object format {other}"))),
        };
        if self.head.len() != expected
            || self.branch.is_empty()
            || self.branch.len() > usize::from(u16::MAX)
            || !self.branch.starts_with(b"refs/heads/")
            || self.pack_length < 12 + u64::try_from(expected)?
            || (self.first_root == [0; 32]) != (self.previous_root == [0; 32])
        {
            return Err(Error::Invalid("descriptor fields".into()));
        }
        Ok(())
    }
}

pub fn digest(input: &mut impl Read) -> Result<[u8; 32], Error> {
    Ok(urma_io::digest(input)?)
}

fn read_name(input: &mut impl Read, revision: u8) -> Result<String, Error> {
    if revision == 0 {
        return Ok(String::new());
    }
    let mut length = [0; 2];
    input.read_exact(&mut length)?;
    let length = usize::from(u16::from_le_bytes(length));
    if length == 0 || length > 100 {
        return Err(Error::Invalid(
            "repository name length must be 1..100 bytes".into(),
        ));
    }
    let mut name = vec![0; length];
    input.read_exact(&mut name)?;
    let name = String::from_utf8(name)?;
    validate_name(&name)?;
    Ok(name)
}

pub fn validate_name(name: &str) -> Result<(), Error> {
    let first = name
        .bytes()
        .next()
        .ok_or_else(|| Error::Invalid("repository name must not be empty".into()))?;
    let valid_start = first.is_ascii_alphanumeric();
    let stem = name
        .split('.')
        .next()
        .ok_or_else(|| Error::Invalid("repository name".into()))?;
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if name.len() > 100
        || !valid_start
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        || reserved
            .iter()
            .any(|value| stem.eq_ignore_ascii_case(value))
    {
        return Err(Error::Invalid("unsafe repository name; use --name with 1..100 ASCII letters, digits, '-', '_' or '.', starting with a letter/digit; no trailing dot or reserved device names".into()));
    }
    Ok(())
}

pub fn source_name(repo: &std::path::Path) -> Result<String, Error> {
    let path = repo.canonicalize()?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::Invalid("source has no portable basename; provide --name".into()))?;
    validate_name(name)?;
    Ok(name.to_owned())
}
