use crate::error::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub object_format: u8,
    pub head: Vec<u8>,
    pub branch: Vec<u8>,
    pub pack_length: u64,
    pub pack_sha256: [u8; 32],
    pub first_root: [u8; 32],
    pub previous_root: [u8; 32],
}

impl Descriptor {
    pub const PROFILE: [u8; 8] = *b"URMAGIT0";
    pub fn object_format_name(&self) -> Result<&'static str, Error> {
        match self.object_format {
            1 => Ok("sha1"),
            2 => Ok("sha256"),
            value => Err(Error::Invalid(format!("object format {value}"))),
        }
    }

    pub fn encode(&self, output: &mut impl Write) -> Result<(), Error> {
        self.validate()?;
        output.write_all(&[self.object_format, 0])?;
        output.write_all(&u16::try_from(self.branch.len())?.to_le_bytes())?;
        output.write_all(&self.pack_length.to_le_bytes())?;
        output.write_all(&self.pack_sha256)?;
        output.write_all(&self.first_root)?;
        output.write_all(&self.previous_root)?;
        output.write_all(&self.head)?;
        output.write_all(&self.branch)?;
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
        if prefix[1] != 0 {
            return Err(Error::Invalid("descriptor flags".into()));
        }
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
        let descriptor = Self {
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
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let length = input.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    Ok(hash.finalize().into())
}
