use crate::{
    error::{WebError, ensure_web},
    grammar::{Wanted, is_entry_mime, validate_label, validate_mime, validate_path, wanted},
};
use bitcoin::{Txid, hashes::Hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use urma_core::error::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub mime: String,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}

impl FileEntry {
    pub fn new(path: &str, mime: &str, bytes: Vec<u8>) -> Self {
        Self {
            path: path.to_owned(),
            mime: mime.to_owned(),
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedEntry {
    pub path: String,
    pub mime: String,
    pub root_txid: Txid,
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub label: String,
    pub entry: u16,
    pub files: Vec<FileEntry>,
    pub pinned: Vec<PinnedEntry>,
}

pub enum Resource<'a> {
    File(&'a FileEntry),
    Pinned(&'a PinnedEntry),
    Undeclared,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], WebError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| WebError::Invalid("package offset overflow".into()))?;
        ensure_web!(end <= self.bytes.len(), "truncated package");
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WebError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WebError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }

    fn u64(&mut self) -> Result<u64, WebError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn text(&mut self, length: usize) -> Result<String, WebError> {
        Ok(std::str::from_utf8(self.take(length)?)?.to_owned())
    }

    fn array(&mut self) -> Result<[u8; 32], WebError> {
        Ok(self.take(32)?.try_into()?)
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

impl From<std::str::Utf8Error> for WebError {
    fn from(cause: std::str::Utf8Error) -> Self {
        Self::Protocol(Error::Utf8(cause))
    }
}

impl From<std::array::TryFromSliceError> for WebError {
    fn from(cause: std::array::TryFromSliceError) -> Self {
        Self::Protocol(Error::Slice(cause))
    }
}

fn push_text(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(text.as_bytes());
}

impl Package {
    pub const PROFILE: [u8; 8] = *b"URMAWEB1";
    pub const REVISION: u8 = 2;
    pub const HEADER_BYTES: usize = 9;

    pub fn build(
        label: &str,
        entry: &str,
        mut files: Vec<FileEntry>,
        mut pinned: Vec<PinnedEntry>,
    ) -> Result<Self, WebError> {
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        pinned.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        for file in &mut files {
            file.sha256 = Sha256::digest(&file.bytes).into();
        }
        let Some(index) = files.iter().position(|file| file.path == entry) else {
            return Err(WebError::Missing(format!(
                "entry {entry:?} is not a packaged file"
            )));
        };
        let package = Self {
            label: label.to_owned(),
            entry: u16::try_from(index)?,
            files,
            pinned,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<(), WebError> {
        validate_label(&self.label)?;
        ensure_web!(
            !self.files.is_empty() && self.files.len() <= usize::from(u16::MAX),
            "package must declare 1..65535 files"
        );
        ensure_web!(
            self.pinned.len() <= usize::from(u16::MAX),
            "package declares too many pinned objects"
        );
        let Some(entry) = self.files.get(usize::from(self.entry)) else {
            return Err(WebError::Invalid(
                "entry index outside the files table".into(),
            ));
        };
        ensure_web!(
            is_entry_mime(&entry.mime),
            "entry document must be text/html: {:?}",
            entry.mime
        );
        let mut paths = BTreeSet::new();
        for file in &self.files {
            validate_path(&file.path)?;
            validate_mime(&file.mime)?;
            ensure_web!(
                <[u8; 32]>::from(Sha256::digest(&file.bytes)) == file.sha256,
                "file hash mismatch: {:?}",
                file.path
            );
            ensure_web!(
                paths.insert(file.path.as_bytes()),
                "duplicate path: {:?}",
                file.path
            );
        }
        for pin in &self.pinned {
            validate_path(&pin.path)?;
            validate_mime(&pin.mime)?;
            ensure_web!(
                paths.insert(pin.path.as_bytes()),
                "duplicate path: {:?}",
                pin.path
            );
        }
        ensure_web!(
            self.files
                .windows(2)
                .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes()),
            "files must be sorted by path bytes"
        );
        ensure_web!(
            self.pinned
                .windows(2)
                .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes()),
            "pinned objects must be sorted by path bytes"
        );
        Ok(())
    }

    pub fn entry(&self) -> Result<&FileEntry, WebError> {
        self.files
            .get(usize::from(self.entry))
            .ok_or_else(|| WebError::Invalid("entry index outside the files table".into()))
    }

    pub fn encode(&self) -> Result<Vec<u8>, WebError> {
        self.validate()?;
        let mut bytes = vec![Self::REVISION, 0];
        bytes.extend_from_slice(&u16::try_from(self.files.len())?.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(self.pinned.len())?.to_le_bytes());
        bytes.extend_from_slice(&self.entry.to_le_bytes());
        bytes.push(u8::try_from(self.label.len())?);
        push_text(&mut bytes, &self.label);
        for file in &self.files {
            bytes.extend_from_slice(&u16::try_from(file.path.len())?.to_le_bytes());
            push_text(&mut bytes, &file.path);
            bytes.push(u8::try_from(file.mime.len())?);
            push_text(&mut bytes, &file.mime);
            bytes.extend_from_slice(&u64::try_from(file.bytes.len())?.to_le_bytes());
            bytes.extend_from_slice(&file.sha256);
        }
        for pin in &self.pinned {
            bytes.extend_from_slice(&u16::try_from(pin.path.len())?.to_le_bytes());
            push_text(&mut bytes, &pin.path);
            bytes.push(u8::try_from(pin.mime.len())?);
            push_text(&mut bytes, &pin.mime);
            bytes.extend_from_slice(pin.root_txid.as_byte_array());
            bytes.extend_from_slice(&pin.payload_sha256);
        }
        for file in &self.files {
            bytes.extend_from_slice(&file.bytes);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WebError> {
        let mut cursor = Cursor { bytes, offset: 0 };
        let revision = cursor.u8()?;
        if revision != Self::REVISION {
            return Err(WebError::Protocol(Error::Unsupported(format!(
                "unsupported web package revision {revision}"
            ))));
        }
        ensure_web!(cursor.u8()? == 0, "reserved package flags");
        let file_count = cursor.u16()?;
        let pinned_count = cursor.u16()?;
        let entry = cursor.u16()?;
        let label_length = cursor.u8()?;
        let label = cursor.text(usize::from(label_length))?;
        let mut directory = Vec::new();
        for _index in 0..file_count {
            let path_length = cursor.u16()?;
            let path = cursor.text(usize::from(path_length))?;
            let mime_length = cursor.u8()?;
            let mime = cursor.text(usize::from(mime_length))?;
            let length = cursor.u64()?;
            let sha256 = cursor.array()?;
            directory.push((path, mime, length, sha256));
        }
        let mut pinned = Vec::new();
        for _index in 0..pinned_count {
            let path_length = cursor.u16()?;
            let path = cursor.text(usize::from(path_length))?;
            let mime_length = cursor.u8()?;
            let mime = cursor.text(usize::from(mime_length))?;
            let root_txid = Txid::from_byte_array(cursor.array()?);
            let payload_sha256 = cursor.array()?;
            pinned.push(PinnedEntry {
                path,
                mime,
                root_txid,
                payload_sha256,
            });
        }
        let mut files = Vec::new();
        for (path, mime, length, sha256) in directory {
            let data = cursor.take(usize::try_from(length)?)?.to_vec();
            files.push(FileEntry {
                path,
                mime,
                sha256,
                bytes: data,
            });
        }
        ensure_web!(cursor.finished(), "trailing package bytes");
        let package = Self {
            label,
            entry,
            files,
            pinned,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn resolve(&self, url_path: &str) -> Resource<'_> {
        let path = match wanted(url_path) {
            Wanted::Entry => {
                let Some(entry) = self.files.get(usize::from(self.entry)) else {
                    return Resource::Undeclared;
                };
                return Resource::File(entry);
            }
            Wanted::Path(path) => path,
            Wanted::Unresolvable => return Resource::Undeclared,
        };
        for file in &self.files {
            if file.path == path {
                return Resource::File(file);
            }
        }
        for pin in &self.pinned {
            if pin.path == path {
                return Resource::Pinned(pin);
            }
        }
        Resource::Undeclared
    }
}
