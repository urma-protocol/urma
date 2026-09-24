use crate::{
    error::{WebError, ensure_web},
    package::{Package, Resource},
};
use bitcoin::{
    Transaction, Txid,
    consensus::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use urma_core::multipart::{MultipartRecord, VerifiedRecord};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pointer {
    pub format: String,
    pub network: String,
    pub root: String,
    pub commit: String,
    pub tip_height: u64,
    pub tip_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFile {
    pub path: String,
    pub mime: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPin {
    pub path: String,
    pub mime: String,
    pub root_txid: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPublication {
    pub format: String,
    pub network: String,
    pub root: String,
    pub commit: String,
    pub author: String,
    pub label: String,
    pub entry: String,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub files: Vec<StoredFile>,
    pub pinned: Vec<StoredPin>,
    pub tip_height: u64,
    pub tip_hash: String,
}

pub struct Verified {
    pub pointer: Pointer,
    pub author: String,
    pub payload_sha256: String,
    pub package: Package,
    pub pinned_lengths: Vec<u64>,
}

pub enum Served {
    Resource {
        mime: String,
        sha256: String,
        bytes: Vec<u8>,
    },
    Undeclared,
}

pub struct Store {
    root: PathBuf,
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn check_component(text: &str) -> Result<(), WebError> {
    ensure_web!(
        !text.is_empty()
            && text.len() <= 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "store key must be alphanumeric or hyphen: {text:?}"
    );
    Ok(())
}

impl Store {
    pub const FORMAT: &'static str = "URMA-WEB-STORE-2";
    pub const MAX_POINTER_BYTES: usize = 64 * 1024;
    pub const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
    pub const MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;

    pub fn open(root: &Path) -> Result<Self, WebError> {
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("publications"))?;
        fs::create_dir_all(root.join("tx"))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, sha256: &str) -> Result<PathBuf, WebError> {
        ensure_web!(is_hex64(sha256), "store object key must be 64 hex digits");
        Ok(self.root.join("objects").join(sha256))
    }

    pub fn put_object(&self, bytes: &[u8]) -> Result<String, WebError> {
        let sha256 = hex::encode(Sha256::digest(bytes));
        let path = self.object_path(&sha256)?;
        if path.try_exists()? {
            let same_length = fs::metadata(&path)?.len() == u64::try_from(bytes.len())?;
            if same_length && urma_io::read_bounded(&path, bytes.len())? == bytes {
                return Ok(sha256);
            }
        }
        urma_io::write_replace(&path, bytes)?;
        Ok(sha256)
    }

    pub fn object(&self, sha256: &str, limit: usize) -> Result<Vec<u8>, WebError> {
        let bytes = urma_io::read_bounded(&self.object_path(sha256)?, limit)?;
        ensure_web!(
            hex::encode(Sha256::digest(&bytes)) == sha256.to_ascii_lowercase(),
            "store object {sha256} failed re-verification"
        );
        Ok(bytes)
    }

    pub fn has_object(&self, sha256: &str) -> Result<bool, WebError> {
        Ok(self.object_path(sha256)?.try_exists()?)
    }

    fn transaction_path(&self, txid: &str) -> Result<PathBuf, WebError> {
        ensure_web!(
            is_hex64(txid),
            "store transaction key must be a 64 hex digit TXID"
        );
        Ok(self.root.join("tx").join(format!("{txid}.bin")))
    }

    pub fn put_transaction(&self, transaction: &Transaction) -> Result<String, WebError> {
        let txid = transaction.compute_txid().to_string();
        let bytes = serialize(transaction);
        let path = self.transaction_path(&txid)?;
        if path.try_exists()? {
            let existing = urma_io::read_bounded(&path, Self::MAX_TRANSACTION_BYTES)?;
            ensure_web!(
                existing == bytes,
                "stored transaction {txid} disagrees with new bytes"
            );
            return Ok(txid);
        }
        urma_io::write_new(&path, &bytes)?;
        Ok(txid)
    }

    pub fn transaction(&self, txid: &str) -> Result<Transaction, WebError> {
        let bytes =
            urma_io::read_bounded(&self.transaction_path(txid)?, Self::MAX_TRANSACTION_BYTES)?;
        let transaction: Transaction = deserialize(&bytes)?;
        ensure_web!(
            transaction.compute_txid().to_string() == txid,
            "stored transaction {txid} failed re-verification"
        );
        Ok(transaction)
    }

    fn pointer_path(&self, network: &str, root: &str) -> Result<PathBuf, WebError> {
        check_component(network)?;
        ensure_web!(
            is_hex64(root),
            "publication root must be a 64 hex digit TXID"
        );
        Ok(self
            .root
            .join("publications")
            .join(network)
            .join(format!("{root}.json")))
    }

    pub fn put_pointer(&self, pointer: &Pointer) -> Result<(), WebError> {
        ensure_web!(pointer.format == Self::FORMAT, "unsupported store format");
        ensure_web!(is_hex64(&pointer.commit), "pointer commit must be a TXID");
        let path = self.pointer_path(&pointer.network, &pointer.root)?;
        let Some(parent) = path.parent() else {
            return Err(WebError::Invalid("pointer path without parent".into()));
        };
        fs::create_dir_all(parent)?;
        urma_io::write_replace(&path, &serde_json::to_vec_pretty(pointer)?)?;
        Ok(())
    }

    pub fn pointer(&self, network: &str, root: &str) -> Result<Pointer, WebError> {
        let path = self.pointer_path(network, root)?;
        let pointer: Pointer =
            serde_json::from_slice(&urma_io::read_bounded(&path, Self::MAX_POINTER_BYTES)?)?;
        ensure_web!(pointer.format == Self::FORMAT, "unsupported store format");
        ensure_web!(
            pointer.network == network && pointer.root == root,
            "stored pointer names another network or root"
        );
        Ok(pointer)
    }

    pub fn publication(
        &self,
        network: &str,
        root: &str,
        max_payload_bytes: usize,
    ) -> Result<Verified, WebError> {
        let pointer = self.pointer(network, root)?;
        let reveal = self.transaction(root)?;
        ensure_web!(reveal.input.len() == 1, "root reveal must spend one commit");
        let commit_txid = reveal.input[0].previous_output.txid.to_string();
        ensure_web!(
            commit_txid == pointer.commit,
            "pointer commit differs from the reveal's commit"
        );
        let commit = self.transaction(&commit_txid)?;
        let verified = VerifiedRecord::verify(root.parse::<Txid>()?, &reveal, &commit)?;
        let MultipartRecord::Root(manifest) = verified.decode()? else {
            return Err(WebError::Invalid(format!("{root} is not a root manifest")));
        };
        ensure_web!(
            manifest.profile == Package::PROFILE,
            "{root} is not an URMAWEB1 publication"
        );
        let payload_sha256 = hex::encode(manifest.payload_hash);
        let payload = self.object(&payload_sha256, max_payload_bytes)?;
        ensure_web!(
            u64::try_from(payload.len())? == manifest.length,
            "package length differs from the root manifest"
        );
        let package = Package::decode(&payload)?;
        let pinned_lengths = self.verify_pins(&package)?;
        Ok(Verified {
            pointer,
            author: verified.author().to_string(),
            payload_sha256,
            package,
            pinned_lengths,
        })
    }

    fn verify_pins(&self, package: &Package) -> Result<Vec<u64>, WebError> {
        let mut lengths = Vec::with_capacity(package.pinned.len());
        for pin in &package.pinned {
            let sha256 = hex::encode(pin.payload_sha256);
            ensure_web!(
                self.has_object(&sha256)?,
                "declared set incomplete in the store: pinned object {} ({}) is missing; fetch the publication again",
                pin.path,
                pin.root_txid
            );
            let bytes = self
                .object(&sha256, Self::MAX_OBJECT_BYTES)
                .map_err(|error| {
                    WebError::Invalid(format!(
                        "declared set corrupt in the store: pinned object {} ({}) failed re-verification ({error}); fetch the publication again",
                        pin.path, pin.root_txid
                    ))
                })?;
            lengths.push(u64::try_from(bytes.len())?);
        }
        Ok(lengths)
    }

    pub fn summary(&self, verified: &Verified) -> Result<StoredPublication, WebError> {
        let mut files = Vec::new();
        for file in &verified.package.files {
            files.push(StoredFile {
                path: file.path.clone(),
                mime: file.mime.clone(),
                sha256: hex::encode(file.sha256),
                length: u64::try_from(file.bytes.len())?,
            });
        }
        let mut pinned = Vec::new();
        for (pin, length) in verified.package.pinned.iter().zip(&verified.pinned_lengths) {
            pinned.push(StoredPin {
                path: pin.path.clone(),
                mime: pin.mime.clone(),
                root_txid: pin.root_txid.to_string(),
                sha256: hex::encode(pin.payload_sha256),
                length: *length,
            });
        }
        let mut payload_length = 0u64;
        for file in &verified.package.files {
            payload_length = payload_length
                .checked_add(u64::try_from(file.bytes.len())?)
                .ok_or_else(|| WebError::Invalid("payload length overflow".into()))?;
        }
        Ok(StoredPublication {
            format: Self::FORMAT.into(),
            network: verified.pointer.network.clone(),
            root: verified.pointer.root.clone(),
            commit: verified.pointer.commit.clone(),
            author: verified.author.clone(),
            label: verified.package.label.clone(),
            entry: verified.package.entry()?.path.clone(),
            payload_sha256: verified.payload_sha256.clone(),
            payload_length: u64::try_from(verified.package.encode()?.len())?,
            files,
            pinned,
            tip_height: verified.pointer.tip_height,
            tip_hash: verified.pointer.tip_hash.clone(),
        })
    }

    pub fn serve(&self, verified: &Verified, url_path: &str) -> Result<Served, WebError> {
        match verified.package.resolve(url_path) {
            Resource::File(file) => Ok(Served::Resource {
                mime: file.mime.clone(),
                sha256: hex::encode(file.sha256),
                bytes: file.bytes.clone(),
            }),
            Resource::Pinned(pin) => {
                let sha256 = hex::encode(pin.payload_sha256);
                let bytes = self.object(&sha256, Self::MAX_OBJECT_BYTES)?;
                Ok(Served::Resource {
                    mime: pin.mime.clone(),
                    sha256,
                    bytes,
                })
            }
            Resource::Undeclared => Ok(Served::Undeclared),
        }
    }
}
