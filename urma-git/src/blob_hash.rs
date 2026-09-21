use crate::error::Error;
use bitcoin::hashes::{Hash, HashEngine, sha1, sha256};

pub(crate) enum BlobHash {
    Sha1(sha1::HashEngine),
    Sha256(sha256::HashEngine),
}

impl BlobHash {
    pub(crate) fn new(oid: &str, size: u64) -> Result<Self, Error> {
        let mut hash = match oid.len() {
            40 => Self::Sha1(sha1::Hash::engine()),
            64 => Self::Sha256(sha256::Hash::engine()),
            _ => return Err(Error::Invalid("unsupported Git object hash".into())),
        };
        hash.input(format!("blob {size}\0").as_bytes());
        Ok(hash)
    }

    pub(crate) fn input(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(engine) => engine.input(bytes),
            Self::Sha256(engine) => engine.input(bytes),
        }
    }

    pub(crate) fn verify(self, oid: &str) -> Result<(), Error> {
        let actual = match self {
            Self::Sha1(engine) => sha1::Hash::from_engine(engine).to_string(),
            Self::Sha256(engine) => sha256::Hash::from_engine(engine).to_string(),
        };
        if actual != oid {
            return Err(Error::Invalid("streamed blob OID mismatch".into()));
        }
        Ok(())
    }
}
