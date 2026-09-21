use bitcoin::{Transaction, consensus::deserialize};
use urma_core::{envelope, error::Error, format::PublicRecord};
use urma_identity::keys::AuthorIdentity;

pub struct VerifiedWireRecord {
    author: AuthorIdentity,
    record: PublicRecord,
    raw_record: Vec<u8>,
}

pub fn verify(reveal: &Transaction, commit: &Transaction) -> Result<VerifiedWireRecord, Error> {
    let proof = envelope::verify_reveal(reveal, commit)?;
    Ok(VerifiedWireRecord {
        author: AuthorIdentity(proof.author),
        record: PublicRecord::decode(&proof.record)?,
        raw_record: proof.record,
    })
}

pub fn verify_bytes(commit: &[u8], reveal: &[u8]) -> Result<VerifiedWireRecord, Error> {
    verify(&deserialize(reveal)?, &deserialize(commit)?)
}

impl VerifiedWireRecord {
    pub fn raw_record(&self) -> &[u8] {
        &self.raw_record
    }

    pub fn author(&self) -> AuthorIdentity {
        self.author
    }
    pub fn record(&self) -> &PublicRecord {
        &self.record
    }
}
