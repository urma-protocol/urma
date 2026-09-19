use bitcoin::Transaction;
use urma_core::{envelope, error::Error, format::PublicRecord};
use urma_identity::keys::AuthorIdentity;

pub struct VerifiedWireRecord {
    author: AuthorIdentity,
    record: PublicRecord,
}

pub fn verify(reveal: &Transaction, commit: &Transaction) -> Result<VerifiedWireRecord, Error> {
    let proof = envelope::verify_reveal(reveal, commit)?;
    Ok(VerifiedWireRecord {
        author: AuthorIdentity(proof.author),
        record: PublicRecord::decode(&proof.record)?,
    })
}

impl VerifiedWireRecord {
    pub fn author(&self) -> AuthorIdentity {
        self.author
    }
    pub fn record(&self) -> &PublicRecord {
        &self.record
    }
}
