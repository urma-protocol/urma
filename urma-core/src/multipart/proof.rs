use super::{ChildReference, MultipartRecord};
use crate::{
    envelope,
    error::{Error, ensure},
};
use bitcoin::{Transaction, Txid, XOnlyPublicKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct VerifiedRecord {
    txid: Txid,
    author: XOnlyPublicKey,
    record_hash: [u8; 32],
    record: Vec<u8>,
}

impl VerifiedRecord {
    pub fn verify(
        expected: Txid,
        reveal: &Transaction,
        commit: &Transaction,
    ) -> Result<Self, Error> {
        ensure!(reveal.compute_txid() == expected, "candidate TXID mismatch");
        let proof = envelope::verify_record_proof(reveal, commit)?;
        Ok(Self {
            txid: expected,
            author: proof.author,
            record_hash: Sha256::digest(&proof.record).into(),
            record: proof.record,
        })
    }

    pub fn txid(&self) -> Txid {
        self.txid
    }
    pub fn author(&self) -> XOnlyPublicKey {
        self.author
    }
    pub fn record_bytes(&self) -> &[u8] {
        &self.record
    }
    pub fn decode(&self) -> Result<MultipartRecord, Error> {
        MultipartRecord::decode(&self.record)
    }
    pub fn reference(&self) -> ChildReference {
        ChildReference {
            txid: self.txid,
            record_hash: self.record_hash,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RecordRequest {
    pub reference: ChildReference,
}

impl RecordRequest {
    pub fn verify(
        &self,
        reveal: &Transaction,
        commit: &Transaction,
    ) -> Result<VerifiedRecord, Error> {
        let verified = VerifiedRecord::verify(self.reference.txid, reveal, commit)?;
        self.check(&verified)?;
        Ok(verified)
    }

    pub fn check(&self, verified: &VerifiedRecord) -> Result<(), Error> {
        ensure!(
            verified.reference() == self.reference,
            "candidate TXID or record hash mismatch"
        );
        Ok(())
    }
}
