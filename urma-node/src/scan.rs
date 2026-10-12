use crate::{
    Error,
    model::{Retention, ScanTicket},
};
use bitcoin::{Transaction, Txid};
use urma_chain::{
    decode,
    inclusion::{BlockProofBuilder, TransactionProof},
    observation::Chain,
};
use urma_core::{envelope, format::RecordKind, multipart::VerifiedRecord};

pub(crate) struct Record {
    pub position: u32,
    pub wtxid: bitcoin::Wtxid,
    pub verified: VerifiedRecord,
    pub proof: TransactionProof,
    pub commit: Transaction,
    pub raw_commit: Vec<u8>,
}

pub(crate) struct Dependency {
    pub position: u32,
    pub commit: Txid,
    pub proof: TransactionProof,
}

/// Multipart components a pruned archive may omit while scanning.
pub(crate) fn prunable(record: &VerifiedRecord) -> Result<bool, Error> {
    let kind =
        RecordKind::parse(record.record_bytes()).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(matches!(
        kind,
        RecordKind::DataPart | RecordKind::LeafManifest
    ))
}

/// Produced only by checking an entire supplied block, never by a peer's
/// declaration of completeness or by a list of selective proofs.
pub(crate) struct ScanBatch {
    pub ticket: ScanTicket,
    pub locators: Vec<(Txid, bitcoin::Wtxid)>,
    pub records: Vec<Record>,
    pub dependencies: Vec<Dependency>,
}

impl ScanBatch {
    pub fn verify(
        chain: Chain,
        ticket: ScanTicket,
        raw_block: &[u8],
        retention: Retention,
        mut resolve: impl FnMut(Txid) -> Result<Option<Vec<u8>>, Error>,
    ) -> Result<Self, Error> {
        let decoded = decode::esplora_block_with_transactions(raw_block, chain, ticket.point.hash)
            .map_err(|e| Error::Invalid(format!("full block verification: {e}")))?;
        let (block, raw) = decoded.into_parts();
        let builder = BlockProofBuilder::new(&block).map_err(|e| Error::Invalid(e.to_string()))?;
        let mut records = Vec::new();
        let mut dependencies = Vec::new();
        let positions: std::collections::HashMap<_, _> = block
            .txdata
            .iter()
            .enumerate()
            .map(|(i, tx)| (tx.compute_txid(), i))
            .collect();
        for (position, reveal) in block.txdata.iter().enumerate().skip(1) {
            if reveal.input.len() != 1 || !envelope::is_candidate(&reveal.input[0].witness) {
                continue;
            }
            // Structurally invalid/unsupported records do not belong to the V0
            // index. This is not a signed-object contradiction classification.
            if envelope::extract_reveal(reveal).is_err() {
                continue;
            }
            let position = u32::try_from(position).map_err(|e| Error::Invalid(e.to_string()))?;
            let proof = builder
                .proof(position, raw[position as usize].clone(), raw[0].clone())
                .map_err(|e| Error::Invalid(e.to_string()))?;
            let commit_id = reveal.input[0].previous_output.txid;
            let commit_raw = match positions.get(&commit_id) {
                Some(index) => Some(raw[*index].clone()),
                None => resolve(commit_id)?,
            };
            let Some(raw_commit) = commit_raw else {
                dependencies.push(Dependency {
                    position,
                    commit: commit_id,
                    proof,
                });
                continue;
            };
            let commit = decode::transaction(&raw_commit, chain)
                .map_err(|e| Error::Invalid(format!("commit source: {e}")))?;
            // A wrong transaction from a source is a failed dependency lookup,
            // not evidence that the authenticated block's record is invalid.
            if commit.compute_txid() != commit_id {
                return Err(Error::Invalid(
                    "dependency source returned another TXID".into(),
                ));
            }
            let Ok(verified) = VerifiedRecord::verify(reveal.compute_txid(), reveal, &commit)
            else {
                continue;
            };
            if retention == Retention::Pruned && prunable(&verified)? {
                continue;
            }
            records.push(Record {
                position,
                wtxid: reveal.compute_wtxid(),
                verified,
                proof,
                commit,
                raw_commit,
            });
        }
        Ok(Self {
            ticket,
            locators: block
                .txdata
                .iter()
                .map(|tx| (tx.compute_txid(), tx.compute_wtxid()))
                .collect(),
            records,
            dependencies,
        })
    }
}
