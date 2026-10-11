use crate::{
    error::{NamesError, ensure_names},
    payload::Payload,
    state::{Commit, Observation},
};
use bitcoin::{OutPoint, Transaction};
use urma_core::{
    format::{PublicRecord, RecordKind},
    multipart::VerifiedRecord,
};

/// Projects an authenticated Names V0 record into an observation without I/O.
///
/// Checks that `reveal` has the verified TXID and exactly one input spending
/// the supplied commit outpoint. The payload, author and record hash come
/// exclusively from `record`; the reveal witness is not parsed again.
/// Non-ProfileRecord kinds and foreign profiles return `None`. Names records
/// are decoded strictly, and malformed records return an error.
///
/// `height`, `position` and the commit location are caller-supplied metadata,
/// not proofs of inclusion, confirmation or active-chain membership. The
/// caller must anchor the reveal and commit before admitting the observation
/// to a registry. The registry retains responsibility for the reveal window,
/// genesis, ordering and other Names V0 rules.
pub fn observation_from_verified(
    record: &VerifiedRecord,
    reveal: &Transaction,
    height: u64,
    position: u32,
    commit: Commit,
) -> Result<Option<Observation>, NamesError> {
    ensure_names!(
        reveal.compute_txid() == record.txid(),
        "reveal TXID differs from the verified record"
    );
    ensure_names!(reveal.input.len() == 1, "names reveal must have one input");
    ensure_names!(
        reveal.input[0].previous_output
            == OutPoint {
                txid: commit.txid,
                vout: commit.vout,
            },
        "names reveal does not spend the supplied commit outpoint"
    );
    let bytes = record.record_bytes();
    if RecordKind::parse(bytes)? != RecordKind::ProfileRecord {
        return Ok(None);
    }
    let public = PublicRecord::decode(bytes)?;
    let PublicRecord::ProfileRecord { profile, .. } = &public else {
        return Ok(None);
    };
    if *profile != Payload::PROFILE {
        return Ok(None);
    }
    let payload = Payload::from_record(&public)?;
    Ok(Some(Observation {
        txid: record.txid(),
        author: record.author(),
        record_sha256: record.reference().record_hash,
        payload,
        height,
        position,
        commit,
    }))
}
