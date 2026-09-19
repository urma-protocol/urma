use crate::node::{Node, Presence};
use bitcoin::Txid;
use std::path::Path;
use urma::{
    error::{Context, Error, ensure},
    multipart::{
        FetchError, MultipartSource, RecordRequest, RecoveredObject, RecoveryError, RecoveryLimits,
        VerifiedRecord,
    },
};

pub fn verified_record(node: &Node, txid: Txid) -> Result<VerifiedRecord, Error> {
    ensure!(
        matches!(node.presence(txid)?, Presence::Confirmed { .. }),
        "record {txid} has no confirmed inclusion on {:?}; check the TXID, wait for confirmation or use --testnet for Litecoin test data",
        node.chain()
    );
    let reveal = node.transaction(txid)?;
    let parent = reveal
        .input
        .first()
        .context("reveal missing input")?
        .previous_output
        .txid;
    let commit = node.transaction(parent)?;
    Ok(VerifiedRecord::verify(txid, &reveal, &commit)?)
}

struct Source<'a> {
    node: &'a Node,
}

impl MultipartSource for Source<'_> {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        match verified_record(self.node, request.reference.txid) {
            Ok(record) => Ok(record),
            Err(Error::Protocol(cause)) => Err(FetchError::Rejected(cause)),
            Err(cause) => Err(FetchError::Source(cause)),
        }
    }
}

pub fn recover(
    node: &Node,
    root: Txid,
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    node.verify_network()?;
    node.require_txindex()?;
    let tip = node.tip()?;
    let verified = verified_record(node, root)?;
    let result = urma::multipart::reconstruct(&verified, &mut Source { node }, limits, scratch)
        .map_err(|cause| match cause {
            RecoveryError::InvalidObject(error)
            | RecoveryError::InvalidCandidate { cause: error, .. } => Error::Protocol(error),
            RecoveryError::Source { cause, .. } => cause,
            RecoveryError::Storage(cause) => Error::Io(cause),
            RecoveryError::Incomplete { txid } => {
                Error::Missing(format!("multipart record unavailable: {txid}"))
            }
            RecoveryError::Capacity(message) => Error::Capacity(message),
        })?;
    ensure!(
        node.block_hash(tip.0)?.to_string() == tip.1,
        "chain changed during reconstruction; retry recovery"
    );
    Ok(result)
}
