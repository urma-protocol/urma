use crate::node::{Node, Presence};
use bitcoin::{Transaction, Txid, consensus::serialize};
use std::{collections::BTreeMap, os::unix::fs::DirBuilderExt, path::Path};
use urma::{
    error::{Context, Error, ensure},
    multipart::{
        FetchError, MultipartSource, RecordRequest, RecoveredObject, RecoveryError, RecoveryLimits,
        VerifiedRecord,
    },
};

#[derive(Clone, Copy)]
enum Retention<'a> {
    Discard,
    Directory(&'a Path),
}

impl Retention<'_> {
    fn store(self, transaction: &Transaction) -> Result<(), Error> {
        match self {
            Self::Discard => Ok(()),
            Self::Directory(directory) => {
                let path = directory
                    .join("tx")
                    .join(format!("{}.bin", transaction.compute_txid()));
                let bytes = serialize(transaction);
                if path.try_exists()? {
                    ensure!(
                        std::fs::symlink_metadata(&path)?.is_file(),
                        "proof transaction must be a regular file"
                    );
                    ensure!(
                        urma::storage::read_bounded(&path, 4 * 1024 * 1024)? == bytes,
                        "retained transaction bytes disagree"
                    );
                    return Ok(());
                }
                urma::storage::write_new(&path, &bytes)
            }
        }
    }
}

pub fn verified_record(node: &Node, txid: Txid) -> Result<VerifiedRecord, Error> {
    retained_record(node, txid, Retention::Discard)
}

fn retained_record(
    node: &Node,
    txid: Txid,
    retention: Retention<'_>,
) -> Result<VerifiedRecord, Error> {
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
    let record = VerifiedRecord::verify(txid, &reveal, &commit)?;
    retention.store(&reveal)?;
    retention.store(&commit)?;
    Ok(record)
}

struct Source<'a> {
    node: &'a Node,
    retention: Retention<'a>,
    pending: BTreeMap<Txid, Result<VerifiedRecord, Error>>,
}

fn fetch_error(cause: Error) -> FetchError {
    match cause {
        Error::Protocol(cause) => FetchError::Rejected(cause),
        cause => FetchError::Source(cause),
    }
}

impl MultipartSource for Source<'_> {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        let result = match self.pending.remove(&request.reference.txid) {
            Some(result) => result,
            None => {
                return retained_record(self.node, request.reference.txid, self.retention)
                    .map_err(fetch_error);
            }
        };
        result.map_err(fetch_error)
    }

    fn prefetch(&mut self, requests: &[RecordRequest]) {
        self.pending.clear();
        let node = self.node;
        let retention = self.retention;
        std::thread::scope(|scope| {
            let workers: Vec<_> = requests
                .iter()
                .take(8)
                .map(|request| {
                    let txid = request.reference.txid;
                    (
                        txid,
                        scope.spawn(move || retained_record(node, txid, retention)),
                    )
                })
                .collect();
            for (txid, worker) in workers {
                let result = match worker.join() {
                    Ok(result) => result,
                    Err(payload) => {
                        panic!("multipart fetch worker panicked ({:?})", payload.type_id())
                    }
                };
                self.pending.insert(txid, result);
            }
        });
    }
}

fn recover_from(
    source: &mut Source<'_>,
    root: Txid,
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    source.node.verify_network()?;
    source.node.require_txindex()?;
    let tip = source.node.tip()?;
    let verified = retained_record(source.node, root, source.retention)?;
    let result =
        urma::multipart::reconstruct(&verified, source, limits, scratch).map_err(|cause| {
            match cause {
                RecoveryError::InvalidObject(error)
                | RecoveryError::InvalidCandidate { cause: error, .. } => Error::Protocol(error),
                RecoveryError::Source { cause, .. } => cause,
                RecoveryError::Storage(cause) => Error::Io(cause),
                RecoveryError::Incomplete { txid } => {
                    Error::Missing(format!("multipart record unavailable: {txid}"))
                }
                RecoveryError::Capacity(message) => Error::Capacity(message),
            }
        })?;
    ensure!(
        source.node.block_hash(tip.0)?.to_string() == tip.1,
        "chain changed during reconstruction; retry recovery"
    );
    Ok(result)
}

pub fn recover(
    node: &Node,
    root: Txid,
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    recover_from(
        &mut Source {
            node,
            retention: Retention::Discard,
            pending: BTreeMap::new(),
        },
        root,
        limits,
        scratch,
    )
}

pub fn recover_retained(
    node: &Node,
    root: Txid,
    limits: RecoveryLimits,
    scratch: &Path,
    proof_directory: &Path,
) -> Result<RecoveredObject, Error> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(proof_directory.join("tx"))?;
    recover_from(
        &mut Source {
            node,
            retention: Retention::Directory(proof_directory),
            pending: BTreeMap::new(),
        },
        root,
        limits,
        scratch,
    )
}
