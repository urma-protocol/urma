use crate::multipart;
use crate::node::{Node, Presence};
use crate::storage;
use crate::{
    error::{Context, Error, ensure},
    multipart::{
        Candidate, FetchError, MultipartSource, RecordRequest, RecoveredObject, RecoveryError,
        RecoveryLimits, VerifiedRecord,
    },
};
use bitcoin::{Transaction, Txid, consensus::serialize};
use std::{collections::BTreeMap, fs::File, io::Write, path::Path};
use urma_core::error::Error as ProtocolError;

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
                retain_transaction(directory, &path, &bytes)
            }
        }
    }
}

fn retain_transaction(directory: &Path, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tx_directory = directory.join("tx");
    let mut temporary = tempfile::NamedTempFile::new_in(&tx_directory)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::warn!(error = %error.error, "concurrent proof retention; checking existing transaction");
            ensure!(
                std::fs::symlink_metadata(path)?.is_file(),
                "proof transaction must be a regular file"
            );
            ensure!(
                storage::read_bounded(path, 4 * 1024 * 1024)? == bytes,
                "retained transaction bytes disagree"
            );
        }
        Err(error) => return Err(Error::Io(error.error)),
    }
    File::open(tx_directory)?.sync_all()?;
    Ok(())
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

fn candidate(
    node: &Node,
    txid: Txid,
    rejected: &[String],
    retention: Retention<'_>,
) -> Result<Candidate, FetchError> {
    match node.presence(txid).map_err(FetchError::Source)? {
        Presence::Confirmed { .. } => (),
        Presence::Missing | Presence::Mempool => return Err(FetchError::Unavailable),
    }
    let (reveal, origin) = match node.transaction_avoiding(txid, rejected) {
        Ok(served) => served,
        Err(Error::Missing(message)) => {
            tracing::warn!(%txid, %message, "no remaining provider serves the record");
            return Err(FetchError::Unavailable);
        }
        Err(cause) => return Err(FetchError::Source(cause)),
    };
    let Some(input) = reveal.input.first() else {
        return Err(FetchError::Rejected {
            origin,
            cause: ProtocolError::Invalid("reveal without input".into()),
        });
    };
    let commit = node
        .transaction(input.previous_output.txid)
        .map_err(FetchError::Source)?;
    let record = match VerifiedRecord::verify(txid, &reveal, &commit) {
        Ok(record) => record,
        Err(cause) => return Err(FetchError::Rejected { origin, cause }),
    };
    retention.store(&reveal).map_err(FetchError::Source)?;
    retention.store(&commit).map_err(FetchError::Source)?;
    Ok(Candidate { origin, record })
}

struct Source<'a> {
    node: &'a Node,
    retention: Retention<'a>,
    pending: BTreeMap<Txid, Result<Candidate, FetchError>>,
}

impl MultipartSource for Source<'_> {
    fn fetch(
        &mut self,
        request: &RecordRequest,
        rejected: &[String],
    ) -> Result<Candidate, FetchError> {
        let txid = request.reference.txid;
        if !rejected.is_empty() {
            return candidate(self.node, txid, rejected, self.retention);
        }
        let Some(prefetched) = self.pending.remove(&txid) else {
            return candidate(self.node, txid, rejected, self.retention);
        };
        prefetched
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
                        scope.spawn(move || candidate(node, txid, &[], retention)),
                    )
                })
                .collect();
            for (txid, worker) in workers {
                let result = match worker.join() {
                    Ok(result) => result,
                    Err(payload) => {
                        tracing::warn!(payload_type = ?payload.type_id(), "multipart fetch worker panicked");
                        Err(FetchError::Source(Error::Io(std::io::Error::other(
                            "multipart fetch worker panicked",
                        ))))
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
        multipart::reconstruct(&verified, source, limits, scratch).map_err(
            |cause| match cause {
                RecoveryError::InvalidObject(error)
                | RecoveryError::InvalidCandidate { cause: error, .. } => Error::Protocol(error),
                RecoveryError::Source { cause, .. } => cause,
                RecoveryError::Storage(cause) => Error::Io(cause),
                RecoveryError::Incomplete { txid } => Error::Missing(format!(
                    "record {txid} has no confirmed inclusion on {:?}; check the TXID, wait for confirmation or use --testnet for Litecoin test data",
                    source.node.chain()
                )),
                RecoveryError::Capacity(message) => Error::Capacity(message),
            },
        )?;
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
    urma_io::create_private_directory(&proof_directory.join("tx"))?;
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
