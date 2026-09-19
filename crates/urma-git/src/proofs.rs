use crate::{descriptor::Descriptor, error::Error, snapshot};
use bitcoin::{
    Transaction, Txid,
    consensus::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use urma::{
    error::Context,
    multipart::{
        FetchError, MultipartRecord, MultipartSource, RecordRequest, RecoveredObject,
        RecoveryLimits, VerifiedRecord,
    },
};
use urma_chain::observation::Chain;
use urma_runtime::{node::Node, recovery};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub schema: u8,
    pub chain: Chain,
    pub genesis: String,
    pub root: Txid,
}

pub fn export(
    node: &Node,
    recovered: &RecoveredObject,
    directory: &Path,
) -> Result<Locator, Error> {
    let mut records = BTreeSet::from([recovered.root()]);
    for entry in &recovered.manifest().entries {
        records.insert(entry.txid);
        let record = recovery::verified_record(node, entry.txid)?;
        let MultipartRecord::Leaf(leaf) = record.decode()? else {
            return Err(Error::Invalid("proof export leaf kind".into()));
        };
        for part in leaf.entries {
            records.insert(part.txid);
        }
    }
    let tx_dir = directory.join("tx");
    snapshot::create_private_directory(&tx_dir)?;
    let mut exported = BTreeSet::new();
    for txid in records {
        let reveal = node.transaction(txid)?;
        let parent = reveal
            .input
            .first()
            .context("reveal input")?
            .previous_output
            .txid;
        for transaction in [reveal, node.transaction(parent)?] {
            let id = transaction.compute_txid();
            if exported.insert(id) {
                urma::storage::write_new(
                    &tx_dir.join(format!("{id}.bin")),
                    &serialize(&transaction),
                )?;
            }
        }
    }
    let locator = Locator {
        schema: 1,
        chain: node.chain(),
        genesis: node
            .chain()
            .genesis()
            .map_err(urma::error::Error::from)?
            .0
            .to_string(),
        root: recovered.root(),
    };
    snapshot::write_json(&directory.join("locator.json"), &locator)?;
    Ok(locator)
}

struct DirectorySource<'a> {
    directory: &'a Path,
}

impl DirectorySource<'_> {
    fn transaction(&self, txid: Txid) -> Result<Transaction, urma::error::Error> {
        let path = self.directory.join("tx").join(format!("{txid}.bin"));
        if !std::fs::symlink_metadata(&path)?.is_file() {
            return Err(urma::error::Error::Invalid(
                "proof transaction must be a regular file".into(),
            ));
        }
        let bytes = urma::storage::read_bounded(&path, 4 * 1024 * 1024)?;
        let transaction: Transaction = deserialize(&bytes)?;
        urma::ensure!(
            transaction.compute_txid() == txid,
            "proof transaction TXID mismatch"
        );
        Ok(transaction)
    }

    fn record(&self, txid: Txid) -> Result<VerifiedRecord, urma::error::Error> {
        let reveal = self.transaction(txid)?;
        let parent = reveal
            .input
            .first()
            .context("reveal input")?
            .previous_output
            .txid;
        Ok(VerifiedRecord::verify(
            txid,
            &reveal,
            &self.transaction(parent)?,
        )?)
    }
}

impl MultipartSource for DirectorySource<'_> {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        self.record(request.reference.txid)
            .map_err(|error| match error {
                urma::error::Error::Protocol(cause) => FetchError::Rejected(cause),
                cause => FetchError::Source(cause),
            })
    }
}

pub fn reconstruct(
    directory: &Path,
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    regular_file(&directory.join("locator.json"))?;
    if !std::fs::symlink_metadata(directory.join("tx"))?.is_dir() {
        return Err(Error::Invalid("proof transaction directory type".into()));
    }
    let locator: Locator = serde_json::from_slice(&urma::storage::read_bounded(
        &directory.join("locator.json"),
        4096,
    )?)?;
    if locator.schema != 1
        || locator.genesis
            != locator
                .chain
                .genesis()
                .map_err(urma::error::Error::from)?
                .0
                .to_string()
    {
        return Err(Error::Invalid(
            "proof export locator schema or chain".into(),
        ));
    }
    let mut source = DirectorySource { directory };
    let root = source.record(locator.root)?;
    let object = urma::multipart::reconstruct(&root, &mut source, limits, scratch)
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    if object.manifest().profile != Descriptor::PROFILE {
        return Err(Error::Invalid(
            "Git profile or export author metadata".into(),
        ));
    }
    Ok(object)
}

pub fn regular_file(path: &Path) -> Result<(), Error> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(Error::Invalid(
            "proof artifact must be a regular file".into(),
        ));
    }
    Ok(())
}
