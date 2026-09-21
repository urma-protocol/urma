use crate::{descriptor::Descriptor, error::Error, snapshot};
use bitcoin::{
    Transaction, Txid,
    consensus::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use urma_chain::observation::Chain;
use urma_profiles::git::SnapshotLocator;
use urma_runtime::node::Node;
use urma_runtime::{
    error::Context,
    multipart::{
        FetchError, MultipartRecord, MultipartSource, RecordRequest, RecoveredObject,
        RecoveryLimits, VerifiedRecord,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    pub schema: u8,
    pub chain: Chain,
    pub genesis: String,
    pub root: Txid,
}

impl Locator {
    pub fn snapshot(&self) -> Result<SnapshotLocator, Error> {
        let chain = self
            .chain
            .genesis()
            .map_err(urma_runtime::error::Error::from)?;
        if self.schema != 1 || self.genesis != chain.0.to_string() {
            return Err(Error::Invalid(
                "proof export locator schema or chain".into(),
            ));
        }
        Ok(SnapshotLocator {
            chain,
            root: self.root,
        })
    }
}

pub fn export(
    node: &Node,
    recovered: &RecoveredObject,
    directory: &Path,
) -> Result<Locator, Error> {
    let tx_dir = directory.join("tx");
    if !tx_dir.try_exists()? {
        snapshot::create_private_directory(&tx_dir)?;
    }
    if !std::fs::symlink_metadata(&tx_dir)?.is_dir() {
        return Err(Error::Invalid("proof transaction directory type".into()));
    }
    export_record(node, directory, recovered.root())?;
    for entry in &recovered.manifest().entries {
        let record = export_record(node, directory, entry.txid)?;
        entry_request(*entry).check(&record)?;
        let MultipartRecord::Leaf(leaf) = record.decode()? else {
            return Err(Error::Invalid("proof export leaf kind".into()));
        };
        for part in leaf.entries {
            let record = export_record(node, directory, part.txid)?;
            entry_request(part).check(&record)?;
        }
    }
    let locator = Locator {
        schema: 1,
        chain: node.chain(),
        genesis: node
            .chain()
            .genesis()
            .map_err(urma_runtime::error::Error::from)?
            .0
            .to_string(),
        root: recovered.root(),
    };
    snapshot::write_json(&directory.join("locator.json"), &locator)?;
    Ok(locator)
}

fn entry_request(reference: urma_runtime::multipart::ChildReference) -> RecordRequest {
    RecordRequest { reference }
}

fn export_record(node: &Node, directory: &Path, txid: Txid) -> Result<VerifiedRecord, Error> {
    let reveal = export_transaction(node, directory, txid)?;
    let parent = reveal
        .input
        .first()
        .context("reveal input")?
        .previous_output
        .txid;
    let commit = export_transaction(node, directory, parent)?;
    Ok(VerifiedRecord::verify(txid, &reveal, &commit)?)
}

fn export_transaction(node: &Node, directory: &Path, txid: Txid) -> Result<Transaction, Error> {
    let path = directory.join("tx").join(format!("{txid}.bin"));
    if path.try_exists()? {
        return Ok(DirectorySource { directory }.transaction(txid)?);
    }
    let transaction = node.transaction(txid)?;
    urma_runtime::storage::write_new(&path, &serialize(&transaction))?;
    Ok(transaction)
}

struct DirectorySource<'a> {
    directory: &'a Path,
}

impl DirectorySource<'_> {
    fn transaction(&self, txid: Txid) -> Result<Transaction, urma_runtime::error::Error> {
        let path = self.directory.join("tx").join(format!("{txid}.bin"));
        if !std::fs::symlink_metadata(&path)?.is_file() {
            return Err(urma_runtime::error::Error::Invalid(
                "proof transaction must be a regular file".into(),
            ));
        }
        let bytes = urma_runtime::storage::read_bounded(&path, 4 * 1024 * 1024)?;
        let transaction: Transaction = deserialize(&bytes)?;
        urma_runtime::ensure!(
            transaction.compute_txid() == txid,
            "proof transaction TXID mismatch"
        );
        Ok(transaction)
    }

    fn record(&self, txid: Txid) -> Result<VerifiedRecord, urma_runtime::error::Error> {
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
                urma_runtime::error::Error::Protocol(cause) => FetchError::Rejected(cause),
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
    let locator: Locator = serde_json::from_slice(&urma_runtime::storage::read_bounded(
        &directory.join("locator.json"),
        4096,
    )?)?;
    let snapshot = locator.snapshot()?;
    let mut source = DirectorySource { directory };
    let root = source.record(snapshot.root)?;
    let object = urma_runtime::multipart::reconstruct(&root, &mut source, limits, scratch)
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    if ![Descriptor::PROFILE, Descriptor::UNNAMED_PROFILE].contains(&object.manifest().profile) {
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
