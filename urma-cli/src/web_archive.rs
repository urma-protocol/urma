//! Private optional Web acquisition. A failed attempt cannot publish a pointer
//! or contribute members to autonomous fallback. Local operator metadata is
//! kept separate from authenticated content and from chain inclusion.
use crate::{config, node_cli::chain_name, object_archive::Reader};
use bitcoin::{Transaction, Txid};
use std::{io::Read, path::Path};
use urma_chain::observation::Chain;
use urma_runtime::{
    error::{Error, ensure},
    multipart::{RecoveredObject, RecoveryLimits},
    plan::PublicationPlan,
};
use urma_web::{
    config::Limits,
    error::WebError,
    package::Package,
    store::{AcquisitionSource, Pointer, Store, StoredPublication},
};

fn web<T>(result: Result<T, WebError>) -> Result<T, Error> {
    result.map_err(|cause| Error::Invalid(cause.to_string()))
}

fn bytes(object: &mut RecoveredObject, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    object
        .take(u64::try_from(limit)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "archive payload exceeds limit");
    Ok(bytes)
}

pub(crate) struct Prepared {
    reader: Reader,
    staged: Store,
    pointer: Pointer,
    summary: StoredPublication,
    reveal: Transaction,
    commit: Transaction,
}

/// No live store writes occur here, including when the archive is unavailable.
/// The shared reader charges every root/pin against the same request, raw-pair,
/// payload and cooperative time budgets. Embedded file copies are also charged.
pub(crate) fn prepare(
    chain: Chain,
    root: Txid,
    max_bytes: usize,
) -> Result<Option<Prepared>, Error> {
    let Some(settings) = config::load()?.archive else {
        return Ok(None);
    };
    let attempt = || -> Result<Prepared, Error> {
        let mut reader = Reader::open(
            &settings,
            chain,
            PublicationPlan::MAX_RECORDS,
            &std::env::temp_dir(),
        )?;
        let staged = web(Store::open(&reader.directory().join("web")))?;
        let limits = RecoveryLimits::new(u64::try_from(max_bytes)?, PublicationPlan::MAX_RECORDS);
        let mut object = reader.recover(root, limits)?;
        ensure!(
            object.manifest().profile == Package::PROFILE,
            "archive root is not an URMAWEB1 publication"
        );
        let author = object.author().to_string();
        let payload = bytes(&mut object, max_bytes)?;
        drop(object);
        let package = web(Package::decode(&payload))?;
        web(Limits::DEFAULT.check(&package))?;
        reader.remaining()?;
        for pin in &package.pinned {
            let mut object = reader.recover(pin.root_txid, limits)?;
            ensure!(
                object.manifest().payload_hash == pin.payload_sha256,
                "archive pin root hash differs"
            );
            let payload = bytes(&mut object, max_bytes)?;
            let hash = web(staged.put_object_immutable(&payload))?;
            ensure!(
                hash == hex::encode(pin.payload_sha256),
                "archive pin payload hash differs"
            );
            reader.remaining()?;
        }
        for file in &package.files {
            reader.charge_payload(u64::try_from(file.bytes.len())?)?;
            web(staged.put_object_immutable(&file.bytes))?;
        }
        web(staged.put_object_immutable(&payload))?;
        let reveal = reader.transaction(root)?;
        ensure!(reveal.input.len() == 1, "root reveal must spend one commit");
        let commit = reader.transaction(reveal.input[0].previous_output.txid)?;
        web(staged.put_transaction(&reveal))?;
        let commit_txid = web(staged.put_transaction(&commit))?;
        let pointer = Pointer {
            format: Store::OPERATOR_FORMAT.into(),
            network: chain_name(chain)?,
            root: root.to_string(),
            commit: commit_txid,
            source: Some(AcquisitionSource::LocalNodeOperator),
            tip_height: None,
            tip_hash: None,
        };
        web(staged.put_pointer(&pointer))?;
        let verified = web(staged.publication(&pointer.network, &pointer.root, max_bytes))?;
        ensure!(
            verified.author == author,
            "archive stored author differs from recovered root"
        );
        let summary = web(staged.summary(&verified))?;
        reader.remaining()?;
        Ok(Prepared {
            reader,
            staged,
            pointer,
            summary,
            reveal,
            commit,
        })
    };
    match attempt() {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) => {
            tracing::warn!("optional Web archive unavailable; using autonomous recovery");
            Ok(None)
        }
    }
}

impl Prepared {
    /// All content, pins, proofs and metadata were verified privately. From
    /// here onward errors propagate without fallback. Immutable cache files
    /// may remain on I/O failure; the previous pointer is replaced only last.
    pub(crate) fn publish(self, destination: &Path) -> Result<StoredPublication, Error> {
        self.reader.remaining()?;
        let store = web(Store::open(destination))?;
        for entry in std::fs::read_dir(self.staged.root().join("objects"))? {
            self.reader.remaining()?;
            let entry = entry?;
            let hash = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("invalid staged object name".into()))?;
            let payload = web(self.staged.object(&hash, Store::MAX_OBJECT_BYTES))?;
            web(store.put_object_immutable(&payload))?;
        }
        self.reader.remaining()?;
        for transaction in [&self.reveal, &self.commit] {
            let path = store
                .root()
                .join("tx")
                .join(format!("{}.bin", transaction.compute_txid()));
            let bytes = bitcoin::consensus::serialize(transaction);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    ensure!(metadata.is_file(), "stored transaction must be regular");
                    // No-follow bounded read also protects against replacement
                    // after the metadata check. Reuse never rewrites a file.
                    let existing = urma_io::read_regular(&path, Store::MAX_TRANSACTION_BYTES)?;
                    ensure!(
                        existing.as_slice() == bytes.as_slice(),
                        "stored transaction disagrees with acquired bytes"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Exclusive create refuses a racing file or symlink.
                    urma_io::write_new(&path, &bytes)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.reader.remaining()?;
        web(store.put_pointer(&self.pointer))?;
        Ok(self.summary)
    }
}
