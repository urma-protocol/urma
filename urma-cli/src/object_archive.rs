//! Optional local content acquisition. Signatures and the complete multipart
//! graph are checked here; selected-chain membership is not. No header is
//! available from this API, so package paths remain unverified operator data.
use crate::config::ArchiveSettings;
use bitcoin::{Transaction, Txid, consensus::serialize};
use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_node_client::{Client, model::API_VERSION};
use urma_runtime::{
    error::{Error, ensure},
    multipart::{
        self, Candidate, FetchError, MultipartSource, RecordRequest, RecoveredObject,
        RecoveryLimits, VerifiedRecord,
    },
};

const OPERATION_TIME: Duration = Duration::from_secs(30);
const MAX_RECORDS: u32 = 32_768;
const MAX_TRANSACTIONS_BYTES: usize = 512 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
// Compatibility with the existing offline Git proof reader. These are
// canonical transparent Bitcoin projections, not original Litecoin encodings.
const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const ORIGIN: &str = "local operator archive";

fn refused() -> Error {
    // Server-controlled diagnostics must never expose a reflected bearer.
    Error::Invalid("optional archive content unavailable".into())
}

/// One private acquisition session; pins share its deadline and total budgets.
pub(crate) struct Reader {
    client: Client,
    chain: Chain,
    directory: tempfile::TempDir,
    deadline: Instant,
    remaining_records: u32,
    remaining_bytes: usize,
    remaining_payload: u64,
}

impl Reader {
    pub(crate) fn open(
        settings: &ArchiveSettings,
        chain: Chain,
        max_records: u32,
        parent: &Path,
    ) -> Result<Self, Error> {
        let deadline = Instant::now() + OPERATION_TIME;
        ensure!(
            std::fs::symlink_metadata(&settings.token_file)?.is_file(),
            "archive token must be regular"
        );
        let token = urma_io::read_private(&settings.token_file, 256)?;
        let token = std::str::from_utf8(&token).map_err(|_| refused())?.trim();
        let client = Client::new(settings.endpoint, token.to_owned()).map_err(|_| refused())?;
        let directory = tempfile::Builder::new()
            .prefix(".urma-archive-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        urma_io::create_private_directory(&directory.path().join("tx"))?;
        Ok(Self {
            client,
            chain,
            directory,
            deadline,
            remaining_records: max_records.min(MAX_RECORDS),
            remaining_bytes: MAX_TRANSACTIONS_BYTES,
            remaining_payload: MAX_PAYLOAD_BYTES,
        })
    }

    pub(crate) fn directory(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn remaining(&self) -> Result<(), Error> {
        ensure!(
            Instant::now() < self.deadline,
            "optional archive content deadline passed"
        );
        Ok(())
    }

    pub(crate) fn recover(
        &mut self,
        root: Txid,
        mut limits: RecoveryLimits,
    ) -> Result<RecoveredObject, Error> {
        self.remaining()?;
        limits.max_nodes = limits.max_nodes.min(self.remaining_records);
        limits.max_payload_bytes = limits.max_payload_bytes.min(self.remaining_payload);
        limits.attempts = 1;
        limits.timeout = OPERATION_TIME;
        let verified = self.record(root)?;
        let urma_core::multipart::MultipartRecord::Root(manifest) = verified.decode()? else {
            return Err(refused());
        };
        // Charge before allocating the reconstruction payload, across all roots.
        self.charge_payload(manifest.length)?;
        let path = self.directory.path().to_path_buf();
        let object =
            multipart::reconstruct(&verified, self, limits, &path).map_err(|_| refused())?;
        self.remaining()?;
        Ok(object)
    }

    /// Account for additional private payload copies, such as embedded Web files.
    pub(crate) fn charge_payload(&mut self, bytes: u64) -> Result<(), Error> {
        self.remaining()?;
        self.remaining_payload = self
            .remaining_payload
            .checked_sub(bytes)
            .ok_or_else(refused)?;
        Ok(())
    }

    /// Read back a canonical transaction already authenticated and retained in
    /// this private attempt. This never performs another HTTP request.
    pub(crate) fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        self.remaining()?;
        let path = self.directory().join("tx").join(format!("{txid}.bin"));
        let raw = urma_io::read_regular(&path, MAX_TRANSACTION_BYTES)?;
        let transaction: Transaction = bitcoin::consensus::deserialize(&raw)?;
        ensure!(
            transaction.compute_txid() == txid,
            "retained transaction identity differs"
        );
        self.remaining()?;
        Ok(transaction)
    }

    fn retain(&self, transaction: &Transaction) -> Result<(), Error> {
        let bytes = serialize(transaction);
        ensure!(
            bytes.len() <= MAX_TRANSACTION_BYTES,
            "archive proof transaction exceeds limit"
        );
        let path = self
            .directory
            .path()
            .join("tx")
            .join(format!("{}.bin", transaction.compute_txid()));
        if path.try_exists()? {
            // Only this attempt writes inside its private directory. Shared
            // commits must agree even when referenced by different reveals.
            ensure!(
                urma_io::read_regular(&path, MAX_TRANSACTION_BYTES)?.as_slice() == bytes,
                "archive proof transactions disagree"
            );
        } else {
            urma_io::write_new(&path, &bytes)?;
        }
        self.remaining()
    }

    fn record(&mut self, txid: Txid) -> Result<VerifiedRecord, Error> {
        self.remaining()?;
        self.remaining_records = self.remaining_records.checked_sub(1).ok_or_else(refused)?;
        let archived = self
            .client
            .record(txid)
            .map_err(|_| refused())?
            .ok_or_else(refused)?;
        self.remaining()?;
        let package = archived.package;
        ensure!(
            package.version == API_VERSION && package.chain_genesis == self.chain.genesis()?.0,
            "archive package version or network differs"
        );
        ensure!(
            package.block == archived.receipt.block
                && package.reveal.txid_path.index == archived.receipt.position,
            "archive package and receipt disagree"
        );
        ensure!(
            package.reveal.transaction.len() <= MAX_TRANSACTION_BYTES
                && package.commit.len() <= MAX_TRANSACTION_BYTES,
            "archive transaction exceeds proof export limit"
        );
        let bytes = package
            .reveal
            .transaction
            .len()
            .checked_add(package.commit.len())
            .ok_or_else(refused)?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(bytes)
            .ok_or_else(refused)?;
        let reveal = urma_chain::decode::transaction(&package.reveal.transaction, self.chain)?;
        let commit = urma_chain::decode::transaction(&package.commit, self.chain)?;
        ensure!(
            reveal.compute_wtxid() == archived.receipt.wtxid,
            "archive receipt witness identity differs"
        );
        let verified = VerifiedRecord::verify(txid, &reveal, &commit)?;
        urma_core::envelope::extract_reveal(&reveal)?;
        self.remaining()?;
        self.retain(&reveal)?;
        self.retain(&commit)?;
        Ok(verified)
    }
}

impl MultipartSource for Reader {
    fn fetch(
        &mut self,
        request: &RecordRequest,
        rejected: &[String],
    ) -> Result<Candidate, FetchError> {
        if rejected.iter().any(|origin| origin == ORIGIN) {
            return Err(FetchError::Unavailable);
        }
        let record = self
            .record(request.reference.txid)
            .map_err(FetchError::Source)?;
        // Reconstruct checks the signed reference, author, geometry and final
        // payload. There is one attempt, with no per-record retry or prefetch.
        Ok(Candidate {
            origin: ORIGIN.into(),
            record,
        })
    }
}

/// Return a complete, independently authenticated content graph in an owned
/// staging directory. Dropping it discards every file from a failed attempt.
/// Time bounds are cooperative across root, children and retention; an entered
/// HTTP call (five seconds), filesystem operation or crypto work is not killed.
/// The locator asserts the requested network, not verified chain inclusion.
pub(crate) fn retain(
    settings: &ArchiveSettings,
    chain: Chain,
    root: Txid,
    limits: RecoveryLimits,
    parent: &Path,
) -> Result<tempfile::TempDir, Error> {
    let mut source = Reader::open(settings, chain, limits.max_nodes, parent)?;
    let reconstructed = source.recover(root, limits)?;
    source.remaining()?;
    drop(reconstructed);
    // Existing offline Git readers reverify every retained pair and payload.
    // No operator tip, confirmation count or membership claim is exported.
    let locator = urma_git::proofs::Locator {
        schema: 1,
        chain,
        genesis: chain.genesis()?.0.to_string(),
        root,
    };
    urma_io::write_new(
        &source.directory().join("locator.json"),
        &serde_json::to_vec(&locator)?,
    )?;
    source.remaining()?;
    Ok(source.directory)
}
