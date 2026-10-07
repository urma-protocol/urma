use super::{
    ChildReference, Geometry, ManifestInventory, MultipartRecord, RecordRequest, RootManifest,
    VerifiedRecord,
};
use crate::error::Error as ServiceError;
use bitcoin::{Txid, XOnlyPublicKey, hashes::Hash};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};
use urma_core::error::Error;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub origin: String,
    pub record: VerifiedRecord,
}

#[derive(Debug)]
pub enum FetchError {
    Unavailable,
    Rejected { origin: String, cause: Error },
    Source(ServiceError),
}

pub trait MultipartSource {
    fn fetch(
        &mut self,
        request: &RecordRequest,
        rejected: &[String],
    ) -> Result<Candidate, FetchError>;

    fn prefetch(&mut self, _requests: &[RecordRequest]) {}
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryLimits {
    pub max_payload_bytes: u64,
    pub max_nodes: u32,
    pub attempts: u32,
    pub timeout: Duration,
}

impl RecoveryLimits {
    pub const ATTEMPTS: u32 = 4;
    pub const TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

    pub fn new(max_payload_bytes: u64, max_nodes: u32) -> Self {
        Self {
            max_payload_bytes,
            max_nodes,
            attempts: Self::ATTEMPTS,
            timeout: Self::TIMEOUT,
        }
    }
}

#[derive(Debug)]
pub enum RecoveryError {
    InvalidObject(Error),
    InvalidCandidate { txid: Txid, cause: Error },
    Incomplete { txid: Txid },
    Source { txid: Txid, cause: ServiceError },
    Capacity(String),
    Storage(std::io::Error),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObject(cause) => write!(formatter, "invalid multipart object: {cause}"),
            Self::InvalidCandidate { txid, cause } => {
                write!(formatter, "invalid candidate {txid}: {cause}")
            }
            Self::Incomplete { txid } => write!(formatter, "incomplete object; missing {txid}"),
            Self::Source { txid, cause } => write!(formatter, "source failure for {txid}: {cause}"),
            Self::Capacity(message) => write!(formatter, "multipart capacity: {message}"),
            Self::Storage(cause) => write!(formatter, "multipart storage: {cause}"),
        }
    }
}
impl std::error::Error for RecoveryError {}
impl From<Error> for RecoveryError {
    fn from(cause: Error) -> Self {
        Self::InvalidObject(cause)
    }
}
impl From<std::io::Error> for RecoveryError {
    fn from(cause: std::io::Error) -> Self {
        Self::Storage(cause)
    }
}

#[derive(Debug)]
pub struct RecoveredObject {
    root: Txid,
    author: XOnlyPublicKey,
    manifest: RootManifest,
    payload: File,
}

impl RecoveredObject {
    pub fn root(&self) -> Txid {
        self.root
    }
    pub fn author(&self) -> XOnlyPublicKey {
        self.author
    }
    pub fn manifest(&self) -> &RootManifest {
        &self.manifest
    }
}
impl Read for RecoveredObject {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.payload.read(bytes)
    }
}
impl Seek for RecoveredObject {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.payload.seek(position)
    }
}

struct Budget {
    attempts: u32,
    started: Instant,
    timeout: Duration,
}

impl Budget {
    fn new(limits: RecoveryLimits) -> Self {
        Self {
            attempts: limits.attempts.max(1),
            started: Instant::now(),
            timeout: limits.timeout,
        }
    }

    fn expired(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }
}

enum Attempted {
    Nothing,
    Rejected(Error),
    Failed(ServiceError),
}

fn given_up(txid: Txid, attempted: Attempted) -> RecoveryError {
    match attempted {
        Attempted::Nothing => RecoveryError::Source {
            txid,
            cause: ServiceError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "recovery deadline passed",
            )),
        },
        Attempted::Rejected(cause) => RecoveryError::InvalidCandidate { txid, cause },
        Attempted::Failed(cause) => RecoveryError::Source { txid, cause },
    }
}

fn unavailable(txid: Txid, attempted: Attempted) -> RecoveryError {
    match attempted {
        Attempted::Nothing => RecoveryError::Incomplete { txid },
        Attempted::Rejected(cause) => RecoveryError::InvalidCandidate { txid, cause },
        Attempted::Failed(cause) => {
            tracing::warn!(%txid, error = %cause, "record unavailable after a transport failure");
            RecoveryError::Incomplete { txid }
        }
    }
}

fn accept(
    request: &RecordRequest,
    record: VerifiedRecord,
    author: XOnlyPublicKey,
) -> Result<VerifiedRecord, RecoveryError> {
    request.check_hash(&record)?;
    if record.author() != author {
        return Err(Error::Invalid("referenced child author differs from root".into()).into());
    }
    Ok(record)
}

fn fetch<S: MultipartSource>(
    source: &mut S,
    reference: ChildReference,
    author: XOnlyPublicKey,
    budget: &Budget,
) -> Result<VerifiedRecord, RecoveryError> {
    let request = RecordRequest { reference };
    let txid = reference.txid;
    let mut rejected: Vec<String> = Vec::new();
    let mut attempted = Attempted::Nothing;
    for attempt in 1..=budget.attempts {
        if budget.expired() {
            return Err(given_up(txid, attempted));
        }
        let (origin, cause) = match source.fetch(&request, &rejected) {
            Ok(candidate) => match request.check_txid(&candidate.record) {
                Ok(()) => return accept(&request, candidate.record, author),
                Err(cause) => {
                    tracing::warn!(%txid, origin = %candidate.origin, error = %cause, "candidate rejected");
                    (candidate.origin, cause)
                }
            },
            Err(FetchError::Rejected { origin, cause }) => {
                tracing::warn!(%txid, %origin, error = %cause, "candidate rejected");
                (origin, cause)
            }
            Err(FetchError::Source(cause)) => {
                tracing::warn!(%txid, attempt, error = %cause, "multipart fetch failed; asking again");
                attempted = Attempted::Failed(cause);
                continue;
            }
            Err(FetchError::Unavailable) => return Err(unavailable(txid, attempted)),
        };
        if rejected.contains(&origin) {
            return Err(RecoveryError::InvalidCandidate { txid, cause });
        }
        rejected.push(origin);
        attempted = Attempted::Rejected(cause);
    }
    Err(given_up(txid, attempted))
}

fn inventory_error(cause: Error) -> RecoveryError {
    match cause {
        Error::Allocation(error) => RecoveryError::Capacity(error.to_string()),
        error => RecoveryError::InvalidObject(error),
    }
}

fn inventory<S: MultipartSource>(
    root: &VerifiedRecord,
    manifest: &RootManifest,
    source: &mut S,
    budget: &Budget,
    file: &mut File,
) -> Result<(), RecoveryError> {
    let mut inventory = ManifestInventory::new(root.txid(), manifest).map_err(inventory_error)?;
    let mut received = 0u64;
    tracing::info!(target: "urma_ui", phase = "Receiving manifests", done = received, total = manifest.entries.len());
    for batch in manifest.entries.chunks(8) {
        let requests: Vec<_> = batch
            .iter()
            .map(|reference| RecordRequest {
                reference: *reference,
            })
            .collect();
        source.prefetch(&requests);
        for entry in batch {
            let verified = fetch(source, *entry, root.author(), budget)?;
            let MultipartRecord::Leaf(leaf) = verified.decode()? else {
                return Err(Error::Invalid("root must reference leaf manifests".into()).into());
            };
            inventory.accept_leaf(&leaf).map_err(inventory_error)?;
            for reference in leaf.entries {
                file.write_all(reference.txid.as_byte_array())?;
                file.write_all(&reference.record_hash)?;
            }
            received += 1;
            tracing::info!(target: "urma_ui", phase = "Receiving manifests", done = received, total = manifest.entries.len());
        }
    }
    file.rewind()?;
    Ok(())
}

fn read_requests(file: &mut File, count: u32) -> Result<Vec<RecordRequest>, RecoveryError> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let mut txid = [0; 32];
        let mut record_hash = [0; 32];
        file.read_exact(&mut txid)?;
        file.read_exact(&mut record_hash)?;
        requests.push(RecordRequest {
            reference: ChildReference {
                txid: Txid::from_byte_array(txid),
                record_hash,
            },
        });
    }
    Ok(requests)
}

fn reconstruct_parts<S: MultipartSource>(
    source: &mut S,
    author: XOnlyPublicKey,
    manifest: &RootManifest,
    geometry: Geometry,
    budget: &Budget,
    inventory: &mut File,
    payload: &mut File,
) -> Result<(), RecoveryError> {
    let mut digest = Sha256::new();
    let mut length = 0u64;
    tracing::info!(target: "urma_ui", phase = "Receiving payload bytes", done = length, total = manifest.length);
    for start in (0..geometry.parts()).step_by(8) {
        let count = (geometry.parts() - start).min(8);
        let requests = read_requests(inventory, count)?;
        source.prefetch(&requests);
        for (offset, request) in requests.into_iter().enumerate() {
            let index = start + u32::try_from(offset).map_err(Error::from)?;
            let verified = fetch(source, request.reference, author, budget)?;
            let MultipartRecord::Data(part) = verified.decode()? else {
                return Err(Error::Invalid("leaf must reference data parts".into()).into());
            };
            if part.index != index || part.payload.len() != geometry.part_length(index)? {
                return Err(
                    Error::Invalid("data position or length disagrees with root".into()).into(),
                );
            }
            length = length
                .checked_add(u64::try_from(part.payload.len()).map_err(Error::from)?)
                .ok_or_else(|| Error::Invalid("reconstruction length overflow".into()))?;
            digest.update(&part.payload);
            payload.write_all(&part.payload)?;
            tracing::info!(target: "urma_ui", phase = "Receiving payload bytes", done = length, total = manifest.length);
        }
    }
    let actual_hash: [u8; 32] = digest.finalize().into();
    tracing::info!(target: "urma_ui", phase = "Verifying complete payload digest");
    if length != manifest.length || actual_hash != manifest.payload_hash {
        return Err(Error::Invalid("complete payload length or digest mismatch".into()).into());
    }
    payload.rewind()?;
    Ok(())
}

pub fn reconstruct<S: MultipartSource>(
    root: &VerifiedRecord,
    source: &mut S,
    limits: RecoveryLimits,
    scratch_directory: &Path,
) -> Result<RecoveredObject, RecoveryError> {
    let MultipartRecord::Root(manifest) = root.decode()? else {
        return Err(Error::Invalid("recovery locator must name a root manifest".into()).into());
    };
    let geometry = manifest.geometry()?;
    if geometry.length() > limits.max_payload_bytes || geometry.nodes() > limits.max_nodes {
        return Err(RecoveryError::Capacity(
            "object exceeds caller's byte/node budget".into(),
        ));
    }
    let budget = Budget::new(limits);
    let mut references = tempfile::tempfile_in(scratch_directory)?;
    inventory(root, &manifest, source, &budget, &mut references)?;
    let mut payload = tempfile::tempfile_in(scratch_directory)?;
    reconstruct_parts(
        source,
        root.author(),
        &manifest,
        geometry,
        &budget,
        &mut references,
        &mut payload,
    )?;
    Ok(RecoveredObject {
        root: root.txid(),
        author: root.author(),
        manifest,
        payload,
    })
}
