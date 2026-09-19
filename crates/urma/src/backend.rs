use crate::config::{MAX_DIRECTORY_RECORDS, MAX_OBJECTS};
use crate::error::{Context, Error, ensure};
use crate::format::Urma;
use crate::{
    container::{self, PrivateObject},
    storage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    #[default]
    Litecoin,
    Bitcoin,
    Directory,
    Ethereum,
    Storj,
    GoogleDrive,
    S3,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub preferred: Family,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Locator {
    BlockRange {
        network: String,
        start_height: u64,
        tip_height: u64,
        tip_hash: String,
    },
    Directory {
        path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    LitecoinCoreTrusted,
    LocalBytes,
    CommitmentsAndCoreChain,
    CommitmentsAndProviderChain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub backend: Family,
    pub locator: Locator,
    pub evidence: Evidence,
    pub scanned_bytes: usize,
}

pub trait RecordSource {
    fn read_records(
        &self,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error>;
}

pub struct Recovery {
    pub objects: BTreeMap<[u8; 32], PrivateObject>,
    pub rejected_records: u64,
    pub observation: Observation,
}

pub fn accept_record(
    key: &[u8; 32],
    record: &[u8],
    objects: &mut BTreeMap<[u8; 32], PrivateObject>,
) -> Result<u64, Error> {
    let chunk = match container::open_record(key, record) {
        Ok(container::RecordMatch::Authenticated(chunk)) => chunk,
        Ok(container::RecordMatch::Unrelated) => return Ok(0),
        Err(error) => {
            tracing::warn!(%error, "invalid private candidate rejected");
            return Ok(1);
        }
    };
    match objects.entry(chunk.id) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            match entry.get_mut().insert(chunk) {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(%error, "authenticated object conflict retained");
                }
            }
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(PrivateObject::new(chunk));
        }
    }
    ensure!(
        objects.len() <= MAX_OBJECTS,
        "client object capacity exceeded"
    );
    Ok(0)
}

pub fn recover(source: &dyn RecordSource, key: &[u8; 32]) -> Result<Recovery, Error> {
    let mut objects = BTreeMap::new();
    let mut rejected_records = 0u64;
    let observation = source.read_records(&mut |record| {
        rejected_records = rejected_records
            .checked_add(accept_record(key, record, &mut objects)?)
            .ok_or_else(|| Error::Invalid("rejected record count overflow".into()))?;
        Ok(())
    })?;
    Ok(Recovery {
        objects,
        rejected_records,
        observation,
    })
}

pub struct DirectorySource<'a> {
    pub path: &'a Path,
}

impl RecordSource for DirectorySource<'_> {
    fn read_records(
        &self,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(self.path)?.take(MAX_DIRECTORY_RECORDS + 1) {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "record directory contains a non-regular entry"
            );
            ensure!(
                entry
                    .path()
                    .extension()
                    .context("record extension missing")?
                    == "urma-record",
                "unexpected record directory entry"
            );
            paths.push(entry.path());
        }
        ensure!(
            paths.len() <= MAX_DIRECTORY_RECORDS,
            "directory record limit reached"
        );
        paths.sort();
        let mut scanned_bytes = 0;
        for path in &paths {
            let record = storage::read_bounded(path, Urma::PRIVATE_RECORD_BYTES)?;
            scanned_bytes += record.len();
            emit(&record)?;
        }
        Ok(Observation {
            backend: Family::Directory,
            locator: Locator::Directory {
                path: self.path.to_path_buf(),
            },
            evidence: Evidence::LocalBytes,
            scanned_bytes,
        })
    }
}

pub fn store_directory(path: &Path, records: &[Vec<u8>]) -> Result<Observation, Error> {
    ensure!(
        !records.is_empty() && records.len() <= MAX_DIRECTORY_RECORDS,
        "invalid record count"
    );
    for record in records {
        container::inspect_header(record)?;
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let mut stored_bytes = 0;
    for record in records {
        let name = format!("{}.urma-record", hex::encode(Sha256::digest(record)));
        let target = path.join(name);
        if !target.try_exists()? {
            storage::write_new(&target, record)?;
            stored_bytes += record.len();
        }
    }
    Ok(Observation {
        backend: Family::Directory,
        locator: Locator::Directory {
            path: path.to_path_buf(),
        },
        evidence: Evidence::LocalBytes,
        scanned_bytes: stored_bytes,
    })
}

pub fn require_implemented(family: Family) -> Result<(), Error> {
    ensure!(
        matches!(
            family,
            Family::Litecoin | Family::Bitcoin | Family::Directory
        ),
        "{family:?} adapter is not implemented; no fallback to another backend"
    );
    Ok(())
}

pub struct ExportReport {
    pub complete: bool,
    pub report: serde_json::Value,
}

pub fn export(recovery: Recovery, output: &Path) -> Result<ExportReport, Error> {
    ensure!(
        !output.try_exists()?,
        "recovery requires a new output directory"
    );
    let mut reports = Vec::new();
    let mut complete = 0usize;
    for object in recovery.objects.values() {
        let id = hex::encode(object.id);
        if object.is_conflicted() {
            reports.push(
                serde_json::json!({"id":id,"status":"invalid","reason":"authenticated_conflict"}),
            );
            continue;
        }
        if !object.is_complete() {
            reports.push(serde_json::json!({"id":id,"status":"incomplete","received":object.received(),"expected":object.count,"bytes":object.total}));
            continue;
        }
        let bytes = match object.finish() {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, %id, "object integrity failed; other objects remain recoverable");
                reports.push(
                    serde_json::json!({"id":id,"status":"invalid","reason":error.to_string()}),
                );
                continue;
            }
        };
        if complete == 0 {
            fs::DirBuilder::new().mode(0o700).create(output)?;
        }
        storage::write_new(&output.join(format!("{id}.bin")), &bytes)?;
        reports.push(serde_json::json!({"id":id,"status":"complete","bytes":bytes.len(),"content_type":object.content_type.code(),
            "chunks":object.count,"sha256":hex::encode(Sha256::digest(&bytes))}));
        complete += 1;
    }
    let success = complete > 0 && complete == recovery.objects.len();
    let status = if success {
        "complete"
    } else if recovery.objects.is_empty() {
        "not_found"
    } else {
        "partial"
    };
    let mut report = serde_json::json!({"status":status,"objects":reports,"rejected_records":recovery.rejected_records,
        "scanned_bytes":recovery.observation.scanned_bytes,"observation":recovery.observation});
    if let Locator::BlockRange {
        network,
        start_height,
        tip_height,
        tip_hash,
    } = &recovery.observation.locator
    {
        report["network"] = serde_json::json!(network);
        report["start_height"] = serde_json::json!(start_height);
        report["tip_height"] = serde_json::json!(tip_height);
        report["tip_hash"] = serde_json::json!(tip_hash);
    }
    Ok(ExportReport {
        complete: success,
        report,
    })
}
