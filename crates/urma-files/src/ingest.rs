use crate::config::{MAX_COLLECTION_BYTES, MAX_ENTRIES};
use crate::{
    capture::Capture,
    catalog::{Catalog, Content, Entry, ObjectRef},
    inventory::Inventory,
    safety,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use urma::{
    container,
    error::{Context, Error, ensure},
    format::ContentType,
    storage,
};
use urma_identity::keys::RecoverySecret;

pub struct IngestRequest<'a> {
    pub inputs: &'a [PathBuf],
    pub output: &'a Path,
    pub collection: &'a str,
    pub capture: Capture,
}

#[derive(Clone)]
struct SourceEntry {
    source: PathBuf,
    path: String,
    directory: bool,
    mode: u32,
    bytes: u64,
}

pub fn ingest(secret: &RecoverySecret, request: IngestRequest<'_>) -> Result<Inventory, Error> {
    ensure!(!request.inputs.is_empty(), "at least one input required");
    let sources = scan(request.inputs)?;
    ensure!(
        sources
            .iter()
            .filter(|source| !source.directory && source.bytes != 0)
            .count()
            < urma::config::Limits::OBJECTS,
        "collection exceeds shared recovery object capacity including catalog"
    );
    ensure!(
        !request.output.try_exists()?,
        "output must be a new directory"
    );
    let mut catalog = Catalog {
        schema: match request.capture {
            Capture::Files => "urma.private-files",
            Capture::Session { .. } => "urma.capture-evidence",
        }
        .into(),
        version: 1,
        collection: request.collection.into(),
        entries: sources.iter().map(preflight_entry).collect(),
        capture: request.capture,
    };
    catalog.validate()?;
    safety::new_directory(request.output)?;
    let mut ids = Vec::new();
    for (source, entry) in sources.iter().zip(catalog.entries.iter_mut()) {
        if !source.directory && source.bytes != 0 {
            let bytes = safety::read_regular(&source.source, urma::config::Limits::INPUT_BYTES)?;
            ensure!(
                u64::try_from(bytes.len())? == source.bytes,
                "file length changed during intake"
            );
            let object = store_object(secret, &bytes, request.output)?;
            ids.push(object.id.clone());
            entry.content = Content::File {
                object,
                mime: "application/octet-stream".into(),
            };
        } else if !source.directory {
            ensure!(
                safety::read_regular(&source.source, 0)?.is_empty(),
                "empty file changed during intake"
            );
        }
    }
    let encoded = zeroize::Zeroizing::new(catalog.encode()?);
    let object = store_object(secret, &encoded, request.output)?;
    ids.push(object.id.clone());
    let inventory = Inventory {
        version: 1,
        catalog: object.id,
        objects: ids,
    };
    inventory.save_new(request.output)?;
    Ok(inventory)
}

fn preflight_entry(source: &SourceEntry) -> Entry {
    let content = if source.directory {
        Content::Directory
    } else if source.bytes == 0 {
        Content::EmptyFile {
            mime: "application/octet-stream".into(),
        }
    } else {
        Content::File {
            object: ObjectRef {
                id: "0".repeat(64),
                bytes: source.bytes,
                sha256: "0".repeat(64),
            },
            mime: "application/octet-stream".into(),
        }
    };
    Entry {
        path: source.path.clone(),
        source_mode: source.mode,
        content,
    }
}

fn scan(inputs: &[PathBuf]) -> Result<Vec<SourceEntry>, Error> {
    let mut pending = Vec::new();
    for source in inputs {
        let name = source
            .file_name()
            .context("input must have a basename")?
            .to_str()
            .context("filename is not UTF-8")?;
        pending.push((source.clone(), name.to_owned()));
    }
    let mut entries = Vec::new();
    let mut total = 0u64;
    while !pending.is_empty() {
        let (source, path) = pending.pop().context("intake stack unexpectedly empty")?;
        safety::validate_path(&path)?;
        let metadata = fs::symlink_metadata(&source)?;
        ensure!(
            metadata.is_file() || metadata.is_dir(),
            "symlinks and special files are unsupported"
        );
        ensure!(
            entries.len() < MAX_ENTRIES,
            "collection exceeds entry capacity"
        );
        let directory = metadata.is_dir();
        if directory {
            for child in fs::read_dir(&source)?.take(MAX_ENTRIES + 1) {
                let child = child?;
                let name = child
                    .file_name()
                    .into_string()
                    .map_err(|name| Error::Invalid(format!("filename is not UTF-8: {name:?}")))?;
                ensure!(
                    entries.len() + pending.len() < MAX_ENTRIES,
                    "collection exceeds entry capacity"
                );
                pending.push((child.path(), format!("{path}/{name}")));
            }
        } else {
            ensure!(
                metadata.len() <= u64::try_from(urma::config::Limits::INPUT_BYTES)?,
                "file exceeds client capacity"
            );
            total = total
                .checked_add(metadata.len())
                .context("collection size overflow")?;
            ensure!(
                total <= MAX_COLLECTION_BYTES,
                "collection exceeds client capacity"
            );
        }
        entries.push(SourceEntry {
            source,
            path,
            directory,
            mode: metadata.permissions().mode() & 0o777,
            bytes: if directory { 0 } else { metadata.len() },
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn store_object(secret: &RecoverySecret, bytes: &[u8], output: &Path) -> Result<ObjectRef, Error> {
    let records = secret.with_bytes(|root| container::seal(root, bytes, ContentType::Opaque))?;
    let object = ObjectRef {
        id: hex::encode(container::inspect_header(&records[0])?.id),
        bytes: u64::try_from(bytes.len())?,
        sha256: hex::encode(Sha256::digest(bytes)),
    };
    storage::write_new(
        &output.join(format!("{}.urma", object.id)),
        &container::pack(&records)?,
    )?;
    Ok(object)
}
