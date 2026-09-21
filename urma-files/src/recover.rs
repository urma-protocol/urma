use crate::{
    catalog::{Catalog, Content, ObjectRef},
    config::MAX_CATALOG_BYTES,
    inventory::{Inventory, load_object},
    safety,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use urma_identity::keys::RecoverySecret;
use urma_runtime::{
    container,
    error::{Error, ensure},
    storage,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum ObjectSource<'a> {
    Encrypted {
        directory: &'a Path,
        secret: &'a RecoverySecret,
    },
    Authenticated {
        objects: &'a BTreeMap<[u8; 32], container::PrivateObject>,
    },
    Recovered {
        directory: &'a Path,
    },
}

#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    pub complete: bool,
    pub exported_files: usize,
    pub exported_directories: usize,
    pub missing_objects: Vec<String>,
    pub invalid_objects: Vec<String>,
    pub mode_policy: &'static str,
}

impl ObjectSource<'_> {
    pub fn open(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        safety::validate_id(id)?;
        match self {
            Self::Encrypted { directory, secret } => {
                let records = load_object(directory, id)?;
                Ok(secret.with_bytes(|root| container::open(root, &records))?)
            }
            Self::Authenticated { objects } => {
                let id: [u8; 32] = hex::decode(id)?.try_into().map_err(|bytes: Vec<u8>| {
                    Error::Invalid(format!("invalid ID length {}", bytes.len()))
                })?;
                Ok(objects
                    .get(&id)
                    .ok_or_else(|| Error::Invalid("object missing from recovery".into()))?
                    .finish()?)
            }
            Self::Recovered { directory } => safety::read_regular(
                &directory.join(format!("{id}.bin")),
                urma_runtime::config::Limits::INPUT_BYTES,
            ),
        }
    }

    fn exists(&self, id: &str) -> Result<bool, Error> {
        safety::validate_id(id)?;
        let path = match self {
            Self::Encrypted { directory, .. } => directory.join(format!("{id}.urma")),
            Self::Recovered { directory } => directory.join(format!("{id}.bin")),
            Self::Authenticated { objects } => {
                let id: [u8; 32] = hex::decode(id)?.try_into().map_err(|bytes: Vec<u8>| {
                    Error::Invalid(format!("invalid ID length {}", bytes.len()))
                })?;
                return Ok(objects.contains_key(&id));
            }
        };
        Ok(path.try_exists()?)
    }
}

pub fn catalog(source: ObjectSource<'_>, catalog_id: &str) -> Result<Catalog, Error> {
    let bytes = source.open(catalog_id)?;
    ensure!(
        bytes.len() <= MAX_CATALOG_BYTES,
        "catalog exceeds client capacity"
    );
    Catalog::decode(&bytes)
}

pub fn inspect_bundle(directory: &Path, secret: &RecoverySecret) -> Result<Catalog, Error> {
    let inventory = Inventory::load(directory)?;
    let catalog = catalog(
        ObjectSource::Encrypted { directory, secret },
        &inventory.catalog,
    )?;
    let mut expected = BTreeSet::from([inventory.catalog.clone()]);
    for entry in &catalog.entries {
        if let Content::File { object, .. } = &entry.content {
            expected.insert(object.id.clone());
        }
    }
    ensure!(
        expected == inventory.objects.into_iter().collect(),
        "inventory disagrees with authenticated catalog"
    );
    Ok(catalog)
}

pub fn recover(
    source: ObjectSource<'_>,
    catalog_id: &str,
    output: &Path,
) -> Result<RecoveryReport, Error> {
    let catalog = catalog(source, catalog_id)?;
    ensure!(!output.try_exists()?, "export requires a new directory");
    safety::new_directory(output)?;
    let mut report = RecoveryReport {
        complete: true,
        exported_files: 0,
        exported_directories: 0,
        missing_objects: Vec::new(),
        invalid_objects: Vec::new(),
        mode_policy: "directories 0700; files 0600; source modes retained only in catalog",
    };
    for entry in &catalog.entries {
        let target = output.join(&entry.path);
        match &entry.content {
            Content::Directory => {
                safety::new_directory(&target)?;
                report.exported_directories += 1;
            }
            Content::EmptyFile { .. } => {
                storage::write_new(&target, &[])?;
                report.exported_files += 1;
            }
            Content::File { object, .. } => export_member(source, object, &target, &mut report)?,
        }
    }
    report.complete = report.missing_objects.is_empty() && report.invalid_objects.is_empty();
    Ok(report)
}

fn export_member(
    source: ObjectSource<'_>,
    object: &ObjectRef,
    target: &Path,
    report: &mut RecoveryReport,
) -> Result<(), Error> {
    if !source.exists(&object.id)? {
        report.missing_objects.push(object.id.clone());
        return Ok(());
    }
    let bytes = match source.open(&object.id) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, id = %object.id, "collection object rejected");
            report.invalid_objects.push(object.id.clone());
            return Ok(());
        }
    };
    if u64::try_from(bytes.len())? != object.bytes
        || hex::encode(Sha256::digest(&bytes)) != object.sha256
    {
        report.invalid_objects.push(object.id.clone());
        return Ok(());
    }
    storage::write_new(target, &bytes)?;
    report.exported_files += 1;
    Ok(())
}
