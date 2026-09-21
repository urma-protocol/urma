use crate::{catalog::Content, config::MAX_ENTRIES, recover, safety};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
use urma_runtime::{
    container,
    error::{Error, ensure},
    storage,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub version: u16,
    pub catalog: String,
    pub objects: Vec<String>,
}

pub struct PreparedObject {
    pub id: String,
    pub records: Vec<Vec<u8>>,
    pub is_catalog: bool,
}

impl Inventory {
    pub fn validate(&self) -> Result<(), Error> {
        ensure!(self.version == 1, "unsupported inventory version");
        safety::validate_id(&self.catalog)?;
        ensure!(
            !self.objects.is_empty() && self.objects.len() <= MAX_ENTRIES + 1,
            "invalid inventory size"
        );
        let mut ids = BTreeSet::new();
        for id in &self.objects {
            safety::validate_id(id)?;
            ensure!(ids.insert(id), "duplicate inventory object");
        }
        ensure!(ids.contains(&self.catalog), "catalog absent from inventory");
        Ok(())
    }

    pub fn load(directory: &Path) -> Result<Self, Error> {
        let bytes = safety::read_regular(&directory.join("inventory.json"), 1024 * 1024)?;
        let inventory: Self = serde_json::from_slice(&bytes)?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn save_new(&self, directory: &Path) -> Result<(), Error> {
        self.validate()?;
        storage::write_new(
            &directory.join("inventory.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }
}

pub fn load_object(directory: &Path, id: &str) -> Result<Vec<Vec<u8>>, Error> {
    safety::validate_id(id)?;
    let bytes = safety::read_regular(
        &directory.join(format!("{id}.urma")),
        urma_runtime::config::Limits::CONTAINER_BYTES,
    )?;
    let records = container::unpack(&bytes)?;
    ensure!(
        hex::encode(container::inspect_header(&records[0])?.id) == id,
        "container object ID mismatch"
    );
    Ok(records)
}

pub fn prepared_objects(directory: &Path) -> Result<Vec<PreparedObject>, Error> {
    let inventory = Inventory::load(directory)?;
    let mut objects = Vec::new();
    for id in &inventory.objects {
        objects.push(PreparedObject {
            id: id.clone(),
            records: load_object(directory, id)?,
            is_catalog: *id == inventory.catalog,
        });
    }
    Ok(objects)
}

pub fn authenticated_objects(
    directory: &Path,
    secret: &urma_identity::keys::RecoverySecret,
    max_records: usize,
) -> Result<Vec<PreparedObject>, Error> {
    let catalog = recover::inspect_bundle(directory, secret)?;
    let inventory = Inventory::load(directory)?;
    let mut references = std::collections::BTreeMap::new();
    for entry in &catalog.entries {
        if let Content::File { object, .. } = &entry.content {
            references.insert(object.id.as_str(), object);
        }
    }
    let mut objects = Vec::new();
    let mut count = 0usize;
    for id in &inventory.objects {
        let records = load_object(directory, id)?;
        count = count
            .checked_add(records.len())
            .ok_or_else(|| Error::Capacity("record count overflow".into()))?;
        ensure!(
            count <= max_records,
            "bundle exceeds selected publication record limit"
        );
        let bytes = secret.with_bytes(|root| container::open(root, &records))?;
        if *id != inventory.catalog {
            let expected = references
                .get(id.as_str())
                .ok_or_else(|| Error::Invalid("unexpected inventory object".into()))?;
            ensure!(
                u64::try_from(bytes.len())? == expected.bytes
                    && hex::encode(Sha256::digest(&bytes)) == expected.sha256,
                "original does not match authenticated catalog"
            );
        }
        objects.push(PreparedObject {
            id: id.clone(),
            records,
            is_catalog: *id == inventory.catalog,
        });
    }
    Ok(objects)
}
