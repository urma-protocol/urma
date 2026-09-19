use crate::{config::MAX_ENTRIES, safety};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use urma::{
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
        urma::config::Limits::CONTAINER_BYTES,
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
