use crate::{capture::Capture, safety};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use urma::error::{Error, ensure};

use crate::config::{MAX_CATALOG_BYTES, MAX_COLLECTION_BYTES, MAX_ENTRIES};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: String,
    pub version: u16,
    pub collection: String,
    pub entries: Vec<Entry>,
    pub capture: Capture,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub source_mode: u32,
    pub content: Content,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    Directory,
    EmptyFile { mime: String },
    File { object: ObjectRef, mime: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub id: String,
    pub bytes: u64,
    pub sha256: String,
}

impl Catalog {
    pub fn validate(&self) -> Result<(), Error> {
        ensure!(self.version == 1, "unsupported private profile version");
        ensure!(
            matches!(
                self.schema.as_str(),
                "urma.private-files" | "urma.capture-evidence"
            ),
            "unsupported private profile schema"
        );
        ensure!(
            !self.collection.is_empty() && self.collection.len() <= 256,
            "invalid collection label"
        );
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_ENTRIES,
            "collection entry limit"
        );
        let mut names = BTreeSet::new();
        let mut entries = BTreeMap::new();
        let mut total = 0u64;
        let mut objects: BTreeMap<&str, &ObjectRef> = BTreeMap::new();
        let mut previous = "";
        for entry in &self.entries {
            safety::validate_path(&entry.path)?;
            ensure!(
                previous < entry.path.as_str(),
                "entries must be uniquely sorted by path"
            );
            previous = &entry.path;
            ensure!(
                names.insert(entry.path.to_lowercase()),
                "case-insensitive path collision"
            );
            ensure!(entry.source_mode <= 0o777, "invalid source mode");
            validate_content(&entry.content)?;
            if let Content::File { object, .. } = &entry.content {
                match objects.entry(object.id.as_str()) {
                    std::collections::btree_map::Entry::Occupied(previous) => {
                        ensure!(*previous.get() == object, "conflicting object references")
                    }
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(object);
                    }
                }
                total = total
                    .checked_add(object.bytes)
                    .ok_or_else(|| Error::Capacity("collection length overflow".into()))?;
            }
            entries.insert(entry.path.as_str(), &entry.content);
        }
        ensure!(
            total <= MAX_COLLECTION_BYTES,
            "collection exceeds client capacity"
        );
        ensure!(
            objects.len() < urma::config::Limits::OBJECTS,
            "collection exceeds shared recovery object capacity including catalog"
        );
        validate_parents(&entries)?;
        self.capture.validate(&self.schema, &entries)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "catalog exceeds client capacity"
        );
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "catalog exceeds client capacity"
        );
        let catalog: Self = serde_json::from_slice(bytes)?;
        catalog.validate()?;
        Ok(catalog)
    }
}

fn validate_content(content: &Content) -> Result<(), Error> {
    match content {
        Content::Directory => {}
        Content::EmptyFile { mime } => validate_mime(mime)?,
        Content::File { object, mime } => {
            safety::validate_id(&object.id)?;
            safety::validate_id(&object.sha256)?;
            ensure!(
                (1..=u64::try_from(urma::config::Limits::INPUT_BYTES)?).contains(&object.bytes),
                "file size exceeds client capacity"
            );
            validate_mime(mime)?;
        }
    }
    Ok(())
}

fn validate_mime(mime: &str) -> Result<(), Error> {
    ensure!(
        !mime.is_empty() && mime.len() <= 128 && mime.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid MIME hint"
    );
    Ok(())
}

fn validate_parents(entries: &BTreeMap<&str, &Content>) -> Result<(), Error> {
    for path in entries.keys() {
        for (position, _separator) in path.match_indices('/') {
            let parent = &path[..position];
            ensure!(
                matches!(entries.get(parent), Some(Content::Directory)),
                "missing or non-directory parent"
            );
        }
    }
    Ok(())
}
