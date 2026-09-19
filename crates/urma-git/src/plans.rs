use crate::{
    descriptor::{self, Descriptor},
    error::Error,
    inventory::Limits,
    snapshot,
};
use bitcoin::{Transaction, consensus::deserialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, path::Path};
use urma_core::multipart::{MultipartRecord, VerifiedRecord};
use urma_runtime::disk_plan::DiskPlan;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPlan {
    pub schema: u8,
    pub publication_id: String,
    pub root_txid: String,
    pub author: String,
    pub artifacts: Vec<Artifact>,
    pub limits: Limits,
}

impl GitPlan {
    const NAMES: [&'static str; 7] = [
        "object.bin",
        "snapshot.pack",
        "snapshot.json",
        "scan.json",
        "publication/plan.json",
        "publication/records.bin",
        "publication/index.bin",
    ];

    pub fn freeze(
        directory: &Path,
        publication: &DiskPlan,
        limits: &Limits,
    ) -> Result<String, Error> {
        publication.validate()?;
        let mut artifacts = Vec::new();
        for name in Self::NAMES {
            let mut file = File::open(directory.join(name))?;
            artifacts.push(Artifact {
                name: name.into(),
                length: file.metadata()?.len(),
                sha256: hex::encode(descriptor::digest(&mut file)?),
            });
        }
        let plan = Self {
            schema: 2,
            publication_id: publication.id()?,
            root_txid: publication.root_txid.clone(),
            author: publication.author.clone(),
            artifacts,
            limits: limits.clone(),
        };
        snapshot::write_json(&directory.join("plan.json"), &plan)?;
        Self::load(directory).map(|loaded| loaded.1)
    }

    pub fn load(directory: &Path) -> Result<(Self, String), Error> {
        let (plan, identifier, _) = Self::load_with_publication(directory)?;
        Ok((plan, identifier))
    }

    pub fn load_with_publication(directory: &Path) -> Result<(Self, String, DiskPlan), Error> {
        let bytes = urma::storage::read_bounded(&directory.join("plan.json"), 1024 * 1024)?;
        let plan: Self = serde_json::from_slice(&bytes)?;
        if plan.schema != 2 {
            return Err(Error::Invalid(
                "unsupported Git plan schema; prepare and review a new plan with this binary"
                    .into(),
            ));
        }
        let names = plan
            .artifacts
            .iter()
            .map(|artifact| artifact.name.as_str())
            .collect::<BTreeSet<_>>();
        if names != BTreeSet::from(Self::NAMES) || plan.artifacts.len() != Self::NAMES.len() {
            return Err(Error::Invalid("Git plan artifact inventory".into()));
        }
        for artifact in &plan.artifacts {
            let path = directory.join(&artifact.name);
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.len() != artifact.length
                || hex::encode(descriptor::digest(&mut File::open(path)?)?) != artifact.sha256
            {
                return Err(Error::Invalid("immutable Git plan artifact changed".into()));
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"URMA/Git/plan/v0\n");
        hash.update(bytes);
        let identifier = hex::encode(hash.finalize());
        let publication = plan.publication(directory)?;
        Ok((plan, identifier, publication))
    }

    pub fn publication(&self, directory: &Path) -> Result<DiskPlan, Error> {
        let publication = DiskPlan::load(&directory.join("publication"))?;
        if publication.id()? != self.publication_id
            || publication.root_txid != self.root_txid
            || publication.author != self.author
        {
            return Err(Error::Invalid("publication does not match Git plan".into()));
        }
        let root_index = publication
            .record_count
            .checked_sub(1)
            .ok_or_else(|| Error::Invalid("empty publication".into()))?;
        let pair = publication.record(root_index)?;
        let reveal: Transaction =
            deserialize(&hex::decode(&pair.reveal)?).map_err(urma::error::Error::from)?;
        let commit: Transaction =
            deserialize(&hex::decode(&pair.commit)?).map_err(urma::error::Error::from)?;
        let root = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
        let MultipartRecord::Root(manifest) = root.decode()? else {
            return Err(Error::Invalid("Git publication root kind".into()));
        };
        let path = directory.join("object.bin");
        let descriptor = snapshot::inspect(&path)?;
        descriptor.require_profile(manifest.profile)?;
        if descriptor.pack_length > self.limits.max_pack_bytes {
            return Err(Error::Capacity(
                "native PACK bytes exceed frozen limits".into(),
            ));
        }
        if manifest.profile != Descriptor::PROFILE
            || manifest.length != path.metadata()?.len()
            || manifest.payload_hash != descriptor::digest(&mut File::open(path)?)?
        {
            return Err(Error::Invalid(
                "signed publication does not preserve reviewed Git artifact".into(),
            ));
        }
        Ok(publication)
    }
}
