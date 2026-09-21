use crate::error::{Error, ensure};
use crate::publication::PublicPlan;
use crate::storage;
use crate::{node::Node, planner::Planner, validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use urma_chain::observation::Chain;
use urma_core::{
    format::PublicRecord,
    multipart::{DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest},
};
use urma_identity::identity::IdentitySigner;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLimits {
    pub fee_rate: u64,
    pub max_fee: u64,
    pub max_records: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPlan {
    pub version: u8,
    pub chain: Chain,
    pub author: String,
    pub root_txid: String,
    pub total_fee: u64,
    pub maximum_fee: u64,
    pub records: Vec<PublicPlan>,
}

impl PublicationPlan {
    pub const MAX_BYTES: usize = 128 * 1024 * 1024;
    pub const MAX_RECORDS: u32 = 1024;

    pub fn id(&self) -> Result<String, Error> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn validate(&self) -> Result<(), Error> {
        validation::validate(self)
    }

    pub fn save_new(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= Self::MAX_BYTES,
            "plan exceeds client byte capacity"
        );
        storage::write_new(path, &bytes)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let plan: Self = serde_json::from_slice(&storage::read_bounded(path, Self::MAX_BYTES)?)?;
        plan.validate()?;
        Ok(plan)
    }
}

pub fn prepare_atomic(
    node: &Node,
    signer: &impl IdentitySigner,
    record: &PublicRecord,
    limits: PlanLimits,
) -> Result<PublicationPlan, Error> {
    let mut planner = Planner::new(node, signer, limits, 1)?;
    planner.append(&record.encode()?)?;
    planner.finish()
}

pub fn prepare_private_records(
    node: &Node,
    signer: &impl IdentitySigner,
    records: &[Vec<u8>],
    limits: PlanLimits,
) -> Result<PublicationPlan, Error> {
    let mut planner = Planner::new(node, signer, limits, u32::try_from(records.len())?)?;
    for record in records {
        urma_core::container::inspect_header(record)?;
        planner.append(record)?;
    }
    planner.finish()
}

pub fn prepare_multipart(
    node: &Node,
    signer: &impl IdentitySigner,
    payload: &[u8],
    profile: [u8; 8],
    limits: PlanLimits,
) -> Result<PublicationPlan, Error> {
    let geometry = Geometry::new(u64::try_from(payload.len())?)?;
    let mut planner = Planner::new(node, signer, limits, geometry.nodes())?;
    let mut parts = Vec::new();
    for index in 0..geometry.parts() {
        let start = usize::try_from(index)? * Geometry::DATA_BYTES;
        let end = start + geometry.part_length(index)?;
        let bytes = MultipartRecord::Data(DataPart {
            index,
            payload: payload[start..end].to_vec(),
        })
        .encode()?;
        parts.push(planner.append(&bytes)?);
    }
    let mut leaves = Vec::new();
    for (index, entries) in parts.chunks(usize::from(Geometry::FANOUT)).enumerate() {
        let bytes = MultipartRecord::Leaf(LeafManifest {
            index: u16::try_from(index)?,
            entries: entries.to_vec(),
        })
        .encode()?;
        leaves.push(planner.append(&bytes)?);
    }
    let root = MultipartRecord::Root(RootManifest {
        length: u64::try_from(payload.len())?,
        payload_hash: Sha256::digest(payload).into(),
        profile,
        entries: leaves,
    })
    .encode()?;
    planner.append(&root)?;
    planner.finish()
}
