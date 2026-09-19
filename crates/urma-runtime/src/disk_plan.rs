use crate::disk_writer::DiskWriter;
use crate::{
    node::Node,
    plan::{PlanLimits, PublicationPlan},
    planner::Planner,
    validation::Validation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use urma::{
    error::{Context, Error, ensure},
    publication::PublicPlan,
};
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskPlan {
    pub version: u8,
    pub chain: Chain,
    pub author: String,
    pub root_txid: String,
    pub total_fee: u64,
    pub maximum_fee: u64,
    pub record_count: u32,
    pub records_hash: String,
    pub index_hash: String,
    #[serde(skip)]
    directory: PathBuf,
}

impl DiskPlan {
    pub const MAX_RECORDS: u32 = 261633;
    pub(crate) const MAX_PAIR_BYTES: usize = 512 * 1024;

    pub fn prepare_multipart(
        node: &Node,
        signer: &impl IdentitySigner,
        reader: &mut impl Read,
        length: u64,
        profile: [u8; 8],
        limits: PlanLimits,
        directory: &Path,
    ) -> Result<Self, Error> {
        let geometry = urma_core::multipart::Geometry::new(length)?;
        let planner = Planner::streaming(node, signer, limits, geometry.nodes())?;
        let writer = DiskWriter::new(directory, planner)?;
        writer.prepare(reader, geometry, length, profile)
    }

    pub(crate) fn from_metadata(
        metadata: &PublicationPlan,
        count: u32,
        records_hash: String,
        index_hash: String,
        directory: &Path,
    ) -> Self {
        Self {
            version: 1,
            chain: metadata.chain,
            author: metadata.author.clone(),
            root_txid: metadata.root_txid.clone(),
            total_fee: metadata.total_fee,
            maximum_fee: metadata.maximum_fee,
            record_count: count,
            records_hash,
            index_hash,
            directory: directory.to_owned(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn load(directory: &Path) -> Result<Self, Error> {
        let mut plan: Self = serde_json::from_slice(&urma::storage::read_bounded(
            &directory.join("plan.json"),
            16384,
        )?)?;
        plan.directory = directory.to_owned();
        plan.validate()?;
        Ok(plan)
    }

    pub fn id(&self) -> Result<String, Error> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn record(&self, index: u32) -> Result<PublicPlan, Error> {
        ensure!(index < self.record_count, "record index exceeds plan");
        let mut offsets = File::open(self.directory.join("index.bin"))?;
        offsets.seek(SeekFrom::Start(u64::from(index) * 12))?;
        let (offset, length) = read_index(&mut offsets)?;
        let mut records = File::open(self.directory.join("records.bin"))?;
        records.seek(SeekFrom::Start(offset))?;
        read_pair(&mut records, length)
    }

    pub fn validate(&self) -> Result<(), Error> {
        ensure!(
            self.version == 1 && self.record_count > 0 && self.record_count <= Self::MAX_RECORDS,
            "invalid disk plan version or record count"
        );
        ensure!(
            self.maximum_fee > 0 && self.total_fee <= self.maximum_fee,
            "plan fee budget exceeded"
        );
        let mut index = File::open(self.directory.join("index.bin"))?;
        let mut records = File::open(self.directory.join("records.bin"))?;
        ensure!(
            index.metadata()?.len() == u64::from(self.record_count) * 12,
            "invalid disk plan index length"
        );
        ensure!(
            digest(&mut index)? == self.index_hash && digest(&mut records)? == self.records_hash,
            "disk plan digest mismatch"
        );
        let mut offset = 0u64;
        let mut state = Validation::new();
        for _ in 0..self.record_count {
            let (actual, length) = read_index(&mut index)?;
            ensure!(actual == offset, "noncanonical disk plan offset");
            state.append(&read_pair(&mut records, length)?, self.chain, &self.author)?;
            offset = offset
                .checked_add(u64::from(length))
                .context("disk plan offset overflow")?;
        }
        ensure!(
            offset == records.metadata()?.len(),
            "trailing disk plan bytes"
        );
        state.finish(self.total_fee, &self.root_txid)
    }
}

fn read_index(reader: &mut impl Read) -> Result<(u64, u32), Error> {
    let mut offset = [0u8; 8];
    let mut length = [0u8; 4];
    reader.read_exact(&mut offset)?;
    reader.read_exact(&mut length)?;
    Ok((u64::from_le_bytes(offset), u32::from_le_bytes(length)))
}

fn read_pair(reader: &mut impl Read, length: u32) -> Result<PublicPlan, Error> {
    ensure!(
        length > 0 && usize::try_from(length)? <= DiskPlan::MAX_PAIR_BYTES,
        "disk plan record exceeds capacity"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn digest(file: &mut File) -> Result<String, Error> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    file.rewind()?;
    Ok(hex::encode(hash.finalize()))
}
