use crate::error::{Context, Error, ensure};
use crate::storage;
use crate::{disk_plan::DiskPlan, planner::Planner};
use bitcoin::{Txid, hashes::Hash};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::Path,
};
use urma_core::multipart::{
    ChildReference, DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest,
};
use urma_identity::identity::IdentitySigner;

pub(crate) struct DiskWriter<'a, S> {
    directory: &'a Path,
    planner: Planner<'a, S>,
    records: File,
    index: File,
    records_hash: Sha256,
    index_hash: Sha256,
    offset: u64,
    count: u32,
}

impl<'a, S: IdentitySigner> DiskWriter<'a, S> {
    pub(crate) fn new(directory: &'a Path, planner: Planner<'a, S>) -> Result<Self, Error> {
        use std::os::unix::fs::OpenOptionsExt;
        urma_io::create_private_directory(directory)?;
        let records = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("records.bin"))?;
        let index = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("index.bin"))?;
        Ok(Self {
            directory,
            planner,
            records,
            index,
            records_hash: Sha256::new(),
            index_hash: Sha256::new(),
            offset: 0,
            count: 0,
        })
    }

    fn append(&mut self, bytes: &[u8], total: u32) -> Result<ChildReference, Error> {
        let (reference, pair) = self.planner.prepare_record(bytes)?;
        let encoded = serde_json::to_vec(&pair)?;
        ensure!(
            encoded.len() <= DiskPlan::MAX_PAIR_BYTES,
            "signed record exceeds disk plan capacity"
        );
        let mut entry = Vec::with_capacity(12);
        entry.extend_from_slice(&self.offset.to_le_bytes());
        entry.extend_from_slice(&u32::try_from(encoded.len())?.to_le_bytes());
        self.records.write_all(&encoded)?;
        self.index.write_all(&entry)?;
        self.records_hash.update(&encoded);
        self.index_hash.update(&entry);
        self.offset = self
            .offset
            .checked_add(u64::try_from(encoded.len())?)
            .context("disk plan offset overflow")?;
        self.count = self
            .count
            .checked_add(1)
            .context("disk plan record count overflow")?;
        tracing::info!(target: "urma_ui", phase = "Signing records", done = self.count, total);
        Ok(reference)
    }

    pub(crate) fn prepare(
        mut self,
        reader: &mut impl Read,
        geometry: Geometry,
        length: u64,
        profile: [u8; 8],
    ) -> Result<DiskPlan, Error> {
        let mut hash = Sha256::new();
        tracing::info!(target: "urma_ui", phase = "Signing records", done = 0u64, total = geometry.nodes());
        let mut references = tempfile::tempfile_in(self.directory)?;
        for index in 0..geometry.parts() {
            signing_progress(index, geometry.parts());
            let mut payload = vec![0; geometry.part_length(index)?];
            reader.read_exact(&mut payload)?;
            hash.update(&payload);
            let reference = self.append(
                &MultipartRecord::Data(DataPart { index, payload }).encode()?,
                geometry.nodes(),
            )?;
            references.write_all(&reference.txid.to_byte_array())?;
            references.write_all(&reference.record_hash)?;
        }
        references.rewind()?;
        let mut leaves = Vec::new();
        let mut remaining = geometry.parts();
        while remaining > 0 {
            let count = remaining.min(u32::from(Geometry::FANOUT));
            let mut entries = Vec::new();
            for _ in 0..count {
                let mut txid = [0u8; 32];
                let mut record_hash = [0u8; 32];
                references.read_exact(&mut txid)?;
                references.read_exact(&mut record_hash)?;
                entries.push(ChildReference {
                    txid: Txid::from_byte_array(txid),
                    record_hash,
                });
            }
            leaves.push(
                self.append(
                    &MultipartRecord::Leaf(LeafManifest {
                        index: u16::try_from(leaves.len())?,
                        entries,
                    })
                    .encode()?,
                    geometry.nodes(),
                )?,
            );
            remaining -= count;
        }
        let mut extra = [0u8; 1];
        ensure!(
            reader.read(&mut extra)? == 0,
            "payload exceeds declared length"
        );
        let root = MultipartRecord::Root(RootManifest {
            length,
            payload_hash: hash.finalize().into(),
            profile,
            entries: leaves,
        })
        .encode()?;
        self.append(&root, geometry.nodes())?;
        tracing::info!(target: "urma_ui", phase = "Saving and validating signed records");
        ensure!(
            self.count == geometry.nodes(),
            "disk plan geometry mismatch"
        );
        self.finish()
    }

    fn finish(self) -> Result<DiskPlan, Error> {
        self.records.sync_all()?;
        self.index.sync_all()?;
        let plan = DiskPlan::from_metadata(
            self.planner.metadata(),
            self.count,
            hex::encode(self.records_hash.finalize()),
            hex::encode(self.index_hash.finalize()),
            self.directory,
        );
        storage::write_new(
            &self.directory.join("plan.json"),
            &serde_json::to_vec_pretty(&plan)?,
        )?;
        File::open(self.directory)?.sync_all()?;
        plan.validate()?;
        Ok(plan)
    }
}

fn signing_progress(index: u32, total: u32) {
    if index.is_multiple_of(128) {
        tracing::debug!(target: "urma_progress", signed_parts = index, total_parts = total, "Signing multipart plan");
    }
}
