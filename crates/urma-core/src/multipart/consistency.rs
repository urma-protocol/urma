use crate::error::{Context, Error, ensure};
use crate::multipart::{
    ChildReference, DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest,
};
use bitcoin::{Txid, hashes::Hash};
use sha2::{Digest, Sha256};

pub struct MultipartConsistency {
    parts: u32,
    leaves: u16,
    length: u64,
    last_part_length: usize,
    last_leaf_entries: usize,
    payload_hash: Sha256,
    group_hash: Sha256,
    groups: Vec<[u8; 32]>,
    leaves_hash: Sha256,
}

impl Default for MultipartConsistency {
    fn default() -> Self {
        Self::new()
    }
}

impl MultipartConsistency {
    pub fn new() -> Self {
        Self {
            parts: 0,
            leaves: 0,
            length: 0,
            last_part_length: 0,
            last_leaf_entries: 0,
            payload_hash: Sha256::new(),
            group_hash: Sha256::new(),
            groups: Vec::new(),
            leaves_hash: Sha256::new(),
        }
    }

    pub fn accept(&mut self, bytes: &[u8], txid: Txid) -> Result<(), Error> {
        let record = MultipartRecord::decode(bytes)?;
        let reference = ChildReference {
            txid,
            record_hash: Sha256::digest(bytes).into(),
        };
        match record {
            MultipartRecord::Data(part) => self.accept_data(part, reference),
            MultipartRecord::Leaf(leaf) => self.accept_leaf(leaf, reference),
            MultipartRecord::Root(root) => self.accept_root(root),
        }
    }

    fn accept_data(&mut self, part: DataPart, reference: ChildReference) -> Result<(), Error> {
        ensure!(
            part.index == self.parts,
            "noncanonical data publication order"
        );
        if self.parts > 0 {
            ensure!(
                self.last_part_length == Geometry::DATA_BYTES,
                "short nonfinal data part"
            );
        }
        self.payload_hash.update(&part.payload);
        self.group_hash.update(reference.txid.to_byte_array());
        self.group_hash.update(reference.record_hash);
        self.last_part_length = part.payload.len();
        self.length = self
            .length
            .checked_add(u64::try_from(part.payload.len())?)
            .context("payload length overflow")?;
        self.parts = self.parts.checked_add(1).context("part count overflow")?;
        if self.parts.is_multiple_of(u32::from(Geometry::FANOUT)) {
            self.groups.push(self.group_hash.finalize_reset().into());
        }
        Ok(())
    }

    fn accept_leaf(&mut self, leaf: LeafManifest, reference: ChildReference) -> Result<(), Error> {
        ensure!(
            self.parts > 0 && leaf.index == self.leaves,
            "noncanonical leaf publication order"
        );
        if self.leaves > 0 {
            ensure!(
                self.last_leaf_entries == usize::from(Geometry::FANOUT),
                "short nonfinal leaf"
            );
        }
        if self.leaves == 0 && !self.parts.is_multiple_of(u32::from(Geometry::FANOUT)) {
            self.groups.push(self.group_hash.finalize_reset().into());
        }
        ensure!(
            references_hash(&leaf.entries)
                == *self
                    .groups
                    .get(usize::from(self.leaves))
                    .context("leaf references exceed data groups")?,
            "leaf references differ from signed data parts"
        );
        self.leaves_hash.update(reference.txid.to_byte_array());
        self.leaves_hash.update(reference.record_hash);
        self.last_leaf_entries = leaf.entries.len();
        self.leaves = self.leaves.checked_add(1).context("leaf count overflow")?;
        Ok(())
    }

    fn accept_root(&self, root: RootManifest) -> Result<(), Error> {
        ensure!(
            root.payload_hash == <[u8; 32]>::from(self.payload_hash.clone().finalize()),
            "root payload hash mismatch"
        );
        ensure!(
            references_hash(&root.entries) == <[u8; 32]>::from(self.leaves_hash.clone().finalize()),
            "root references differ from signed leaves"
        );
        let geometry = Geometry::new(root.length)?;
        ensure!(
            self.length == root.length
                && self.parts == geometry.parts()
                && self.leaves == geometry.leaves(),
            "publication geometry mismatch"
        );
        ensure!(
            self.last_leaf_entries == usize::from(geometry.leaf_entries(self.leaves - 1)?),
            "final leaf size mismatch"
        );
        Ok(())
    }

    pub fn validate_count(&self, count: u32) -> Result<(), Error> {
        ensure!(
            Geometry::new(self.length)?.nodes() == count,
            "publication root or geometry missing"
        );
        Ok(())
    }
}

fn references_hash(entries: &[ChildReference]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for entry in entries {
        hash.update(entry.txid.to_byte_array());
        hash.update(entry.record_hash);
    }
    hash.finalize().into()
}
