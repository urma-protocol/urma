use bitcoin::{Txid, hashes::Hash};
use sha2::{Digest, Sha256};
use urma::error::{Context, Error, ensure};
use urma_core::multipart::ChildReference;
use urma_core::multipart::{Geometry, MultipartRecord};

pub(crate) struct Order {
    parts: u32,
    leaves: u16,
    length: u64,
    last_part_length: usize,
    last_leaf_entries: usize,
    root: bool,
    payload_hash: Sha256,
    group_hash: Sha256,
    groups: Vec<[u8; 32]>,
    leaves_hash: Sha256,
}

impl Order {
    pub(crate) fn new() -> Self {
        Self {
            parts: 0,
            leaves: 0,
            length: 0,
            last_part_length: 0,
            last_leaf_entries: 0,
            root: false,
            payload_hash: Sha256::new(),
            group_hash: Sha256::new(),
            groups: Vec::new(),
            leaves_hash: Sha256::new(),
        }
    }

    pub(crate) fn append(&mut self, bytes: &[u8], txid: Txid) -> Result<(), Error> {
        ensure!(!self.root, "record follows publication root");
        match MultipartRecord::decode(bytes)? {
            MultipartRecord::Data(part) => {
                ensure!(
                    self.leaves == 0 && part.index == self.parts,
                    "noncanonical data publication order"
                );
                if self.parts > 0 {
                    ensure!(
                        self.last_part_length == Geometry::DATA_BYTES,
                        "short nonfinal data part"
                    );
                }
                self.payload_hash.update(&part.payload);
                self.group_hash.update(txid.to_byte_array());
                self.group_hash.update(Sha256::digest(bytes));
                self.last_part_length = part.payload.len();
                self.length = self
                    .length
                    .checked_add(u64::try_from(part.payload.len())?)
                    .context("payload length overflow")?;
                self.parts = self.parts.checked_add(1).context("part count overflow")?;
                if self.parts.is_multiple_of(u32::from(Geometry::FANOUT)) {
                    self.groups.push(self.group_hash.finalize_reset().into());
                }
            }
            MultipartRecord::Leaf(leaf) => {
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
                self.leaves_hash.update(txid.to_byte_array());
                self.leaves_hash.update(Sha256::digest(bytes));
                self.last_leaf_entries = leaf.entries.len();
                self.leaves = self.leaves.checked_add(1).context("leaf count overflow")?;
            }
            MultipartRecord::Root(root) => {
                ensure!(
                    root.payload_hash == <[u8; 32]>::from(self.payload_hash.clone().finalize()),
                    "root payload hash mismatch"
                );
                ensure!(
                    references_hash(&root.entries)
                        == <[u8; 32]>::from(self.leaves_hash.clone().finalize()),
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
                self.root = true;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&self, count: u32) -> Result<(), Error> {
        ensure!(
            self.root && Geometry::new(self.length)?.nodes() == count,
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
