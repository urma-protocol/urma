use urma::error::{Context, Error, ensure};
use urma_core::multipart::{Geometry, MultipartRecord};

pub(crate) struct Order {
    parts: u32,
    leaves: u16,
    length: u64,
    last_part_length: usize,
    last_leaf_entries: usize,
    root: bool,
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
        }
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
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
                self.last_part_length = part.payload.len();
                self.length = self
                    .length
                    .checked_add(u64::try_from(part.payload.len())?)
                    .context("payload length overflow")?;
                self.parts = self.parts.checked_add(1).context("part count overflow")?;
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
                self.last_leaf_entries = leaf.entries.len();
                self.leaves = self.leaves.checked_add(1).context("leaf count overflow")?;
            }
            MultipartRecord::Root(root) => {
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
