use super::{Geometry, LeafManifest, RootManifest};
use crate::error::{Error, ensure};
use bitcoin::Txid;
use std::collections::HashSet;

pub struct ManifestInventory {
    geometry: Geometry,
    next_leaf: u16,
    seen: HashSet<Txid>,
}

impl ManifestInventory {
    pub fn new(root_txid: Txid, manifest: &RootManifest) -> Result<Self, Error> {
        let geometry = manifest.geometry()?;
        let mut seen = HashSet::new();
        seen.try_reserve(usize::try_from(geometry.nodes())?)?;
        seen.insert(root_txid);
        for reference in &manifest.entries {
            ensure!(
                seen.insert(reference.txid),
                "duplicate or cyclic root reference"
            );
        }
        Ok(Self {
            geometry,
            next_leaf: 0,
            seen,
        })
    }

    pub fn accept_leaf(&mut self, leaf: &LeafManifest) -> Result<(), Error> {
        leaf.validate()?;
        ensure!(leaf.index == self.next_leaf, "leaf order mismatch");
        ensure!(
            leaf.entries.len() == usize::from(self.geometry.leaf_entries(self.next_leaf)?),
            "leaf count disagrees with root"
        );
        let mut additions = HashSet::new();
        additions.try_reserve(leaf.entries.len())?;
        for reference in &leaf.entries {
            ensure!(
                !self.seen.contains(&reference.txid) && additions.insert(reference.txid),
                "duplicate or cyclic data reference"
            );
        }
        self.seen.extend(additions);
        self.next_leaf += 1;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.next_leaf == self.geometry.leaves()
    }
}
