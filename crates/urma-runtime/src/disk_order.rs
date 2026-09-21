use crate::error::{Error, ensure};
use bitcoin::Txid;
use urma_core::{format::RecordKind, multipart::MultipartConsistency};

pub(crate) struct Order {
    consistency: MultipartConsistency,
    leaves: bool,
    root: bool,
}

impl Order {
    pub(crate) fn new() -> Self {
        Self {
            consistency: MultipartConsistency::new(),
            leaves: false,
            root: false,
        }
    }

    pub(crate) fn append(&mut self, bytes: &[u8], txid: Txid) -> Result<(), Error> {
        ensure!(!self.root, "record follows publication root");
        let kind = RecordKind::parse(bytes)?;
        if kind == RecordKind::DataPart {
            ensure!(!self.leaves, "noncanonical data publication order");
        }
        self.consistency.accept(bytes, txid)?;
        self.leaves |= kind == RecordKind::LeafManifest;
        self.root = kind == RecordKind::RootManifest;
        Ok(())
    }

    pub(crate) fn finish(&self, count: u32) -> Result<(), Error> {
        ensure!(self.root, "publication root or geometry missing");
        Ok(self.consistency.validate_count(count)?)
    }
}
