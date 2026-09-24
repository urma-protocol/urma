use crate::{
    engine::Registry,
    error::{NamesError, ensure_names},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowBlock {
    pub height: u64,
    pub commits: Vec<(String, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesIndex {
    pub format: String,
    pub network: String,
    pub chain_genesis: String,
    pub genesis_hash: String,
    pub blocks: Vec<Checkpoint>,
    pub window: Vec<WindowBlock>,
    pub registry: Registry,
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl NamesIndex {
    pub const FORMAT: &'static str = "URMA-NAMES-INDEX-2";
    pub const MAX_BYTES: usize = 256 * 1024 * 1024;
    pub const REVERSIBLE: usize = 1000;

    pub fn new(
        network: &str,
        chain_genesis: String,
        genesis_hash: String,
        registry: Registry,
    ) -> Self {
        Self {
            format: Self::FORMAT.into(),
            network: network.to_owned(),
            chain_genesis,
            genesis_hash,
            blocks: Vec::new(),
            window: Vec::new(),
            registry,
        }
    }

    pub fn load(path: &Path) -> Result<Self, NamesError> {
        let bytes = urma_io::read_bounded(path, Self::MAX_BYTES)?;
        let index: Self = serde_json::from_slice(&bytes)?;
        ensure_names!(
            index.format == Self::FORMAT,
            "unsupported names index format"
        );
        ensure_names!(!index.network.is_empty(), "names index without a network");
        ensure_names!(
            is_hex64(&index.chain_genesis) && is_hex64(&index.genesis_hash),
            "names index anchors must be block hashes"
        );
        ensure_names!(
            index
                .blocks
                .windows(2)
                .all(|pair| u128::from(pair[0].height) + 1 == u128::from(pair[1].height)),
            "noncontiguous names checkpoints"
        );
        let last = index.blocks.last();
        for checkpoint in last.iter() {
            ensure_names!(
                checkpoint.height == index.registry.height(),
                "names checkpoint and registry height differ"
            );
        }
        ensure_names!(
            !index.blocks.is_empty() || index.registry.height() == index.registry.genesis_height(),
            "names index without checkpoints must sit at the genesis height"
        );
        ensure_names!(
            index
                .window
                .iter()
                .all(|block| block.height <= index.registry.height()),
            "names commit window is ahead of the registry"
        );
        Ok(index)
    }

    pub fn persist(&self, path: &Path) -> Result<(), NamesError> {
        let bytes = serde_json::to_vec(self)?;
        ensure_names!(bytes.len() <= Self::MAX_BYTES, "names index byte capacity");
        urma_io::write_replace(path, &bytes)?;
        Ok(())
    }

    pub fn tip_hash(&self) -> String {
        self.blocks
            .iter()
            .rev()
            .take(1)
            .map(|checkpoint| checkpoint.hash.clone())
            .collect()
    }

    pub fn trim(&mut self, window_blocks: u16) {
        let keep = usize::from(window_blocks).max(Self::REVERSIBLE);
        let Some(excess) = self.blocks.len().checked_sub(keep) else {
            return;
        };
        let kept = self.blocks.split_off(excess);
        self.blocks = kept;
        self.registry.prune(keep);
        let next = u128::from(self.registry.height()) + 1;
        self.window
            .retain(|block| u128::from(block.height) + u128::from(window_blocks) >= next);
    }
}
