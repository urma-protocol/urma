use crate::config::P2P_BLOCK_CACHE_BYTES;
use bitcoin::BlockHash;
use std::collections::VecDeque;

pub(super) enum Held {
    Cached(Vec<u8>),
    Absent,
}

struct Cached {
    hash: BlockHash,
    height: u64,
    raw: Vec<u8>,
}

pub(super) struct BlockCache {
    entries: VecDeque<Cached>,
    bytes: usize,
}

impl BlockCache {
    pub(super) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
        }
    }

    pub(super) fn get(&self, hash: BlockHash) -> Held {
        let Some(entry) = self.entries.iter().find(|entry| entry.hash == hash) else {
            return Held::Absent;
        };
        Held::Cached(entry.raw.clone())
    }

    pub(super) fn insert(&mut self, hash: BlockHash, height: u64, raw: Vec<u8>) {
        if raw.len() > P2P_BLOCK_CACHE_BYTES {
            tracing::warn!(%hash, bytes = raw.len(), "block exceeds the whole cache budget; not cached");
            return;
        }
        self.entries.retain(|entry| entry.hash != hash);
        self.bytes = self.entries.iter().map(|entry| entry.raw.len()).sum();
        while self.bytes + raw.len() > P2P_BLOCK_CACHE_BYTES {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= evicted.raw.len();
        }
        self.bytes += raw.len();
        self.entries.push_back(Cached { hash, height, raw });
    }

    pub(super) fn prune_above(&mut self, height: u64) {
        self.entries.retain(|entry| entry.height <= height);
        self.bytes = self.entries.iter().map(|entry| entry.raw.len()).sum();
    }
}
