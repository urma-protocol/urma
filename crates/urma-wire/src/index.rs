use crate::reader::Reader;
use bitcoin::{Block, BlockHash, Transaction};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, path::Path};
use urma::error::{Error, ensure};
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub height: u64,
    pub position: u32,
    pub txid: String,
    pub author: String,
    pub record: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    pub format: String,
    pub genesis: String,
    pub start: u64,
    pub blocks: Vec<Checkpoint>,
    pub entries: Vec<Entry>,
}
#[derive(Serialize)]
pub struct SyncReport {
    pub scanned: u64,
    pub rolled_back: u64,
    pub records: usize,
    pub tip: u64,
    pub complete_to_tip: bool,
}
impl Index {
    pub const MAX_BYTES: usize = 64 * 1024 * 1024;
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = urma::storage::read_bounded(path, Self::MAX_BYTES)?;
        let index: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            index.format == "URMA-WIRE-INDEX-1",
            "unsupported Wire index"
        );
        ensure!(index.blocks.len() <= 500_000, "Wire checkpoint capacity");
        ensure!(index.entries.len() <= 50_000, "Wire record capacity");
        for (offset, block) in index.blocks.iter().enumerate() {
            ensure!(
                block.height
                    == index
                        .start
                        .checked_add(u64::try_from(offset)?)
                        .ok_or_else(|| Error::Capacity("checkpoint overflow".into()))?,
                "noncontiguous index checkpoints"
            );
            block.hash.parse::<BlockHash>()?;
        }
        for entry in &index.entries {
            PublicRecord::decode(&hex::decode(&entry.record)?)?;
            entry.txid.parse::<bitcoin::Txid>()?;
            entry.author.parse::<bitcoin::XOnlyPublicKey>()?;
        }
        Ok(index)
    }
    pub fn persist(&self, path: &Path) -> Result<(), Error> {
        ensure!(
            self.blocks.len() <= 500_000 && self.entries.len() <= 50_000,
            "Wire index capacity"
        );
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= Self::MAX_BYTES, "Wire index byte capacity");
        let parent = urma::config::output_parent(path);
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

pub fn sync(
    reader: &impl Reader,
    path: &Path,
    start: u64,
    max_blocks: u64,
) -> Result<SyncReport, Error> {
    ensure!(
        (1..=10_000).contains(&max_blocks),
        "max blocks must be 1..10000"
    );
    let genesis = reader.genesis()?.to_string();
    let mut index = if path.exists() {
        Index::load(path)?
    } else {
        Index {
            format: "URMA-WIRE-INDEX-1".into(),
            genesis: genesis.clone(),
            start,
            blocks: Vec::new(),
            entries: Vec::new(),
        }
    };
    ensure!(
        index.genesis == genesis && index.start == start,
        "index chain/start mismatch"
    );
    let tip = reader.tip_height()?;
    let rolled_back = rollback(reader, &mut index, tip)?;
    index.persist(path)?;
    let next = index
        .start
        .checked_add(u64::try_from(index.blocks.len())?)
        .ok_or_else(|| Error::Capacity("height overflow".into()))?;
    let mut scanned = 0;
    for height in next..=tip {
        if scanned >= max_blocks {
            break;
        }
        let block = reader.block(height)?;
        let previous_checkpoint = index.blocks.last();
        for previous in previous_checkpoint.iter() {
            ensure!(
                block.header.prev_blockhash.to_string() == previous.hash,
                "source reorg during index; retry"
            );
        }
        let entries = read_entries(reader, &block, height)?;
        ensure!(
            reader.block_hash(height)? == block.block_hash(),
            "source reorg during index; retry"
        );
        index.entries.extend(entries);
        index.blocks.push(Checkpoint {
            height,
            hash: block.block_hash().to_string(),
        });
        index.persist(path)?;
        scanned += 1;
    }
    Ok(SyncReport {
        scanned,
        rolled_back,
        records: index.entries.len(),
        tip,
        complete_to_tip: !index.blocks.is_empty()
            && next
                .checked_add(scanned)
                .ok_or_else(|| Error::Capacity("height overflow".into()))?
                == tip
                    .checked_add(1)
                    .ok_or_else(|| Error::Capacity("height overflow".into()))?,
    })
}

fn rollback(reader: &impl Reader, index: &mut Index, tip: u64) -> Result<u64, Error> {
    let mut removed = 0;
    while !index.blocks.is_empty() {
        let last = index
            .blocks
            .last()
            .ok_or_else(|| Error::Invalid("index checkpoint invariant".into()))?;
        if last.height <= tip && reader.block_hash(last.height)?.to_string() == last.hash {
            break;
        }
        let height = last.height;
        index.entries.retain(|entry| entry.height < height);
        index.blocks.pop();
        removed += 1;
    }
    Ok(removed)
}

fn read_entries(reader: &impl Reader, block: &Block, height: u64) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    for (position, tx) in block.txdata.iter().enumerate() {
        if tx.input.len() != 1
            || !tx.input[0]
                .witness
                .iter()
                .any(|item| item.windows(4).any(|bytes| bytes == b"URMA"))
        {
            continue;
        }
        let candidate = match envelope::extract_reveal(tx) {
            Ok(parsed) => parsed,
            Err(cause) => {
                tracing::warn!(%cause, "candidate is not a supported URMA reveal");
                continue;
            }
        };
        match RecordKind::parse(&candidate.record)? {
            RecordKind::Post | RecordKind::Reply | RecordKind::Profile | RecordKind::Avatar => {}
            other => {
                tracing::trace!(?other, "non-Wire URMA record");
                continue;
            }
        }
        let commit = reader.transaction(tx.input[0].previous_output.txid)?;
        match verified_entry(tx, &commit, height, u32::try_from(position)?) {
            Ok(entry) => entries.push(entry),
            Err(cause) => tracing::warn!(%cause, "rejected Wire author proof"),
        }
    }
    Ok(entries)
}
fn verified_entry(
    tx: &Transaction,
    commit: &Transaction,
    height: u64,
    position: u32,
) -> Result<Entry, Error> {
    let parsed = envelope::verify_reveal(tx, commit)?;
    PublicRecord::decode(&parsed.record)?;
    Ok(Entry {
        height,
        position,
        txid: tx.compute_txid().to_string(),
        author: parsed.author.to_string(),
        record: hex::encode(parsed.record),
    })
}
