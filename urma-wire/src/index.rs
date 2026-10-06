use crate::config::FETCH_WORKERS;
use crate::{Error, SyncError, ensure, reader::Reader};
use bitcoin::{Block, BlockHash, Transaction};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
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
        let bytes = urma_io::read_bounded(path, Self::MAX_BYTES)?;
        let index: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            index.format == "URMA-WIRE-INDEX-1" || index.format == "URMA-WIRE-INDEX-2",
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
        urma_io::write_replace(path, &bytes)?;
        Ok(())
    }
}

pub fn sync<R: Reader + Sync>(
    reader: &R,
    path: &Path,
    start: u64,
    max_blocks: u64,
) -> Result<(SyncReport, Index), SyncError<R::Error>>
where
    R::Error: Send,
{
    if !(1..=10_000).contains(&max_blocks) {
        return Err(Error::Invalid("max blocks must be 1..10000".into()).into());
    }
    let mut index = opened(reader, path, start)?;
    let tip = reader.tip_height().map_err(SyncError::Source)?;
    let rolled_back = rollback(reader, &mut index, tip)?;
    if rolled_back > 0 || !path.exists() {
        index.persist(path)?;
    }
    let next = index
        .start
        .checked_add(u64::try_from(index.blocks.len()).map_err(Error::from)?)
        .ok_or_else(|| Error::Capacity("height overflow".into()))?;
    let heights: Vec<u64> = (next..=tip).take(usize::try_from(max_blocks).map_err(Error::from)?).collect();
    let fetched = fetch_in_parallel(reader, &heights)?;
    let scanned = apply_in_order(reader, &mut index, heights.iter().copied().zip(fetched))?;
    if scanned > 0 {
        index.persist(path)?;
    }
    Ok((
        SyncReport {
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
        },
        index,
    ))
}

fn opened<R: Reader>(reader: &R, path: &Path, start: u64) -> Result<Index, SyncError<R::Error>> {
    let genesis = reader.genesis().map_err(SyncError::Source)?.to_string();
    let mut index = if path.exists() {
        Index::load(path)?
    } else {
        Index {
            format: "URMA-WIRE-INDEX-2".into(),
            genesis: genesis.clone(),
            start,
            blocks: Vec::new(),
            entries: Vec::new(),
        }
    };
    if index.genesis != genesis || index.start != start {
        return Err(Error::Invalid("index chain/start mismatch".into()).into());
    }
    if index.format == "URMA-WIRE-INDEX-1" {
        index.blocks.clear();
        index.entries.clear();
        index.format = "URMA-WIRE-INDEX-2".into();
    }
    Ok(index)
}

fn fetch_in_parallel<R: Reader + Sync>(
    reader: &R,
    heights: &[u64],
) -> Result<Vec<(Block, BlockHash)>, SyncError<R::Error>>
where
    R::Error: Send,
{
    let cursor = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let (answers, inbox) = mpsc::channel::<(usize, Result<(Block, BlockHash), R::Error>)>();
    let mut slots: Vec<Option<Result<(Block, BlockHash), R::Error>>> =
        std::iter::repeat_with(|| None).take(heights.len()).collect();
    std::thread::scope(|scope| {
        for _worker in 0..FETCH_WORKERS.min(heights.len()) {
            let answers = answers.clone();
            let cursor = &cursor;
            let failed = &failed;
            scope.spawn(move || {
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let position = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(height) = heights.get(position) else {
                        break;
                    };
                    let answer = reader.block(*height);
                    match &answer {
                        Ok(_pair) => (),
                        Err(cause) => {
                            tracing::warn!(error = %cause, height, "block fetch failed; the batch stops here");
                            failed.store(true, Ordering::Relaxed);
                        }
                    }
                    match answers.send((position, answer)) {
                        Ok(()) => (),
                        Err(cause) => {
                            tracing::warn!(error = %cause, "batch collector gone; fetch worker stops");
                            break;
                        }
                    }
                }
            });
        }
        drop(answers);
        for (position, answer) in inbox {
            let Some(slot) = slots.get_mut(position) else {
                continue;
            };
            *slot = Some(answer);
        }
    });
    let mut blocks = Vec::with_capacity(heights.len());
    for slot in slots {
        match slot {
            Some(Ok(pair)) => blocks.push(pair),
            Some(Err(cause)) => return Err(SyncError::Source(cause)),
            None => break,
        }
    }
    Ok(blocks)
}

fn apply_in_order<R: Reader>(
    reader: &R,
    index: &mut Index,
    batch: impl Iterator<Item = (u64, (Block, BlockHash))>,
) -> Result<u64, SyncError<R::Error>> {
    let mut scanned = 0;
    let mut applied: Option<(u64, BlockHash)> = None;
    for (height, (block, hash)) in batch {
        if block.block_hash() != hash {
            return Err(Error::Invalid(
                "reader returned a block whose hash differs from its verified hash".into(),
            )
            .into());
        }
        let previous_checkpoint = index.blocks.last();
        for previous in previous_checkpoint.iter() {
            if block.header.prev_blockhash.to_string() != previous.hash {
                return Err(Error::Invalid("source reorg during index; retry".into()).into());
            }
        }
        let entries = read_entries(reader, &block, height)?;
        index.entries.extend(entries);
        index.blocks.push(Checkpoint {
            height,
            hash: hash.to_string(),
        });
        applied = Some((height, hash));
        scanned += 1;
    }
    for (height, hash) in applied.iter() {
        if reader.block_hash(*height).map_err(SyncError::Source)? != *hash {
            return Err(Error::Invalid("source reorg during index; retry".into()).into());
        }
    }
    Ok(scanned)
}

fn rollback<R: Reader>(
    reader: &R,
    index: &mut Index,
    tip: u64,
) -> Result<u64, SyncError<R::Error>> {
    let mut removed = 0;
    while !index.blocks.is_empty() {
        let last = index
            .blocks
            .last()
            .ok_or_else(|| Error::Invalid("index checkpoint invariant".into()))?;
        if last.height <= tip
            && reader
                .block_hash(last.height)
                .map_err(SyncError::Source)?
                .to_string()
                == last.hash
        {
            break;
        }
        let height = last.height;
        index.entries.retain(|entry| entry.height < height);
        index.blocks.pop();
        removed += 1;
    }
    Ok(removed)
}

fn read_entries<R: Reader>(
    reader: &R,
    block: &Block,
    height: u64,
) -> Result<Vec<Entry>, SyncError<R::Error>> {
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
                tracing::warn!(error = %cause, "candidate is not a supported URMA reveal");
                continue;
            }
        };
        match RecordKind::parse(&candidate.record).map_err(Error::from)? {
            RecordKind::Post
            | RecordKind::Reply
            | RecordKind::Profile
            | RecordKind::Avatar
            | RecordKind::WirePost
            | RecordKind::WireReply => {}
            other => {
                tracing::trace!(?other, "non-Wire URMA record");
                continue;
            }
        }
        let commit = reader
            .transaction(tx.input[0].previous_output.txid)
            .map_err(SyncError::Source)?;
        match verified_entry(
            tx,
            &commit,
            height,
            u32::try_from(position).map_err(Error::from)?,
        ) {
            Ok(entry) => entries.push(entry),
            Err(cause) => tracing::warn!(error = %cause, "rejected Wire author proof"),
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
    let parsed = urma_profiles::wire::verify(tx, commit)?;
    Ok(Entry {
        height,
        position,
        txid: tx.compute_txid().to_string(),
        author: parsed.author().0.to_string(),
        record: hex::encode(parsed.raw_record()),
    })
}
