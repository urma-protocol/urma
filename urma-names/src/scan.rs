use crate::{
    engine::Registry,
    error::{NamesError, ScanError, ensure_names},
    index::{Checkpoint, NamesIndex, WindowBlock},
    payload::Payload,
    state::{Commit, Observation, Outcome, Verdict},
};
use bitcoin::{Block, BlockHash, Transaction, Txid};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use urma_chain::validation::validate_block_integrity;
use urma_core::{
    envelope::{self, ParsedEnvelope},
    format::{PublicRecord, RecordKind},
};

pub trait Source {
    type Error: std::error::Error + 'static;

    fn genesis(&self) -> Result<BlockHash, Self::Error>;
    fn tip_height(&self) -> Result<u64, Self::Error>;
    fn block_hash(&self, height: u64) -> Result<BlockHash, Self::Error>;
    fn block(&self, height: u64) -> Result<Block, Self::Error>;
    fn transaction(&self, txid: Txid) -> Result<Transaction, Self::Error>;
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannedRecord {
    pub height: u64,
    pub txid: String,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
    pub network: String,
    pub genesis: String,
    pub genesis_height: u64,
    pub genesis_hash: String,
    pub scanned: u64,
    pub rolled_back: u64,
    pub height: u64,
    pub tip: u64,
    pub complete_to_tip: bool,
    pub names: usize,
    pub pending: usize,
    pub records: Vec<ScannedRecord>,
}

pub struct Registration<'a> {
    pub network: &'a str,
    pub genesis: Txid,
    pub genesis_height: u64,
}

pub enum CommitLocation {
    Known { height: u64, position: u32 },
    Unknown,
}

struct Locator {
    blocks: BTreeMap<u64, BTreeMap<Txid, u32>>,
}

impl Locator {
    fn from_index(index: &NamesIndex) -> Result<Self, NamesError> {
        let mut blocks = BTreeMap::new();
        for block in &index.window {
            let mut commits = BTreeMap::new();
            for (txid, position) in &block.commits {
                commits.insert(txid.parse::<Txid>()?, *position);
            }
            blocks.insert(block.height, commits);
        }
        Ok(Self { blocks })
    }

    fn push(&mut self, height: u64, commits: &[(Txid, u32)]) {
        self.blocks
            .insert(height, commits.iter().copied().collect());
    }

    fn trim(&mut self, next: u64, window_blocks: u16) {
        self.blocks.retain(|height, _commits| {
            u128::from(*height) + u128::from(window_blocks) >= u128::from(next)
        });
    }

    fn locate(&self, txid: Txid) -> CommitLocation {
        for (height, commits) in &self.blocks {
            let Some(position) = commits.get(&txid) else {
                continue;
            };
            return CommitLocation::Known {
                height: *height,
                position: *position,
            };
        }
        CommitLocation::Unknown
    }
}

pub fn sync<S: Source>(
    source: &S,
    path: &Path,
    registration: Registration<'_>,
    max_blocks: u64,
) -> Result<ScanReport, ScanError<S::Error>> {
    ensure_names!(
        (1..=10_000).contains(&max_blocks),
        "max blocks must be 1..10000"
    );
    let chain_genesis = source.genesis().map_err(ScanError::Source)?.to_string();
    let mut index = if path.exists() {
        NamesIndex::load(path)?
    } else {
        let (registry, genesis_hash) =
            verify_genesis(source, registration.genesis, registration.genesis_height)?;
        NamesIndex::new(
            registration.network,
            chain_genesis.clone(),
            genesis_hash.to_string(),
            registry,
        )
    };
    ensure_names!(
        index.network == registration.network
            && index.chain_genesis == chain_genesis
            && index.registry.genesis() == registration.genesis
            && index.registry.genesis_height() == registration.genesis_height,
        "names index belongs to another network, chain or registry"
    );
    anchor(source, &index)?;
    let tip = source.tip_height().map_err(ScanError::Source)?;
    let rolled_back = rollback(source, &mut index, tip)?;
    if rolled_back > 0 {
        rebuild_window(source, &mut index)?;
    }
    index.persist(path)?;
    let mut locator = Locator::from_index(&index)?;
    let mut records = Vec::new();
    let mut scanned = 0;
    while scanned < max_blocks {
        let height = index
            .registry
            .height()
            .checked_add(1)
            .ok_or_else(|| NamesError::Invalid("height overflow".into()))?;
        if height > tip {
            break;
        }
        for outcome in scan_block(source, &mut index, &mut locator, height)? {
            records.push(ScannedRecord {
                height,
                txid: outcome.txid.to_string(),
                verdict: outcome.verdict,
            });
        }
        index.persist(path)?;
        scanned += 1;
    }
    Ok(ScanReport {
        network: index.network.clone(),
        genesis: registration.genesis.to_string(),
        genesis_height: registration.genesis_height,
        genesis_hash: index.genesis_hash.clone(),
        scanned,
        rolled_back,
        height: index.registry.height(),
        tip,
        complete_to_tip: index.registry.height() == tip,
        names: index.registry.names().len(),
        pending: index.registry.pending().len(),
        records,
    })
}

fn fetch_block<S: Source>(source: &S, height: u64) -> Result<Block, ScanError<S::Error>> {
    let block = source.block(height).map_err(ScanError::Source)?;
    let expected = source.block_hash(height).map_err(ScanError::Source)?;
    validate_block_integrity(&block, expected)?;
    Ok(block)
}

fn anchor<S: Source>(source: &S, index: &NamesIndex) -> Result<(), ScanError<S::Error>> {
    let height = index.registry.genesis_height();
    let tip = source.tip_height().map_err(ScanError::Source)?;
    ensure_names!(
        height <= tip
            && source
                .block_hash(height)
                .map_err(ScanError::Source)?
                .to_string()
                == index.genesis_hash,
        "registry genesis block {} is not on the current chain at height {height}; the genesis was orphaned or the height is wrong, delete the names index",
        index.genesis_hash
    );
    Ok(())
}

fn verify_genesis<S: Source>(
    source: &S,
    genesis: Txid,
    height: u64,
) -> Result<(Registry, BlockHash), ScanError<S::Error>> {
    let block = fetch_block(source, height)?;
    let Some(tx) = block.txdata.iter().find(|tx| tx.compute_txid() == genesis) else {
        return Err(
            NamesError::Missing(format!("genesis {genesis} is not in block {height}")).into(),
        );
    };
    ensure_names!(tx.input.len() == 1, "genesis reveal must have one input");
    let commit = source
        .transaction(tx.input[0].previous_output.txid)
        .map_err(ScanError::Source)?;
    let parsed = envelope::verify_reveal(tx, &commit)?;
    let Payload::Genesis(rules) = Payload::from_record(&PublicRecord::decode(&parsed.record)?)?
    else {
        return Err(NamesError::Invalid("genesis record is not a names genesis".into()).into());
    };
    Ok((Registry::new(genesis, height, rules)?, block.block_hash()))
}

fn rollback<S: Source>(
    source: &S,
    index: &mut NamesIndex,
    tip: u64,
) -> Result<u64, ScanError<S::Error>> {
    let mut removed = 0;
    loop {
        let last = index.blocks.last();
        let Some(checkpoint) = last else {
            break;
        };
        let height = checkpoint.height;
        if height <= tip
            && source
                .block_hash(height)
                .map_err(ScanError::Source)?
                .to_string()
                == checkpoint.hash
        {
            break;
        }
        ensure_names!(
            index.registry.reversible_blocks() > 0,
            "reorg deeper than the reversible window; delete the names index and rescan"
        );
        index.blocks.truncate(index.blocks.len() - 1);
        ensure_names!(
            index.registry.disconnect()? == height,
            "names checkpoints and registry diverged"
        );
        removed += 1;
    }
    ensure_names!(
        !index.blocks.is_empty() || index.registry.height() == index.registry.genesis_height(),
        "reorg deeper than the reversible window; delete the names index and rescan"
    );
    Ok(removed)
}

fn commit_candidates(block: &Block) -> Result<Vec<(Txid, u32)>, NamesError> {
    let mut commits = Vec::new();
    for (position, tx) in block.txdata.iter().enumerate() {
        if tx
            .output
            .iter()
            .any(|output| output.script_pubkey.is_p2tr())
        {
            commits.push((tx.compute_txid(), u32::try_from(position)?));
        }
    }
    Ok(commits)
}

fn window_block(block: &Block, height: u64) -> Result<WindowBlock, NamesError> {
    Ok(WindowBlock {
        height,
        commits: commit_candidates(block)?
            .iter()
            .map(|(txid, position)| (txid.to_string(), *position))
            .collect(),
    })
}

fn rebuild_window<S: Source>(
    source: &S,
    index: &mut NamesIndex,
) -> Result<(), ScanError<S::Error>> {
    let height = index.registry.height();
    let window = u64::from(index.registry.rules().reveal_max_blocks);
    let genesis_height = index.registry.genesis_height();
    let floor = if u128::from(height) > u128::from(genesis_height) + u128::from(window) {
        height - window
    } else {
        genesis_height
    };
    index.window.clear();
    let mut at = floor
        .checked_add(1)
        .ok_or_else(|| NamesError::Invalid("height overflow".into()))?;
    while at <= height {
        let block = fetch_block(source, at)?;
        index.window.push(window_block(&block, at)?);
        at = at
            .checked_add(1)
            .ok_or_else(|| NamesError::Invalid("height overflow".into()))?;
    }
    Ok(())
}

fn scan_block<S: Source>(
    source: &S,
    index: &mut NamesIndex,
    locator: &mut Locator,
    height: u64,
) -> Result<Vec<Outcome>, ScanError<S::Error>> {
    let block = fetch_block(source, height)?;
    let last = index.blocks.last();
    for previous in last.iter() {
        ensure_names!(
            block.header.prev_blockhash.to_string() == previous.hash,
            "source reorg during scan; retry"
        );
    }
    if index.blocks.is_empty() {
        ensure_names!(
            block.header.prev_blockhash.to_string() == index.genesis_hash,
            "source reorg during scan; retry"
        );
    }
    let commits = commit_candidates(&block)?;
    locator.push(height, &commits);
    let observations = observations(source, locator, &block, height)?;
    ensure_names!(
        source.block_hash(height).map_err(ScanError::Source)? == block.block_hash(),
        "source reorg during scan; retry"
    );
    let outcomes = index.registry.connect(height, observations)?;
    index.window.push(window_block(&block, height)?);
    index.blocks.push(Checkpoint {
        height,
        hash: block.block_hash().to_string(),
    });
    let window_blocks = index.registry.rules().reveal_max_blocks;
    index.trim(window_blocks);
    locator.trim(
        height
            .checked_add(1)
            .ok_or_else(|| NamesError::Invalid("height overflow".into()))?,
        window_blocks,
    );
    Ok(outcomes)
}

fn names_payload(tx: &Transaction) -> Result<Payload, NamesError> {
    let parsed = envelope::extract_reveal(tx)?;
    ensure_names!(
        RecordKind::parse(&parsed.record)? == RecordKind::ProfileRecord,
        "not a profile record"
    );
    Ok(Payload::from_record(&PublicRecord::decode(
        &parsed.record,
    )?)?)
}

fn observations<S: Source>(
    source: &S,
    locator: &Locator,
    block: &Block,
    height: u64,
) -> Result<Vec<Observation>, ScanError<S::Error>> {
    let mut observations = Vec::new();
    for (position, tx) in block.txdata.iter().enumerate() {
        if tx.input.len() != 1 || !envelope::is_candidate(&tx.input[0].witness) {
            continue;
        }
        let payload = match names_payload(tx) {
            Ok(payload) => payload,
            Err(cause) => {
                tracing::warn!(error = %cause, txid = %tx.compute_txid(), "URMA candidate is not a names record");
                continue;
            }
        };
        let outpoint = tx.input[0].previous_output;
        let CommitLocation::Known {
            height: commit_height,
            position: commit_position,
        } = locator.locate(outpoint.txid)
        else {
            tracing::warn!(txid = %tx.compute_txid(), "names reveal spends a commit outside the window");
            continue;
        };
        let commit = source
            .transaction(outpoint.txid)
            .map_err(ScanError::Source)?;
        let verified: ParsedEnvelope = match envelope::verify_reveal(tx, &commit) {
            Ok(verified) => verified,
            Err(cause) => {
                tracing::warn!(error = %cause, txid = %tx.compute_txid(), "names reveal failed the author proof");
                continue;
            }
        };
        observations.push(Observation {
            txid: tx.compute_txid(),
            author: verified.author,
            record_sha256: Sha256::digest(&verified.record).into(),
            payload,
            height,
            position: u32::try_from(position)?,
            commit: Commit {
                txid: outpoint.txid,
                vout: outpoint.vout,
                height: commit_height,
                position: commit_position,
            },
        });
    }
    Ok(observations)
}
