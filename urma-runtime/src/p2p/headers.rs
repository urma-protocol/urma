use crate::config::{
    Checkpoint, LITECOIN_MAINNET_CHECKPOINT, LITECOIN_TESTNET_CHECKPOINT, P2P_HEADER_CACHE_MAX,
    P2P_HEADER_CACHE_REVALIDATE, P2P_LOCATOR_LINEAR, P2P_MAX_FUTURE_SECS, P2P_MEDIAN_TIME_SPAN,
    P2P_POW_WORKERS,
};
use crate::error::{Context, Error, ensure};
use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use urma_chain::observation::Chain;
use urma_chain::pow::{chain_work, check_header_pow, expected_bits};

pub struct HeaderChain {
    chain: Chain,
    start_height: u64,
    trusted_next: BlockHash,
    headers: Vec<Header>,
    index: HashMap<BlockHash, usize>,
    path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Extension {
    Appended(usize),
    Reorganized { fork_height: u64, appended: usize },
    Ignored,
}

pub fn checkpoint(chain: Chain) -> Result<&'static Checkpoint, Error> {
    match chain {
        Chain::LitecoinMainnet => Ok(&LITECOIN_MAINNET_CHECKPOINT),
        Chain::LitecoinTestnet => Ok(&LITECOIN_TESTNET_CHECKPOINT),
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => Err(Error::Unsupported(
            "the peer-to-peer light client serves Litecoin networks only".into(),
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub header: Header,
    pub next_hash: BlockHash,
}

impl Anchor {
    pub fn embedded(chain: Chain) -> Result<Self, Error> {
        let checkpoint = checkpoint(chain)?;
        Ok(Self {
            height: checkpoint.height,
            header: deserialize(&hex::decode(checkpoint.header)?)?,
            next_hash: checkpoint.next_hash.parse()?,
        })
    }
}

impl HeaderChain {
    pub fn open(chain: Chain, cache_dir: &Path) -> Result<Self, Error> {
        Self::open_at(chain, cache_dir, Anchor::embedded(chain)?)
    }

    pub fn open_at(chain: Chain, cache_dir: &Path, anchor: Anchor) -> Result<Self, Error> {
        let path = cache_dir.join(format!("{}-headers.bin", chain.label().replace(' ', "-")));
        Self::anchored(chain, path, anchor.height, anchor.header, anchor.next_hash)
    }

    pub fn anchored(
        chain: Chain,
        path: PathBuf,
        start_height: u64,
        anchor: Header,
        trusted_next: BlockHash,
    ) -> Result<Self, Error> {
        check_header_pow(&anchor, chain).map_err(|cause| Error::Invalid(cause.to_string()))?;
        let mut fresh = Self {
            chain,
            start_height,
            trusted_next,
            headers: vec![anchor],
            index: HashMap::from([(anchor.block_hash(), 0)]),
            path,
        };
        if fresh.path.try_exists()? {
            match fresh.load() {
                Ok(()) => (),
                Err(error) => {
                    tracing::warn!(%error, path = %fresh.path.display(), "header cache rejected; restarting from the checkpoint");
                    fresh.reset()?;
                }
            }
        }
        Ok(fresh)
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.headers.truncate(1);
        self.index = HashMap::from([(self.headers[0].block_hash(), 0)]);
        std::fs::remove_file(&self.path)?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), Error> {
        let raw = urma_io::read_bounded(&self.path, P2P_HEADER_CACHE_MAX * Header::SIZE)?;
        ensure!(
            raw.len() % Header::SIZE == 0 && raw.len() >= Header::SIZE,
            "header cache {} is not a whole number of headers",
            self.path.display()
        );
        let stored: Header = deserialize(&raw[..Header::SIZE])?;
        ensure!(
            stored == self.headers[0],
            "header cache {} starts from a different checkpoint",
            self.path.display()
        );
        let count = raw.len() / Header::SIZE;
        let mut headers = Vec::new();
        headers.try_reserve_exact(count)?;
        for slice in raw.chunks_exact(Header::SIZE) {
            headers.push(deserialize::<Header>(slice)?);
        }
        let revalidate_from = count.max(P2P_HEADER_CACHE_REVALIDATE) - P2P_HEADER_CACHE_REVALIDATE;
        for (offset, header) in headers.iter().enumerate().skip(1) {
            ensure!(
                header.prev_blockhash == headers[offset - 1].block_hash(),
                "header cache {} breaks continuity at offset {offset}",
                self.path.display()
            );
            if offset == 1 {
                ensure!(
                    header.block_hash() == self.trusted_next,
                    "header cache {} diverges from the checkpoint",
                    self.path.display()
                );
            }
        }
        prove_batch(self.chain, &headers[revalidate_from.max(1)..])?;
        self.index = headers
            .iter()
            .enumerate()
            .map(|(offset, header)| (header.block_hash(), offset))
            .collect();
        self.headers = headers;
        Ok(())
    }

    pub fn persist(&self) -> Result<(), Error> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(self.headers.len() * Header::SIZE)?;
        for header in &self.headers {
            raw.extend_from_slice(&serialize(header));
        }
        urma_io::write_replace(&self.path, &raw)?;
        Ok(())
    }

    pub fn chain(&self) -> Chain {
        self.chain
    }

    pub fn start_height(&self) -> u64 {
        self.start_height
    }

    pub fn tip_height(&self) -> u64 {
        self.start_height + self.offset_count()
    }

    pub fn synced_count(&self) -> u64 {
        self.offset_count()
    }

    fn offset_count(&self) -> u64 {
        match u64::try_from(self.headers.len() - 1) {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(%error, "header count exceeds u64");
                u64::MAX
            }
        }
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.headers[self.headers.len() - 1].block_hash()
    }

    pub fn height_of(&self, hash: BlockHash) -> Result<u64, Error> {
        let offset = *self
            .index
            .get(&hash)
            .with_context(|| format!("block {hash} is not in the verified header chain"))?;
        Ok(self.start_height + u64::try_from(offset)?)
    }

    pub fn header_at(&self, height: u64) -> Result<Header, Error> {
        let offset = height
            .checked_sub(self.start_height)
            .with_context(|| format!("height {height} precedes the light client checkpoint"))?;
        let offset = usize::try_from(offset)?;
        self.headers
            .get(offset)
            .copied()
            .with_context(|| format!("height {height} is above the verified header tip"))
    }

    pub fn hash_at(&self, height: u64) -> Result<BlockHash, Error> {
        Ok(self.header_at(height)?.block_hash())
    }

    pub fn locator(&self) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let mut back = self.headers.len() - 1;
        let mut step = 1;
        loop {
            hashes.push(self.headers[back].block_hash());
            if back == 0 {
                break;
            }
            if hashes.len() > P2P_LOCATOR_LINEAR {
                step *= 2;
            }
            back = back.max(step) - step;
        }
        hashes
    }

    pub fn extend(&mut self, batch: &[Header], now: u32) -> Result<Extension, Error> {
        let Some(first) = batch.first() else {
            return Ok(Extension::Ignored);
        };
        let fork = *self
            .index
            .get(&first.prev_blockhash)
            .context("peer headers do not connect to the verified header chain")?;
        let known = batch
            .iter()
            .zip(self.headers.iter().skip(fork + 1))
            .take_while(|(incoming, held)| incoming.block_hash() == held.block_hash())
            .count();
        let fresh = &batch[known..];
        if fresh.is_empty() {
            return Ok(Extension::Ignored);
        }
        ensure!(
            self.headers.len() + fresh.len() <= P2P_HEADER_CACHE_MAX,
            "header chain would exceed the client capacity"
        );
        let base = fork + known;
        prove_batch(self.chain, fresh)?;
        if base == self.headers.len() - 1 {
            self.append(fresh, now)?;
            return Ok(Extension::Appended(fresh.len()));
        }
        let mut candidate = self.headers[..=base].to_vec();
        for header in fresh {
            self.validate_next(&candidate, header, now)?;
            candidate.push(*header);
        }
        let challenger = chain_work(&candidate[base + 1..])
            .map_err(|cause| Error::Invalid(cause.to_string()))?;
        let incumbent = chain_work(&self.headers[base + 1..])
            .map_err(|cause| Error::Invalid(cause.to_string()))?;
        if challenger <= incumbent {
            tracing::warn!(
                fork_offset = base,
                "peer branch carries no more work than the held chain"
            );
            return Ok(Extension::Ignored);
        }
        for dropped in &self.headers[base + 1..] {
            self.index.remove(&dropped.block_hash());
        }
        self.headers = candidate;
        for (offset, header) in self.headers.iter().enumerate().skip(base + 1) {
            self.index.insert(header.block_hash(), offset);
        }
        Ok(Extension::Reorganized {
            fork_height: self.start_height + u64::try_from(base)?,
            appended: fresh.len(),
        })
    }

    fn append(&mut self, fresh: &[Header], now: u32) -> Result<(), Error> {
        let original = self.headers.len();
        for header in fresh {
            match self.validate_next(&self.headers, header, now) {
                Ok(()) => {
                    self.index.insert(header.block_hash(), self.headers.len());
                    self.headers.push(*header);
                }
                Err(error) => {
                    for rejected in &self.headers[original..] {
                        self.index.remove(&rejected.block_hash());
                    }
                    self.headers.truncate(original);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn validate_next(&self, window: &[Header], header: &Header, now: u32) -> Result<(), Error> {
        let last = window.last().context("header window is empty")?;
        ensure!(
            header.prev_blockhash == last.block_hash(),
            "peer header does not extend its predecessor"
        );
        if window.len() == 1 {
            ensure!(
                header.block_hash() == self.trusted_next,
                "peer header after the checkpoint is not the checkpointed block"
            );
        } else {
            let required = expected_bits(self.chain, window, self.start_height, header.time)
                .map_err(|cause| Error::Invalid(cause.to_string()))?;
            ensure!(
                header.bits == required,
                "peer header bits {:08x} differ from the required {:08x}",
                header.bits.to_consensus(),
                required.to_consensus()
            );
        }
        ensure!(
            header.time > median_time(window),
            "peer header time is not after the median of the previous blocks"
        );
        let horizon = now
            .checked_add(P2P_MAX_FUTURE_SECS)
            .context("clock horizon overflow")?;
        ensure!(
            header.time <= horizon,
            "peer header time is too far in the future"
        );
        Ok(())
    }
}

pub fn prove_batch(chain: Chain, headers: &[Header]) -> Result<(), Error> {
    if headers.is_empty() {
        return Ok(());
    }
    let workers = std::thread::available_parallelism()?
        .get()
        .min(P2P_POW_WORKERS)
        .min(headers.len());
    let chunk = headers.len().div_ceil(workers);
    let verdicts: Vec<Result<(), (usize, String)>> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (slot, part) in headers.chunks(chunk).enumerate() {
            handles.push(scope.spawn(move || {
                for (offset, header) in part.iter().enumerate() {
                    check_header_pow(header, chain)
                        .map_err(|cause| (slot * chunk + offset, cause.to_string()))?;
                }
                Ok(())
            }));
        }
        let mut verdicts = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(verdict) => verdicts.push(verdict),
                Err(panic) => {
                    tracing::error!(?panic, "header proof worker panicked");
                    verdicts.push(Err((usize::MAX, "header proof worker panicked".into())));
                }
            }
        }
        verdicts
    });
    for verdict in verdicts {
        match verdict {
            Ok(()) => (),
            Err((offset, cause)) => {
                return Err(Error::Invalid(format!(
                    "header at batch offset {offset} fails proof of work: {cause}"
                )));
            }
        }
    }
    Ok(())
}

fn median_time(window: &[Header]) -> u32 {
    let start = window.len().max(P2P_MEDIAN_TIME_SPAN) - P2P_MEDIAN_TIME_SPAN;
    let mut times: Vec<u32> = window[start..].iter().map(|header| header.time).collect();
    times.sort_unstable();
    times[times.len() / 2]
}
