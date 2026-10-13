use crate::config::{P2P_BLOCK_PEER_TIMEOUT_SECS, P2P_PIPELINE_PER_PEER, P2P_PREFETCH_BLOCKS};
use crate::error::Error;
use crate::p2p::blocks::Held;
use crate::p2p::peer::block_hash;
use crate::p2p::peers::Peers;
use crate::p2p::worker::{Shared, admit_block, locked};
use bitcoin::BlockHash;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

struct Asked {
    address: SocketAddr,
    height: u64,
    hash: BlockHash,
    at: Instant,
}

pub(super) enum Holder {
    Peer(SocketAddr),
    Nobody,
}

enum Expected {
    At(u64),
    Unrequested,
}

#[derive(Default)]
pub(super) struct InFlight {
    asked: Vec<Asked>,
}

type Batch = (usize, Vec<(u64, BlockHash)>);

impl InFlight {
    pub(super) fn holder(&self, hash: BlockHash) -> Holder {
        for asked in self.asked.iter().filter(|asked| asked.hash == hash) {
            return Holder::Peer(asked.address);
        }
        Holder::Nobody
    }

    pub(super) fn forget(&mut self, hash: BlockHash) {
        self.asked.retain(|asked| asked.hash != hash);
    }

    pub(super) fn forget_peer(&mut self, address: SocketAddr) {
        self.asked.retain(|asked| asked.address != address);
    }

    fn contains(&self, hash: BlockHash) -> bool {
        self.asked.iter().any(|asked| asked.hash == hash)
    }

    fn forget_from(&mut self, address: SocketAddr, hash: BlockHash) {
        self.asked
            .retain(|asked| asked.address != address || asked.hash != hash);
    }

    fn expected(&self, address: SocketAddr, hash: BlockHash) -> Expected {
        let mut matching = self
            .asked
            .iter()
            .filter(|asked| asked.address == address && asked.hash == hash);
        for asked in matching.by_ref() {
            return Expected::At(asked.height);
        }
        Expected::Unrequested
    }

    fn progressed(&mut self, address: SocketAddr) {
        let now = Instant::now();
        for asked in self
            .asked
            .iter_mut()
            .filter(|asked| asked.address == address)
        {
            asked.at = now;
        }
    }

    fn expired(&self, patience: Duration) -> Vec<SocketAddr> {
        self.asked
            .iter()
            .filter(|asked| asked.at.elapsed() > patience)
            .map(|asked| asked.address)
            .collect()
    }
}

fn wanted(shared: &Shared, flight: &InFlight, from: u64, tip: u64) -> Vec<(u64, BlockHash)> {
    let headers = locked(&shared.headers, "headers");
    let blocks = locked(&shared.blocks, "blocks");
    let mut targets = Vec::new();
    let last = (from + P2P_PREFETCH_BLOCKS - 1).min(tip);
    for height in from..=last {
        let hash = match headers.hash_at(height) {
            Ok(hash) => hash,
            Err(error) => {
                tracing::warn!(height, %error, "pipeline stopped at a header the chain no longer holds");
                break;
            }
        };
        match blocks.get(hash) {
            Held::Cached(_raw) => continue,
            Held::Absent if flight.contains(hash) => continue,
            Held::Absent => targets.push((height, hash)),
        }
    }
    targets
}

fn assign(
    peers: &Peers,
    targets: Vec<(u64, BlockHash)>,
    avoid: &HashSet<SocketAddr>,
    tip: u64,
) -> Vec<Batch> {
    let mut batches: Vec<Batch> = Vec::new();
    for (turn, (height, hash)) in targets.into_iter().enumerate() {
        let queued = |index: usize, batches: &[Batch]| -> usize {
            batches
                .iter()
                .filter(|(asked, _rows)| *asked == index)
                .map(|(_asked, rows)| rows.len())
                .sum()
        };
        let holders: Vec<usize> = peers
            .order_for_block(height, tip)
            .into_iter()
            .filter(|index| !avoid.contains(&peers.connected[*index].address))
            .filter(|index| {
                turn == 0
                    || peers.connected[*index].outstanding() + queued(*index, &batches)
                        < P2P_PIPELINE_PER_PEER
            })
            .collect();
        if holders.is_empty() {
            break;
        }
        enqueue(&mut batches, holders[turn % holders.len()], (height, hash));
    }
    batches
}

fn enqueue(batches: &mut Vec<Batch>, index: usize, row: (u64, BlockHash)) {
    for (asked, rows) in batches.iter_mut() {
        if *asked == index {
            rows.push(row);
            return;
        }
    }
    batches.push((index, vec![row]));
}

pub(super) fn fill(
    shared: &Shared,
    peers: &mut Peers,
    flight: &mut InFlight,
    from: u64,
    avoid: &HashSet<SocketAddr>,
) {
    let tip = locked(&shared.headers, "headers").tip_height();
    let targets = wanted(shared, flight, from, tip);
    for (index, rows) in assign(peers, targets, avoid, tip) {
        let address = peers.connected[index].address;
        let hashes: Vec<BlockHash> = rows.iter().map(|(_height, hash)| *hash).collect();
        match peers.connected[index].ask_blocks(&hashes) {
            Ok(()) => {
                let at = Instant::now();
                flight
                    .asked
                    .extend(rows.into_iter().map(|(height, hash)| Asked {
                        address,
                        height,
                        hash,
                        at,
                    }));
            }
            Err(error) => {
                tracing::warn!(peer = %address, %error, "pipeline request failed")
            }
        }
    }
}

pub(super) fn receive(
    shared: &Shared,
    peers: &mut Peers,
    flight: &mut InFlight,
    index: usize,
    target: (u64, BlockHash),
) -> Result<Vec<u8>, Error> {
    let (height, hash) = target;
    let raw = peers.connected[index].await_block(hash)?;
    admit_block(shared, &raw, hash, height)?;
    flight.forget(hash);
    flight.progressed(peers.connected[index].address);
    settle(shared, peers, flight);
    Ok(raw)
}

fn absorb_arrivals(shared: &Shared, peers: &mut Peers, flight: &mut InFlight) -> Vec<SocketAddr> {
    let mut failed = Vec::new();
    for peer in peers.connected.iter_mut() {
        let address = peer.address;
        for hash in std::mem::take(&mut peer.lacking) {
            tracing::debug!(peer = %address, %hash, "pipeline peer lacks a block; asking elsewhere");
            flight.forget_from(address, hash);
        }
        for raw in std::mem::take(&mut peer.arrived) {
            let hash = match block_hash(&raw) {
                Ok(hash) => hash,
                Err(error) => {
                    tracing::warn!(peer = %address, %error, "pipeline block unreadable");
                    failed.push(address);
                    continue;
                }
            };
            let height = match flight.expected(address, hash) {
                Expected::At(height) => height,
                Expected::Unrequested => {
                    tracing::debug!(peer = %address, %hash, "unrequested block ignored");
                    continue;
                }
            };
            match locked(&shared.headers, "headers").hash_at(height) {
                Ok(selected) if selected == hash => (),
                Ok(selected) => {
                    tracing::debug!(height, %hash, %selected, "pipeline block left the selected chain");
                    flight.forget(hash);
                    continue;
                }
                Err(error) => {
                    tracing::warn!(height, %error, "pipeline block above the selected chain");
                    flight.forget(hash);
                    continue;
                }
            }
            match admit_block(shared, &raw, hash, height) {
                Ok(()) => {
                    flight.forget(hash);
                    flight.progressed(address);
                }
                Err(error) => {
                    tracing::warn!(peer = %address, %error, height, "pipeline block refused");
                    failed.push(address);
                }
            }
        }
    }
    failed
}

pub(super) fn settle(shared: &Shared, peers: &mut Peers, flight: &mut InFlight) {
    peers.poll_idle();
    let mut failed = absorb_arrivals(shared, peers, flight);
    failed.extend(flight.expired(Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS)));
    failed.sort_unstable();
    failed.dedup();
    for address in failed {
        flight.forget_peer(address);
        let mut index = peers.connected.len();
        while index > 0 {
            index -= 1;
            if peers.connected[index].address == address {
                tracing::warn!(peer = %address, "pipeline peer timed out or sent a bad block; dropped");
                peers.drop_peer(index);
            }
        }
    }
}
