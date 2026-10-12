//! Raw commit parents from configured URMA peers over the overlay.
use crate::{
    Error,
    peer::PeerSource,
    source::{CommitSource, check_cancelled, verify_parent},
};
use bitcoin::Txid;
use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;

/// A metadata-bound parent reply. Hex length is checked, bytes are not yet.
pub(crate) enum Parent {
    Hex(String),
    /// Missing, TooLarge, WrongNetwork or UnsupportedVersion: definitive answers.
    Absent,
    Busy,
}

/// Tries up to PEERS_PER_FETCH configured peers from a rotating start. Bytes
/// are bound to the TXID only for fairness across peers; Engine verifies.
pub struct OverlayCommitSource {
    chain: Chain,
    peers: Vec<PeerSource>,
    next: AtomicUsize,
}

impl OverlayCommitSource {
    const PEERS_PER_FETCH: usize = 8;
    const FETCH_DEADLINE: Duration = Duration::from_secs(20);

    pub(crate) fn new(chain: Chain, peers: Vec<PeerSource>) -> Self {
        Self {
            chain,
            peers,
            next: AtomicUsize::new(0),
        }
    }
}

impl CommitSource for OverlayCommitSource {
    fn chain(&self) -> Chain {
        self.chain
    }

    /// Busy, local or remote, is no answer. Zero answers plus any other peer or
    /// transport error is an error; otherwise absence. First valid parent wins.
    fn fetch(&self, txid: Txid, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        check_cancelled(cancelled)?;
        let count = self.peers.len();
        if count == 0 {
            return Ok(None);
        }
        let deadline = Instant::now() + Self::FETCH_DEADLINE;
        let start = self.next.fetch_add(1, Ordering::Relaxed) % count;
        let mut answered = false;
        let mut failure = None;
        for offset in 0..count.min(Self::PEERS_PER_FETCH) {
            check_cancelled(cancelled)?;
            if Instant::now() >= deadline {
                break;
            }
            match self.peers[(start + offset) % count].parent(txid, deadline) {
                Ok(Parent::Hex(hex)) => match self.decode(&hex, txid) {
                    Ok(raw) => return Ok(Some(raw)),
                    Err(error) => failure = Some(error),
                },
                Ok(Parent::Absent) => answered = true,
                Ok(Parent::Busy) | Err(Error::Busy(_)) => (),
                Err(error) => failure = Some(error),
            }
        }
        match failure {
            Some(error) if !answered => Err(Error::CommitSource(format!("overlay: {error}"))),
            _ => Ok(None),
        }
    }
}

impl OverlayCommitSource {
    fn decode(&self, hex: &str, txid: Txid) -> Result<Vec<u8>, Error> {
        if !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(Error::Invalid("peer parent must be lowercase hex".into()));
        }
        let raw = hex::decode(hex)
            .map_err(|error| Error::Invalid(format!("peer parent hex: {error}")))?;
        verify_parent(self.chain, txid, &raw)?;
        Ok(raw)
    }
}
