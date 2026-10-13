//! Raw commit parents from configured URMA peers over the overlay.
use crate::{
    Error,
    peer::{PeerSource, Pending, bind_response},
    peer_limits::ESTABLISHED_PER_DIRECTION,
    peer_protocol::{PARENT_LIMIT, Reply, Response},
    source::{CommitSource, check_cancelled, verify_parent},
};
use bitcoin::{BlockHash, Txid};
use libp2p::PeerId;
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

/// Busy is capacity, not an answer. Hex is length-checked before any decode.
/// TooLarge, WrongNetwork and UnsupportedVersion are definitive for that peer.
pub(crate) fn validate_parent(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: Response,
) -> Result<Parent, Error> {
    bind_response(genesis, peer, pending, &response)?;
    match response.result {
        Reply::Parent(hex) if hex.len() <= 2 * PARENT_LIMIT => Ok(Parent::Hex(hex)),
        Reply::Parent(_) => Err(Error::Invalid("peer parent exceeds byte limit".into())),
        Reply::Busy => Ok(Parent::Busy),
        Reply::Missing | Reply::TooLarge | Reply::WrongNetwork | Reply::UnsupportedVersion => {
            Ok(Parent::Absent)
        }
        Reply::Record(_) | Reply::Inventory(_) | Reply::Peers(_) | Reply::Refused => Err(
            Error::Invalid("peer answered a parent request with another kind or a refusal".into()),
        ),
    }
}

/// Tries one window of configured peers per fetch; successive fetches move to
/// the next window, so every peer is visited. verify_parent binds bytes to the
/// TXID; a peer whose bytes fail it only lets the next peer be tried and is
/// disconnected so it keeps no outbound slot. Engine verification is final.
pub struct OverlayCommitSource {
    chain: Chain,
    peers: Vec<PeerSource>,
    next: AtomicUsize,
}

impl OverlayCommitSource {
    /// No more peers than outbound connections the limits admit at once.
    const PEERS_PER_FETCH: usize = ESTABLISHED_PER_DIRECTION;
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

    /// Busy, local or remote, is no answer. Local Busy from request() also
    /// covers deadline expiry, a dial denied by our connection limits and a
    /// stopped network, so these are silent (Ok(None), nothing in status);
    /// FETCH_DEADLINE bounds the whole round. Zero answers plus any other peer
    /// or transport error is an error; otherwise absence. First valid wins.
    fn fetch(&self, txid: Txid, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        check_cancelled(cancelled)?;
        let count = self.peers.len();
        if count == 0 {
            return Ok(None);
        }
        let deadline = Instant::now() + Self::FETCH_DEADLINE;
        let window = count.min(Self::PEERS_PER_FETCH);
        let start = self.next.fetch_add(window, Ordering::Relaxed) % count;
        let mut answered = false;
        let mut failure = None;
        for offset in 0..window {
            check_cancelled(cancelled)?;
            if Instant::now() >= deadline {
                break;
            }
            let peer = &self.peers[(start + offset) % count];
            match peer.parent(txid, deadline) {
                Ok(Parent::Hex(hex)) => match self.decode(&hex, txid) {
                    Ok(raw) => return Ok(Some(raw)),
                    Err(error) => {
                        peer.disconnect();
                        failure = Some(error);
                    }
                },
                Ok(Parent::Absent) => answered = true,
                Ok(Parent::Busy) | Err(Error::Busy(_)) => (),
                Err(Error::DialDenied(_local_capacity)) => (),
                Err(error) => {
                    peer.disconnect();
                    failure = Some(error);
                }
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
