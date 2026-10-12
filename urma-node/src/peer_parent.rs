//! Raw commit parents from configured URMA peers over the overlay.
use crate::{
    Error,
    peer::PeerSource,
    source::{CommitSource, check_cancelled},
};
use bitcoin::{Transaction, Txid, consensus};
use std::sync::atomic::AtomicBool;
use urma_chain::observation::Chain;

/// A metadata-bound parent reply. Hex length is checked, bytes are not yet.
pub(crate) enum Parent {
    Hex(String),
    Absent,
    Busy,
}

/// Tries configured peers in order. Bytes are bound to the TXID only for
/// fairness across peers; Engine verification is final.
pub struct OverlayCommitSource {
    chain: Chain,
    peers: Vec<PeerSource>,
}

impl OverlayCommitSource {
    pub(crate) fn new(chain: Chain, peers: Vec<PeerSource>) -> Self {
        Self { chain, peers }
    }
}

impl CommitSource for OverlayCommitSource {
    fn chain(&self) -> Chain {
        self.chain
    }

    /// Busy is no answer. Zero answers plus any peer or transport error is an
    /// error; otherwise absence. The first exact parent wins.
    fn fetch(&self, txid: Txid, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>, Error> {
        check_cancelled(cancelled)?;
        let mut answered = false;
        let mut failure = None;
        for peer in &self.peers {
            match peer.parent(txid) {
                Ok(Parent::Hex(hex)) => match exact_parent(&hex, txid) {
                    Ok(raw) => return Ok(Some(raw)),
                    Err(error) => failure = Some(error),
                },
                Ok(Parent::Absent) => answered = true,
                Ok(Parent::Busy) => (),
                Err(error) => failure = Some(error),
            }
        }
        match failure {
            Some(error) if !answered => Err(Error::CommitSource(format!("overlay: {error}"))),
            _ => Ok(None),
        }
    }
}

fn exact_parent(hex: &str, txid: Txid) -> Result<Vec<u8>, Error> {
    let raw =
        hex::decode(hex).map_err(|error| Error::Invalid(format!("peer parent hex: {error}")))?;
    let transaction: Transaction = consensus::deserialize(&raw)
        .map_err(|error| Error::Invalid(format!("peer parent transaction: {error}")))?;
    if transaction.compute_txid() != txid || consensus::serialize(&transaction) != raw {
        return Err(Error::Invalid(
            "peer parent is not the exact requested transaction".into(),
        ));
    }
    Ok(raw)
}
