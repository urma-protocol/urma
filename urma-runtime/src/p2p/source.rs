use crate::error::{Error, ensure};
use bitcoin::{Block, block::Header};
use urma_chain::{decode, observation::Chain};

/// A block whose hash, transaction Merkle root and witness commitment were
/// checked against the provider's active header at acquisition time.
///
/// Header verification relies on the configured trusted checkpoint and the
/// existing local header cache (older cached PoW is not rechecked on reload).
/// This does not establish full script, UTXO or MWEB consensus validity, or
/// guarantee the globally highest-work chain. Membership can change after
/// return; consumers must reconcile subsequent reorganizations.
#[derive(Debug)]
pub struct VerifiedBlock {
    height: u64,
    header: Header,
    raw: Vec<u8>,
    block: Block,
}

impl VerifiedBlock {
    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Original bytes returned by the P2P worker, including Litecoin framing.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Decoded transparent block view. Serializing it need not reproduce
    /// Litecoin HogEx/MWEB framing; use `raw()` for original bytes.
    pub fn block(&self) -> &Block {
        &self.block
    }
}

pub(super) fn decode_verified(
    chain: Chain,
    height: u64,
    header: Header,
    raw: Vec<u8>,
) -> Result<VerifiedBlock, Error> {
    let block = decode::esplora_block(&raw, chain, header.block_hash())?;
    ensure!(
        block.header == header,
        "peer block header differs from the captured verified header"
    );
    Ok(VerifiedBlock {
        height,
        header,
        raw,
        block,
    })
}
