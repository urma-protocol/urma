use crate::{Error, model::ChainPoint};
use bitcoin::{BlockHash, block::Header};
use std::{net::SocketAddr, path::Path};
use urma_chain::observation::Chain;
use urma_runtime::p2p::{Anchor, HeaderBootstrap, P2pProvider};

/// Port implemented by a chain verifier, not by an untrusted remote JSON API.
/// The implementation owns header difficulty, PoW and branch selection. Bodies
/// remain untrusted bytes and are checked again against the selected header.
/// Provider-claimed observations used by autonomous clients are a different
/// contract and do not enter this port by relabelling them as verified.
pub trait ChainSource: Send + Sync {
    fn genesis(&self) -> Result<BlockHash, Error>;
    fn tip(&self) -> Result<ChainPoint, Error>;
    fn header(&self, height: u64) -> Result<Header, Error>;
    fn block(&self, height: u64) -> Result<Vec<u8>, Error>;
}

/// Checkpoint-relative Litecoin light client. Does not validate scripts, UTXOs
/// or MWEB consensus. Opening it does not start network connections; the first
/// sync attempt does. An application start before the configured anchor is an
/// explicit error, never silently replaced with the anchor's height.
pub struct LitecoinSource {
    chain: Chain,
    provider: P2pProvider,
}

impl LitecoinSource {
    pub fn open(
        chain: Chain,
        cache: &Path,
        anchor: Anchor,
        peers: Vec<SocketAddr>,
    ) -> Result<Self, Error> {
        if !matches!(chain, Chain::LitecoinTestnet | Chain::LitecoinMainnet) {
            return Err(Error::Invalid(
                "Litecoin source requires a Litecoin network".into(),
            ));
        }
        Ok(Self {
            chain,
            provider: P2pProvider::with_peers(chain, cache, anchor, peers).map_err(source_error)?,
        })
    }

    /// Open a Litecoin source with authenticated preceding header context.
    /// The operator trusts the bootstrap anchor's chain membership and height;
    /// the context does not prove pre-anchor consensus or earlier scan coverage.
    /// This source does not validate scripts, UTXOs or MWEB consensus. Opening
    /// only loads the local cache; the first sync attempt starts connections.
    pub fn open_bootstrap(
        cache: &Path,
        bootstrap: HeaderBootstrap,
        peers: Vec<SocketAddr>,
    ) -> Result<Self, Error> {
        let chain = bootstrap.chain();
        if !matches!(chain, Chain::LitecoinTestnet | Chain::LitecoinMainnet) {
            return Err(Error::Invalid(
                "Litecoin source requires a Litecoin network".into(),
            ));
        }
        Ok(Self {
            chain,
            provider: P2pProvider::with_bootstrap(cache, bootstrap, peers).map_err(source_error)?,
        })
    }
}

fn source_error(e: urma_runtime::error::Error) -> Error {
    Error::Source(Box::new(e))
}

impl ChainSource for LitecoinSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(self
            .chain
            .genesis()
            .map_err(|e| Error::Invalid(e.to_string()))?
            .0)
    }
    fn tip(&self) -> Result<ChainPoint, Error> {
        let (height, header) = self.provider.verified_tip().map_err(source_error)?;
        Ok(ChainPoint {
            height,
            hash: header.block_hash(),
        })
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.provider.verified_header(height).map_err(source_error)
    }
    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        Ok(self
            .provider
            .verified_block(height)
            .map_err(source_error)?
            .raw()
            .to_vec())
    }
}
