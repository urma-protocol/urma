use crate::{Error, model::ChainPoint};
use bitcoin::{BlockHash, Txid, block::Header};
use std::{net::SocketAddr, path::Path, sync::Arc};
use urma_chain::observation::Chain;
use urma_runtime::{
    node::Node,
    p2p::{Anchor, HeaderBootstrap, P2pProvider},
};

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

/// Untrusted auxiliary parent bytes, not a chain verifier. The chain getter
/// reads local configuration without I/O. Each fetch must bound its own I/O;
/// Engine cancellation is cooperative and cannot interrupt a running fetch.
pub trait CommitSource {
    fn chain(&self) -> Chain;
    fn fetch(&self, txid: Txid) -> Result<Option<Vec<u8>>, Error>;
}

/// Share an explicitly configured, owner-provided runtime Node. Constructing
/// this wrapper or reading its chain creates no Node, connection or defaults.
/// Only fetch calls the existing Node; no header/placement authority is added.
pub struct RuntimeCommitSource {
    pub node: Arc<Node>,
}

impl CommitSource for RuntimeCommitSource {
    fn chain(&self) -> Chain {
        self.node.chain()
    }

    /// Preserve the original returned hex bytes, rather than reserializing a
    /// normalized transaction. The 16M-character/8M-byte admission cap applies
    /// after Node::call: its transport may allocate/decode first and owns its
    /// timeouts. There is no global deadline or transport-allocation promise.
    /// Absence is the runtime's explicit Missing result or a local JSON-RPC
    /// error with code -5 (no such mempool/blockchain transaction, including
    /// lookups a node without -txindex cannot answer), per is_missing_transaction.
    /// Other runtime errors become CommitSource without text matching.
    fn fetch(&self, txid: Txid) -> Result<Option<Vec<u8>>, Error> {
        let result = match self.node.call(
            "getrawtransaction",
            &[serde_json::json!(txid), serde_json::json!(false)],
        ) {
            Ok(result) => result,
            Err(error) if error.is_missing_transaction() => return Ok(None),
            Err(error) => return Err(Error::CommitSource(error.to_string())),
        };
        let encoded = result
            .as_str()
            .ok_or_else(|| Error::Invalid("commit source must return transaction hex".into()))?;
        if encoded.len() > 16_000_000 || encoded.len() % 2 != 0 {
            return Err(Error::Invalid(
                "commit source hex exceeds capacity or has odd length".into(),
            ));
        }
        let raw = hex::decode(encoded)
            .map_err(|error| Error::Invalid(format!("commit source hex: {error}")))?;
        Ok(Some(raw))
    }
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
