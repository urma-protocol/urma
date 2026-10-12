use crate::{Error, model::ChainPoint};
use bitcoin::{BlockHash, Txid, block::Header};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
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
        fetch_from_node(&self.node, txid)
    }
}

fn fetch_from_node(node: &Node, txid: Txid) -> Result<Option<Vec<u8>>, Error> {
    let result = match node.call(
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

/// Default public providers for one chain, without a light client. Creating
/// it does no I/O; the first fetch builds the Node and a failed build is
/// retried on the next fetch. Returned bytes are checked by the Engine.
pub struct PublicCommitSource {
    chain: Chain,
    cache_dir: PathBuf,
    node: Mutex<Option<Arc<Node>>>,
}

impl PublicCommitSource {
    pub fn new(chain: Chain, cache_dir: PathBuf) -> Self {
        Self {
            chain,
            cache_dir,
            node: Mutex::new(None),
        }
    }

    fn node(&self) -> Result<Arc<Node>, Error> {
        let mut slot = self
            .node
            .lock()
            .map_err(|_| Error::Invalid("public commit source poisoned".into()))?;
        for node in slot.iter() {
            return Ok(Arc::clone(node));
        }
        let node = Arc::new(
            Node::public_pinned(self.chain, &self.cache_dir)
                .map_err(|error| Error::CommitSource(error.to_string()))?,
        );
        *slot = Some(Arc::clone(&node));
        Ok(node)
    }
}

impl CommitSource for PublicCommitSource {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn fetch(&self, txid: Txid) -> Result<Option<Vec<u8>>, Error> {
        let node = self.node()?;
        fetch_from_node(&node, txid)
    }
}

/// Ordered labelled sources tried until one returns bytes. A miss or error
/// moves to the next source; the set errors only when every source errored.
/// The error table is locked only to read or write, never across a fetch.
pub struct CommitSources {
    chain: Chain,
    entries: Vec<(String, Box<dyn CommitSource + Send + Sync>)>,
    errors: Mutex<Vec<Option<String>>>,
}

impl CommitSources {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            entries: Vec::new(),
            errors: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&mut self, label: String, source: Box<dyn CommitSource + Send + Sync>) {
        self.entries.push((label, source));
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn status(&self) -> Result<Vec<(String, Option<String>)>, Error> {
        let errors = self.errors()?;
        Ok(self
            .entries
            .iter()
            .zip(errors.iter())
            .map(|(entry, error)| (entry.0.clone(), error.clone()))
            .collect())
    }

    pub(crate) fn source_chains(&self) -> Vec<Chain> {
        self.entries.iter().map(|entry| entry.1.chain()).collect()
    }

    fn errors(&self) -> Result<MutexGuard<'_, Vec<Option<String>>>, Error> {
        let mut errors = self
            .errors
            .lock()
            .map_err(|_| Error::Invalid("commit source status poisoned".into()))?;
        errors.resize(self.entries.len(), None);
        Ok(errors)
    }

    fn record(&self, index: usize, error: Option<String>) -> Result<(), Error> {
        let mut errors = self.errors()?;
        let slot = errors
            .get_mut(index)
            .ok_or_else(|| Error::Invalid("commit source status out of range".into()))?;
        *slot = error;
        Ok(())
    }
}

impl CommitSource for CommitSources {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn fetch(&self, txid: Txid) -> Result<Option<Vec<u8>>, Error> {
        let mut last = None;
        let mut failures = 0;
        for (index, entry) in self.entries.iter().enumerate() {
            match entry.1.fetch(txid) {
                Ok(Some(raw)) => {
                    self.record(index, None)?;
                    return Ok(Some(raw));
                }
                Ok(None) => self.record(index, None)?,
                Err(error) => {
                    self.record(index, Some(error.to_string()))?;
                    failures += 1;
                    last = Some(error);
                }
            }
        }
        let Some(error) = last else {
            return Ok(None);
        };
        if failures == self.entries.len() {
            return Err(error);
        }
        Ok(None)
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
