use crate::config::{P2P_BLOCK_TIMEOUT_SECS, P2P_TIP_REFRESH_SECS};
use crate::error::{Context, Error, ensure};
use crate::light::{LightSync, Progress};
use crate::p2p::blocks::BlockCache;
use crate::p2p::headers::{Anchor, HeaderChain};
use crate::p2p::worker::{self, Command, Freshness, Shared, Status, locked};
use crate::transport::{BlockEncoding, Evidence, Provider};
use bitcoin::BlockHash;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use urma_chain::observation::Chain;

enum Engine {
    Cold,
    Running(SyncSender<Command>),
}

pub struct P2pProvider {
    chain: Chain,
    shared: Arc<Shared>,
    engine: Mutex<Engine>,
}

impl P2pProvider {
    pub fn new(chain: Chain, cache_dir: &Path) -> Result<Self, Error> {
        Self::with_peers(chain, cache_dir, Anchor::embedded(chain)?, Vec::new())
    }

    pub fn with_peers(
        chain: Chain,
        cache_dir: &Path,
        anchor: Anchor,
        pinned: Vec<SocketAddr>,
    ) -> Result<Self, Error> {
        let headers = HeaderChain::open_at(chain, cache_dir, anchor)?;
        let shared = Arc::new(Shared {
            chain,
            pinned,
            headers: Mutex::new(headers),
            blocks: Mutex::new(BlockCache::new()),
            status: Mutex::new(Status {
                peers: 0,
                target: 0,
                synced: false,
                refreshed: Freshness::Never,
            }),
            stop: AtomicBool::new(false),
        });
        Ok(Self {
            chain,
            shared,
            engine: Mutex::new(Engine::Cold),
        })
    }

    pub fn warm(&self) -> Result<(), Error> {
        let mut engine = locked(&self.engine, "engine");
        match &*engine {
            Engine::Running(_commands) => return Ok(()),
            Engine::Cold => (),
        }
        let (sender, receiver) = mpsc::sync_channel(16);
        let background = self.shared.clone();
        std::thread::Builder::new()
            .name("urma-p2p".into())
            .spawn(move || worker::run(background, receiver))?;
        *engine = Engine::Running(sender);
        tracing::debug!(chain = self.chain.label(), "light client worker started");
        Ok(())
    }

    fn ignite(&self) {
        match self.warm() {
            Ok(()) => (),
            Err(error) => tracing::warn!(%error, "light client worker could not start"),
        }
    }

    pub fn progress(&self) -> Progress {
        let headers = locked(&self.shared.headers, "headers");
        let status = locked(&self.shared.status, "status");
        Progress {
            headers_synced: headers.synced_count(),
            headers_target: status.target.max(headers.tip_height()) - headers.start_height(),
            peers_connected: status.peers,
            synced: status.synced,
        }
    }

    pub fn state(&self) -> LightSync {
        let progress = self.progress();
        match &*locked(&self.engine, "engine") {
            Engine::Cold => LightSync::Cold(progress),
            Engine::Running(_commands) => LightSync::Running(progress),
        }
    }

    pub fn synced(&self) -> bool {
        locked(&self.shared.status, "status").synced
    }

    pub fn ready(&self) -> bool {
        let status = locked(&self.shared.status, "status");
        status.synced && status.peers > 0
    }

    fn command(&self, command: Command) -> Result<(), Error> {
        let sender = match &*locked(&self.engine, "engine") {
            Engine::Cold => {
                return Err(Error::Unsupported(
                    "light client worker has not been started".into(),
                ));
            }
            Engine::Running(sender) => sender.clone(),
        };
        sender
            .send(command)
            .map_err(|error| Error::Unsupported(format!("light client worker stopped: {error}")))
    }

    fn refresh_if_stale(&self) -> Result<(), Error> {
        let stale = match locked(&self.shared.status, "status").refreshed {
            Freshness::Never => true,
            Freshness::At(when) => when.elapsed() > Duration::from_secs(P2P_TIP_REFRESH_SECS),
        };
        if !stale {
            return Ok(());
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.command(Command::Refresh { reply })?;
        answer
            .recv_timeout(Duration::from_secs(P2P_BLOCK_TIMEOUT_SECS))
            .map_err(|error| {
                Error::Unsupported(format!("header refresh did not complete: {error}"))
            })?
    }

    fn chain_info(&self) -> Result<Value, Error> {
        self.refresh_if_stale()?;
        let headers = locked(&self.shared.headers, "headers");
        let name = match self.chain {
            Chain::LitecoinMainnet => "main",
            Chain::LitecoinTestnet | Chain::BitcoinTestnet4 => "test",
            Chain::BitcoinRegtest => "regtest",
        };
        Ok(json!({
            "chain": name,
            "blocks": headers.tip_height(),
            "headers": headers.tip_height(),
            "bestblockhash": headers.tip_hash().to_string(),
            "initialblockdownload": false,
        }))
    }

    fn block_hash(&self, args: &[Value]) -> Result<Value, Error> {
        let height = args
            .first()
            .context("missing block height")?
            .as_u64()
            .context("block height must be a non-negative integer")?;
        self.refresh_if_stale()?;
        let headers = locked(&self.shared.headers, "headers");
        Ok(json!(headers.hash_at(height)?.to_string()))
    }

    fn block_header(&self, args: &[Value]) -> Result<Value, Error> {
        let hash = requested_hash(args)?;
        let headers = locked(&self.shared.headers, "headers");
        let height = headers.height_of(hash)?;
        let header = headers.header_at(height)?;
        Ok(json!({
            "hash": hash.to_string(),
            "confirmations": headers.tip_height() - height + 1,
            "height": height,
            "version": header.version.to_consensus(),
            "merkleroot": header.merkle_root.to_string(),
            "time": header.time,
            "nonce": header.nonce,
            "bits": format!("{:08x}", header.bits.to_consensus()),
            "previousblockhash": header.prev_blockhash.to_string(),
        }))
    }

    fn block(&self, args: &[Value]) -> Result<Value, Error> {
        let hash = requested_hash(args)?;
        ensure!(
            args.get(1).context("missing block verbosity")? == &json!(0),
            "the light client serves raw blocks only (verbosity 0)"
        );
        let (reply, answer) = mpsc::sync_channel(1);
        self.command(Command::Block { hash, reply })?;
        let raw = answer
            .recv_timeout(Duration::from_secs(P2P_BLOCK_TIMEOUT_SECS))
            .map_err(|error| {
                Error::Unsupported(format!("block fetch did not complete: {error}"))
            })??;
        Ok(json!(hex::encode(raw)))
    }
}

fn requested_hash(args: &[Value]) -> Result<BlockHash, Error> {
    Ok(args
        .first()
        .context("missing block hash")?
        .as_str()
        .context("block hash must be a string")?
        .parse()?)
}

impl Provider for P2pProvider {
    fn label(&self) -> String {
        format!("p2p light client ({})", self.chain.label())
    }

    fn evidence(&self) -> Evidence {
        Evidence::LightClientInclusion
    }

    fn block_encoding(&self) -> BlockEncoding {
        BlockEncoding::Esplora
    }

    fn supports(&self, method: &str) -> bool {
        match method {
            "getblock" | "getblockheader" => {
                self.ignite();
                self.ready()
            }
            "getblockchaininfo" | "getblockhash" => self.ready(),
            _other => false,
        }
    }

    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        ensure!(
            chain.genesis()? == self.chain.genesis()?,
            "light client serves {} only",
            self.chain.label()
        );
        match method {
            "getblockchaininfo" => self.chain_info(),
            "getblockhash" => self.block_hash(args),
            "getblockheader" => self.block_header(args),
            "getblock" => self.block(args),
            other => Err(Error::Unsupported(format!(
                "the peer-to-peer light client does not serve {other}"
            ))),
        }
    }
}

impl Provider for Arc<P2pProvider> {
    fn label(&self) -> String {
        P2pProvider::label(self)
    }

    fn evidence(&self) -> Evidence {
        P2pProvider::evidence(self)
    }

    fn block_encoding(&self) -> BlockEncoding {
        P2pProvider::block_encoding(self)
    }

    fn supports(&self, method: &str) -> bool {
        P2pProvider::supports(self, method)
    }

    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        P2pProvider::call(self, chain, method, args)
    }
}

impl Drop for P2pProvider {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
    }
}
