use crate::config;
use crate::error::{Context, Error, ensure};
use crate::light::LightSync;
#[cfg(not(target_arch = "wasm32"))]
use crate::pinning::Pins;
use crate::transaction::decode;
use crate::{
    endpoints::{self, PublicEndpoint},
    providers,
    transport::{BlockEncoding, Evidence, Preference, Provider, Router, Standing},
};
use bitcoin::{Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, hash_map::Entry},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::Instant,
};
use urma_chain::{
    decode::{self as chain_decode, DecodeError},
    observation::Chain,
    validation::BlockValidationError,
};

#[derive(Clone)]
pub struct NodeConfig {
    pub chain: Chain,
    pub rpc_url: String,
    pub cookie_file: PathBuf,
}

pub struct Node {
    chain: Chain,
    backend: Backend,
    light: providers::LightClient,
    acknowledged: Mutex<HashMap<Txid, Acknowledged>>,
}

struct Acknowledged {
    when: Instant,
    provider: String,
}

enum Backend {
    Local(Client),
    Routed(Router),
}

pub struct Observed {
    pub value: Value,
    pub provider: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Presence {
    Missing,
    Mempool,
    Confirmed { height: u64, block_hash: String },
}

impl Node {
    pub fn connect(config: NodeConfig) -> Result<Self, Error> {
        let url = url::Url::parse(&config.rpc_url)?;
        ensure!(
            url.scheme() == "http"
                && url.username().is_empty()
                && url.password().iter().count() == 0
                && url.query().iter().count() == 0
                && url.fragment().iter().count() == 0
                && url.path() == "/",
            "RPC requires a local HTTP origin and cookie authentication"
        );
        let host = url
            .host_str()
            .context("missing RPC host")?
            .trim_matches(['[', ']']);
        ensure!(
            host.parse::<std::net::IpAddr>()?.is_loopback(),
            "RPC must use a loopback IP"
        );
        let client = Client::new(url.as_str(), Auth::CookieFile(config.cookie_file.clone()))?;
        let node = Self {
            chain: config.chain,
            backend: Backend::Local(client),
            light: providers::LightClient::Absent,
            acknowledged: Mutex::new(HashMap::new()),
        };
        node.verify_network()?;
        Ok(node)
    }

    pub fn public(chain: Chain) -> Result<Self, Error> {
        Self::with_public_sources(chain, endpoints::defaults(chain))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn public_in(chain: Chain, cache_dir: &std::path::Path) -> Result<Self, Error> {
        Self::public_in_with_providers(chain, cache_dir, Vec::new())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn public_in_with_providers(
        chain: Chain,
        cache_dir: &std::path::Path,
        mut additional: Vec<Box<dyn Provider>>,
    ) -> Result<Self, Error> {
        let pins = std::sync::Arc::new(Pins::in_directory(cache_dir)?);
        let light = providers::light_clients(chain, cache_dir)?;
        additional.extend(providers::assemble(
            endpoints::defaults(chain),
            pins,
            &light,
        )?);
        let mut node = Self::with_providers(chain, additional)?;
        node.light = light;
        Ok(node)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn public_pinned(chain: Chain, cache_dir: &std::path::Path) -> Result<Self, Error> {
        let pins = std::sync::Arc::new(Pins::in_directory(cache_dir)?);
        let public = providers::assemble(
            endpoints::defaults(chain),
            pins,
            &providers::LightClient::Absent,
        )?;
        Self::with_providers(chain, public)
    }

    pub fn light_client_progress(&self) -> LightSync {
        self.light.state()
    }

    pub fn warm_light_client(&self) -> Result<(), Error> {
        self.light.warm()
    }

    pub fn with_public_sources(
        chain: Chain,
        endpoints: Vec<PublicEndpoint>,
    ) -> Result<Self, Error> {
        Self::with_providers(chain, providers::ephemeral(chain, endpoints)?)
    }

    pub fn with_providers(chain: Chain, providers: Vec<Box<dyn Provider>>) -> Result<Self, Error> {
        let router = Router::new(providers)?;
        tracing::debug!(providers = ?router.labels(), evidence = router.evidence().label(), "routed public node");
        let node = Self {
            chain,
            backend: Backend::Routed(router),
            light: providers::LightClient::Absent,
            acknowledged: Mutex::new(HashMap::new()),
        };
        node.verify_network()?;
        Ok(node)
    }

    pub fn is_public(&self) -> bool {
        matches!(self.backend, Backend::Routed(_))
    }

    pub fn evidence(&self) -> Evidence {
        match &self.backend {
            Backend::Local(_) => Evidence::LocalValidatingNode,
            Backend::Routed(router) => router.evidence(),
        }
    }

    pub fn inclusion_evidence(&self) -> &'static str {
        self.evidence().label()
    }

    pub fn provider_labels(&self) -> Vec<String> {
        match &self.backend {
            Backend::Local(_) => vec![config::LOCAL_PROVIDER_LABEL.to_owned()],
            Backend::Routed(router) => router.labels(),
        }
    }

    pub fn standings(&self) -> Vec<Standing> {
        match &self.backend {
            Backend::Local(_) => vec![Standing {
                label: config::LOCAL_PROVIDER_LABEL.to_owned(),
                evidence: Evidence::LocalValidatingNode,
                failures: 0,
                blocked_for: std::time::Duration::ZERO,
            }],
            Backend::Routed(router) => router.standings(),
        }
    }

    pub fn observe(&self, method: &str, args: &[Value]) -> Result<Observed, Error> {
        match &self.backend {
            Backend::Local(client) => Ok(Observed {
                value: client.call(method, args)?,
                provider: config::LOCAL_PROVIDER_LABEL.to_owned(),
                evidence: Evidence::LocalValidatingNode,
            }),
            Backend::Routed(router) => {
                let answer = router.answer(self.chain, method, args)?;
                Ok(Observed {
                    value: answer.value,
                    provider: answer.label,
                    evidence: answer.evidence,
                })
            }
        }
    }

    pub fn chain(&self) -> Chain {
        self.chain
    }

    pub fn tip_height(&self) -> Result<u64, Error> {
        Ok(self.tip()?.0)
    }

    pub fn block_hash(&self, height: u64) -> Result<bitcoin::BlockHash, Error> {
        let value = self.call("getblockhash", &[json!(height)])?;
        Ok(value.as_str().context("missing block hash")?.parse()?)
    }

    pub fn block(&self, height: u64) -> Result<bitcoin::Block, Error> {
        Ok(self.block_at(height)?.0)
    }

    pub fn block_at(&self, height: u64) -> Result<(bitcoin::Block, bitcoin::BlockHash), Error> {
        let hash = self.block_hash(height)?;
        let args = [json!(hash), json!(0)];
        let (value, encoding) = match &self.backend {
            Backend::Local(client) => (client.call("getblock", &args)?, BlockEncoding::Core),
            Backend::Routed(router) => {
                let answer = router.answer(self.chain, "getblock", &args)?;
                tracing::debug!(provider = %answer.label, height, "block served by provider");
                (answer.value, answer.encoding)
            }
        };
        let raw = hex::decode(value.as_str().context("missing block bytes")?)?;
        let decoded = match encoding {
            BlockEncoding::Core => chain_decode::block(&raw, self.chain, hash),
            BlockEncoding::Esplora => chain_decode::esplora_block(&raw, self.chain, hash),
        };
        let block = decoded.map_err(|cause| match cause {
            DecodeError::Integrity(BlockValidationError::HashMismatch) => {
                Error::Invalid("RPC block hash mismatch".into())
            }
            DecodeError::Integrity(BlockValidationError::MerkleRootMismatch) => {
                Error::Invalid("RPC block merkle root mismatch".into())
            }
            cause => Error::from(cause),
        })?;
        Ok((block, hash))
    }

    pub fn confirmations(&self, txid: Txid) -> Result<u32, Error> {
        match self.presence(txid)? {
            Presence::Confirmed { height, .. } => Ok(u32::try_from(
                self.tip_height()?
                    .checked_sub(height)
                    .context("chain changed during confirmation lookup")?
                    .checked_add(1)
                    .context("confirmation count overflow")?,
            )?),
            Presence::Missing | Presence::Mempool => Ok(0),
        }
    }

    pub fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        match &self.backend {
            Backend::Local(client) => Ok(client.call(method, args)?),
            Backend::Routed(router) => {
                if method != "sendrawtransaction" {
                    return router.call(self.chain, method, args);
                }
                let preference = self.parent_provider(args)?;
                let answer = router.answer_preferring(&preference, self.chain, method, args)?;
                self.remember_acknowledged(&answer.value, answer.label)?;
                Ok(answer.value)
            }
        }
    }

    fn acknowledged(&self) -> MutexGuard<'_, HashMap<Txid, Acknowledged>> {
        match self.acknowledged.lock() {
            Ok(acknowledged) => acknowledged,
            Err(poisoned) => {
                tracing::error!("broadcast acknowledgment table lock poisoned");
                poisoned.into_inner()
            }
        }
    }

    fn parent_provider(&self, args: &[Value]) -> Result<Preference, Error> {
        let raw = args
            .first()
            .context("broadcast without a transaction")?
            .as_str()
            .context("broadcast transaction must be hex")?;
        let transaction = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?;
        let acknowledged = self.acknowledged();
        for input in &transaction.input {
            let Some(parent) = acknowledged.get(&input.previous_output.txid) else {
                continue;
            };
            if parent.when.elapsed() < config::SUBMISSION_ACK_WINDOW {
                return Ok(Preference::Provider(parent.provider.clone()));
            }
        }
        Ok(Preference::Any)
    }

    fn remember_acknowledged(&self, value: &Value, provider: String) -> Result<(), Error> {
        let txid: Txid = value
            .as_str()
            .context("broadcast acknowledgment without a txid")?
            .parse()?;
        let now = Instant::now();
        let mut acknowledged = self.acknowledged();
        acknowledged.retain(|_txid, parent| {
            now.duration_since(parent.when) < config::SUBMISSION_ACK_WINDOW
        });
        tracing::debug!(%txid, %provider, "broadcast acknowledged by a public provider");
        acknowledged.insert(
            txid,
            Acknowledged {
                when: now,
                provider,
            },
        );
        Ok(())
    }

    fn recently_acknowledged(&self, txid: Txid) -> bool {
        let acknowledged = self.acknowledged();
        let Some(parent) = acknowledged.get(&txid) else {
            return false;
        };
        parent.when.elapsed() < config::SUBMISSION_ACK_WINDOW
    }

    pub fn presence_after_submission(&self, txid: Txid) -> Result<Presence, Error> {
        let mut checks = 0;
        loop {
            checks += 1;
            let presence = self.presence(txid)?;
            if !matches!(presence, Presence::Missing)
                || checks >= config::SUBMISSION_PRESENCE_CHECKS
            {
                return Ok(presence);
            }
            tracing::warn!(%txid, checks, "submitted transaction not yet visible; checking again");
            std::thread::sleep(config::SUBMISSION_PRESENCE_DELAY);
        }
    }

    pub fn require_txindex(&self) -> Result<(), Error> {
        if matches!(self.backend, Backend::Routed(_)) {
            return self.verify_network();
        }
        let indexes = self.call("getindexinfo", &[json!("txindex")])?;
        ensure!(
            indexes["txindex"]["synced"] == true,
            "publication and recovery require synchronized txindex=1 on the local node"
        );
        Ok(())
    }

    pub fn verify_network(&self) -> Result<(), Error> {
        let started = Instant::now();
        let verified = (|| {
            let genesis = self.call("getblockhash", &[json!(0)])?;
            ensure!(
                genesis.as_str() == Some(self.chain().genesis()?.0.to_string().as_str()),
                "RPC genesis does not match selected chain"
            );
            Ok(())
        })();
        tracing::debug!(
            target: "urma_startup",
            chain = self.chain.label(),
            stage = "network_verification",
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            routed = self.is_public(),
            result = ?verified,
            "light client stage completed"
        );
        verified
    }

    pub fn tip(&self) -> Result<(u64, String), Error> {
        let info = self.call("getblockchaininfo", &[])?;
        Ok((
            info["blocks"].as_u64().context("missing height")?,
            info["bestblockhash"]
                .as_str()
                .context("missing tip hash")?
                .to_owned(),
        ))
    }

    pub fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        let raw = self.call("getrawtransaction", &[json!(txid), json!(false)])?;
        self.decode_transaction(txid, &raw)
    }

    pub fn transaction_avoiding(
        &self,
        txid: Txid,
        avoid: &[String],
    ) -> Result<(Transaction, String), Error> {
        let args = [json!(txid), json!(false)];
        let (raw, provider) = match &self.backend {
            Backend::Local(client) => {
                if avoid
                    .iter()
                    .any(|label| label == config::LOCAL_PROVIDER_LABEL)
                {
                    return Err(Error::Missing(format!(
                        "{txid}: the local node served a rejected candidate"
                    )));
                }
                (
                    client.call("getrawtransaction", &args)?,
                    config::LOCAL_PROVIDER_LABEL.to_owned(),
                )
            }
            Backend::Routed(router) => {
                let answer =
                    router.answer_avoiding(avoid, self.chain, "getrawtransaction", &args)?;
                (answer.value, answer.label)
            }
        };
        Ok((self.decode_transaction(txid, &raw)?, provider))
    }

    fn decode_transaction(&self, txid: Txid, raw: &Value) -> Result<Transaction, Error> {
        let raw = raw.as_str().context("missing raw transaction")?;
        let transaction = chain_decode::transaction(&hex::decode(raw)?, self.chain)?;
        ensure!(
            transaction.compute_txid() == txid,
            "RPC transaction hash mismatch"
        );
        Ok(transaction)
    }

    pub fn presence(&self, txid: Txid) -> Result<Presence, Error> {
        self.presence_cached(txid, &mut std::collections::HashMap::new())
    }

    pub(crate) fn presence_cached(
        &self,
        txid: Txid,
        blocks: &mut std::collections::HashMap<String, Presence>,
    ) -> Result<Presence, Error> {
        let result = self.call("getrawtransaction", &[json!(txid), json!(true)]);
        let value = match result {
            Ok(value) => value,
            Err(error @ Error::Rpc(_)) if error.is_missing_transaction() => {
                tracing::warn!(%error, "transaction absent from node");
                return Ok(Presence::Missing);
            }
            Err(Error::Missing(message)) => {
                if self.recently_acknowledged(txid) {
                    tracing::warn!(%message, %txid, "providers lag behind an acknowledged broadcast; treating as mempool");
                    return Ok(Presence::Mempool);
                }
                tracing::warn!(%message, "transaction absent from public sources");
                return Ok(Presence::Missing);
            }
            Err(error) => return Err(error),
        };
        if config::confirmations(&value)? <= 0 {
            return Ok(Presence::Mempool);
        }
        let hash = value["blockhash"]
            .as_str()
            .context("missing inclusion block")?;
        let slot = match blocks.entry(hash.to_owned()) {
            Entry::Occupied(cached) => return Ok(cached.get().clone()),
            Entry::Vacant(slot) => slot,
        };
        let header = self.call("getblockheader", &[json!(hash)])?;
        let height = header["height"]
            .as_u64()
            .context("missing inclusion height")?;
        let active = self.call("getblockhash", &[json!(height)])?;
        if active != json!(hash) {
            return Ok(Presence::Missing);
        }
        let presence = Presence::Confirmed {
            height,
            block_hash: hash.to_owned(),
        };
        slot.insert(presence.clone());
        Ok(presence)
    }
}
