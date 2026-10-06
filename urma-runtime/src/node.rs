use crate::config;
use crate::error::{Context, Error, ensure};
use crate::light::LightSync;
#[cfg(not(target_arch = "wasm32"))]
use crate::pinning::Pins;
use crate::{
    endpoints::{self, PublicEndpoint},
    providers,
    transport::{BlockEncoding, Evidence, Provider, Router, Standing},
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
use urma_identity::identity::IdentitySigner;
use urma_wallet::funding::Funding;

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
    acknowledged: Mutex<HashMap<Txid, Instant>>,
}

enum Backend {
    Local(Client),
    Routed(Router),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spendable {
    pub outputs: Vec<Utxo>,
    pub reported: usize,
    pub verified: bool,
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
        let pins = std::sync::Arc::new(Pins::in_directory(cache_dir)?);
        let light = providers::light_clients(chain, cache_dir)?;
        let mut node = Self::with_providers(
            chain,
            providers::assemble(endpoints::defaults(chain), pins, &light)?,
        )?;
        node.light = light;
        Ok(node)
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
                let value = router.call(self.chain, method, args)?;
                if method == "sendrawtransaction" {
                    self.remember_acknowledged(&value)?;
                }
                Ok(value)
            }
        }
    }

    fn acknowledged(&self) -> MutexGuard<'_, HashMap<Txid, Instant>> {
        match self.acknowledged.lock() {
            Ok(acknowledged) => acknowledged,
            Err(poisoned) => {
                tracing::error!("broadcast acknowledgment table lock poisoned");
                poisoned.into_inner()
            }
        }
    }

    fn remember_acknowledged(&self, value: &Value) -> Result<(), Error> {
        let txid: Txid = value
            .as_str()
            .context("broadcast acknowledgment without a txid")?
            .parse()?;
        let now = Instant::now();
        let mut acknowledged = self.acknowledged();
        acknowledged
            .retain(|_txid, when| now.duration_since(*when) < config::SUBMISSION_ACK_WINDOW);
        acknowledged.insert(txid, now);
        tracing::debug!(%txid, "broadcast acknowledged by a public provider");
        Ok(())
    }

    fn recently_acknowledged(&self, txid: Txid) -> bool {
        let acknowledged = self.acknowledged();
        let Some(when) = acknowledged.get(&txid) else {
            return false;
        };
        when.elapsed() < config::SUBMISSION_ACK_WINDOW
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
        let genesis = self.call("getblockhash", &[json!(0)])?;
        ensure!(
            genesis.as_str() == Some(self.chain().genesis()?.0.to_string().as_str()),
            "RPC genesis does not match selected chain"
        );
        Ok(())
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
            Err(Error::Rpc(bitcoincore_rpc::Error::JsonRpc(
                bitcoincore_rpc::jsonrpc::Error::Rpc(error),
            ))) if error.code == -5 => {
                tracing::warn!(code = error.code, "transaction absent from node");
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
            let mempool = self.call("getrawmempool", &[])?;
            return Ok(
                if mempool
                    .as_array()
                    .context("invalid mempool")?
                    .contains(&json!(txid))
                {
                    Presence::Mempool
                } else {
                    Presence::Missing
                },
            );
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

    pub fn utxos(&self, signer: &impl IdentitySigner) -> Result<Vec<Utxo>, Error> {
        self.verify_network()?;
        if matches!(self.backend, Backend::Routed(_)) {
            return self.public_utxos(signer);
        }
        let script = urma_wallet::signing::script(signer)?;
        let scan = self.call(
            "scantxoutset",
            &[
                json!("start"),
                json!([format!("raw({})", hex::encode(script.as_bytes()))]),
            ],
        )?;
        ensure!(scan["success"] == true, "UTXO scan did not complete");
        let rows = scan["unspents"].as_array().context("missing UTXO scan")?;
        ensure!(rows.len() <= 1000, "UTXO client capacity exceeded");
        let mut outputs = Vec::new();
        for row in rows {
            let amount = bitcoin::Amount::from_str_in(
                &row["amount"].to_string(),
                bitcoin::Denomination::Bitcoin,
            )?;
            outputs.push(Utxo {
                txid: row["txid"].as_str().context("missing UTXO txid")?.parse()?,
                vout: u32::try_from(row["vout"].as_u64().context("missing UTXO vout")?)?,
                value: amount.to_sat(),
                height: row["height"].as_u64().context("missing UTXO height")?,
            });
        }
        outputs.sort_by_key(|output| (output.value, output.txid, output.vout));
        Ok(outputs)
    }

    fn public_utxos(&self, signer: &impl IdentitySigner) -> Result<Vec<Utxo>, Error> {
        let address = urma_wallet::address::receive_address(signer, self.chain)?;
        let rows = self.call("addressutxos", &[json!(address)])?;
        let rows = rows.as_array().context("missing public UTXOs")?;
        ensure!(rows.len() <= 1000, "UTXO client capacity exceeded");
        let mut outputs = Vec::new();
        for row in rows {
            if row["status"]["confirmed"] != true {
                continue;
            }
            outputs.push(Utxo {
                txid: row["txid"].as_str().context("missing UTXO txid")?.parse()?,
                vout: u32::try_from(row["vout"].as_u64().context("missing UTXO index")?)?,
                value: row["value"].as_u64().context("missing UTXO value")?,
                height: row["status"]["block_height"]
                    .as_u64()
                    .context("missing UTXO height")?,
            });
        }
        outputs.sort_by_key(|output| (output.value, output.txid, output.vout));
        Ok(outputs)
    }

    fn verified_output(&self, output: &Utxo, expected: &str) -> Result<bool, Error> {
        let unspent = self.call(
            "gettxout",
            &[json!(output.txid), json!(output.vout), json!(true)],
        )?;
        if unspent.is_null() {
            return Ok(false);
        }
        let confirmations = config::confirmations(&unspent)?;
        if confirmations < 1 || (unspent["coinbase"] == true && confirmations < 100) {
            return Ok(false);
        }
        ensure!(
            unspent["scriptPubKey"]["hex"] == expected,
            "live funding script disagrees with identity"
        );
        let amount = bitcoin::Amount::from_str_in(
            &unspent["value"].to_string(),
            bitcoin::Denomination::Bitcoin,
        )?;
        ensure!(
            amount.to_sat() == output.value,
            "live funding value disagrees with UTXO scan"
        );
        Ok(true)
    }

    pub fn spendable(&self, signer: &impl IdentitySigner) -> Result<Spendable, Error> {
        let expected = hex::encode(urma_wallet::signing::script(signer)?.as_bytes());
        let outputs = self.utxos(signer)?;
        let reported = outputs.len();
        if reported > config::WALLET_VERIFY_OUTPUTS {
            tracing::warn!(
                reported,
                bound = config::WALLET_VERIFY_OUTPUTS,
                "spendable set exceeds the per-output verification bound; summary follows the provider's unspent rows"
            );
            return Ok(Spendable {
                outputs,
                reported,
                verified: false,
            });
        }
        let mut available = Vec::new();
        for output in outputs {
            if self.verified_output(&output, &expected)? {
                available.push(output);
            }
        }
        Ok(Spendable {
            outputs: available,
            reported,
            verified: true,
        })
    }

    pub fn available_utxos(&self, signer: &impl IdentitySigner) -> Result<Vec<Utxo>, Error> {
        Ok(self.spendable(signer)?.outputs)
    }

    pub fn select_funding(
        &self,
        signer: &impl IdentitySigner,
        minimum: u64,
    ) -> Result<Funding, Error> {
        let expected = hex::encode(urma_wallet::signing::script(signer)?.as_bytes());
        for output in self.utxos(signer)? {
            if output.value < minimum || !self.verified_output(&output, &expected)? {
                continue;
            }
            let block = self.call("getblockhash", &[json!(output.height)])?;
            let raw = self.call(
                "getrawtransaction",
                &[json!(output.txid), json!(false), block],
            )?;
            let funding = Funding {
                raw_transaction: raw.as_str().context("missing funding bytes")?.to_owned(),
                vout: output.vout,
            };
            let (outpoint, previous) = funding.prevout()?;
            ensure!(
                outpoint.txid == output.txid && previous.value.to_sat() == output.value,
                "funding transaction disagrees with scanned outpoint"
            );
            ensure!(
                previous.script_pubkey == urma_wallet::signing::script(signer)?,
                "funding identity mismatch"
            );
            return Ok(funding);
        }
        Err(Error::Missing(
            "no confirmed identity UTXO large enough; fund its address and confirm first".into(),
        ))
    }
}
