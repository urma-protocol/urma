use bitcoin::{Transaction, Txid, consensus::deserialize};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma::error::{Context, Error, ensure};
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;
use urma_wallet::funding::Funding;

#[derive(Clone)]
pub struct NodeConfig {
    pub chain: Chain,
    pub rpc_url: String,
    pub cookie_file: PathBuf,
}

pub struct Node {
    config: NodeConfig,
    client: Client,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        let node = Self { config, client };
        node.verify_network()?;
        Ok(node)
    }

    pub fn chain(&self) -> Chain {
        self.config.chain
    }

    pub fn tip_height(&self) -> Result<u64, Error> {
        Ok(self.tip()?.0)
    }

    pub fn block_hash(&self, height: u64) -> Result<bitcoin::BlockHash, Error> {
        let value = self.call("getblockhash", &[json!(height)])?;
        Ok(value.as_str().context("missing block hash")?.parse()?)
    }

    pub fn block(&self, height: u64) -> Result<bitcoin::Block, Error> {
        let hash = self.block_hash(height)?;
        let value = self.call("getblock", &[json!(hash), json!(0)])?;
        let block: bitcoin::Block = deserialize(&hex::decode(
            value.as_str().context("missing block bytes")?,
        )?)?;
        ensure!(block.block_hash() == hash, "RPC block hash mismatch");
        ensure!(block.check_merkle_root(), "RPC block merkle root mismatch");
        Ok(block)
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
        Ok(self.client.call(method, args)?)
    }

    pub fn require_txindex(&self) -> Result<(), Error> {
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
        let transaction: Transaction = deserialize(&hex::decode(
            raw.as_str().context("missing raw transaction")?,
        )?)?;
        ensure!(
            transaction.compute_txid() == txid,
            "RPC transaction hash mismatch"
        );
        Ok(transaction)
    }

    pub fn presence(&self, txid: Txid) -> Result<Presence, Error> {
        let result = self
            .client
            .call::<Value>("getrawtransaction", &[json!(txid), json!(true)]);
        let value = match result {
            Ok(value) => value,
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(error)))
                if error.code == -5 =>
            {
                tracing::warn!(code = error.code, "transaction absent from node");
                return Ok(Presence::Missing);
            }
            Err(error) => return Err(error.into()),
        };
        if urma::config::confirmations(&value)? <= 0 {
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
        let header = self.call("getblockheader", &[json!(hash)])?;
        let height = header["height"]
            .as_u64()
            .context("missing inclusion height")?;
        let active = self.call("getblockhash", &[json!(height)])?;
        if active != json!(hash) {
            return Ok(Presence::Missing);
        }
        Ok(Presence::Confirmed {
            height,
            block_hash: hash.to_owned(),
        })
    }

    pub fn utxos(&self, signer: &impl IdentitySigner) -> Result<Vec<Utxo>, Error> {
        self.verify_network()?;
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

    pub fn available_utxos(&self, signer: &impl IdentitySigner) -> Result<Vec<Utxo>, Error> {
        let expected = hex::encode(urma_wallet::signing::script(signer)?.as_bytes());
        let mut available = Vec::new();
        for output in self.utxos(signer)? {
            let unspent = self.call(
                "gettxout",
                &[json!(output.txid), json!(output.vout), json!(true)],
            )?;
            if unspent.is_null() {
                continue;
            }
            let confirmations = urma::config::confirmations(&unspent)?;
            if confirmations < 1 || (unspent["coinbase"] == true && confirmations < 100) {
                continue;
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
            available.push(output);
        }
        Ok(available)
    }

    pub fn select_funding(
        &self,
        signer: &impl IdentitySigner,
        minimum: u64,
    ) -> Result<Funding, Error> {
        for output in self.available_utxos(signer)? {
            if output.value < minimum {
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
