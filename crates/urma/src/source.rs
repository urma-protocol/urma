use crate::config::Limits;
use crate::config::{
    SOURCE_MAX_BLOCK_BYTES, SOURCE_MAX_JSON_BYTES, SOURCE_MAX_SCAN_BLOCKS, SOURCE_MAX_SCAN_BYTES,
    SOURCE_MAX_UTXOS,
};
use crate::error::{Context, Error, bail, ensure};
use crate::{
    backend::{self, Evidence, Family, Locator, Observation, RecordSource},
    container, envelope,
    transport::{self, Funding, Plan, Scan},
};
use bitcoin::{
    Address, Block, BlockHash, Network, Transaction, Txid, consensus::deserialize, hashes::Hash,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;

pub struct Source {
    url: String,
    network: Network,
    genesis: BlockHash,
}

#[derive(Clone, Deserialize)]
struct TxStatus {
    confirmed: bool,
    block_height: Option<u64>,
    block_hash: Option<BlockHash>,
}

#[derive(Deserialize)]
struct Utxo {
    txid: Txid,
    vout: u32,
    value: u64,
    status: TxStatus,
}

impl Source {
    pub(crate) fn endpoint(&self) -> &str {
        &self.url
    }

    pub(crate) fn confirmed_funding(&self, plan: &Plan) -> Result<(), Error> {
        ensure!(
            plan.network == self.network.to_string(),
            "funding network mismatch"
        );
        let raw = hex::decode(&plan.funding.raw_transaction)?;
        let expected: Transaction = deserialize(&raw)?;
        let txid = expected.compute_txid();
        let tip = self.height()?;
        let tip_hash = self.block_hash(tip)?;
        let (found, found_raw) = self.transaction(txid)?;
        ensure!(
            found == expected && found_raw == raw,
            "funding transaction/witness differs from journal"
        );
        ensure!(
            usize::try_from(plan.funding.vout)? < found.output.len(),
            "funding vout absent"
        );
        let status: TxStatus = self.json(&format!("/tx/{txid}/status"))?;
        ensure!(
            self.verify_confirmation(&found, &status, tip)? >= 1,
            "funding must be confirmed before relay"
        );
        self.require_unspent(txid, plan.funding.vout)?;
        ensure!(
            self.block_hash(tip)? == tip_hash,
            "source chain changed during relay preflight"
        );
        Ok(())
    }

    pub(crate) fn require_unspent(&self, txid: Txid, vout: u32) -> Result<(), Error> {
        let status: Value = self.json(&format!("/tx/{txid}/outspend/{vout}"))?;
        ensure!(
            status["spent"].as_bool() == Some(false),
            "relay input is spent or unspentness is unknown"
        );
        Ok(())
    }

    pub fn connect(url: &str, network: &Network) -> Result<Self, Error> {
        ensure!(
            matches!(network, Network::Regtest | Network::Testnet4),
            "only regtest and testnet4 are supported"
        );
        let url = checked_url(url)?;
        let genesis = bitcoin::blockdata::constants::genesis_block(*network).block_hash();
        let source = Self {
            url,
            network: *network,
            genesis,
        };
        ensure!(
            source.block_hash(0)? == genesis,
            "source genesis differs from requested network"
        );
        Ok(source)
    }

    fn get_optional(&self, path: &str, limit: usize) -> Result<Option<Vec<u8>>, Error> {
        let response = minreq::get(format!("{}{path}", self.url))
            .with_timeout(20)
            .with_max_redirects(0)
            .with_max_headers_size(16_384)
            .with_max_status_line_length(1_024)
            .with_header("Cache-Control", "no-cache")
            .send_lazy()
            .with_context(|| format!("source GET {path}"))?;
        if response.status_code == 404 {
            return Ok(None);
        }
        ensure!(
            response.status_code == 200,
            "source GET {path}: HTTP {}",
            response.status_code
        );
        let length_header = response.headers.get("content-length");
        for length in length_header.iter() {
            ensure!(
                length
                    .parse::<usize>()
                    .context("invalid source content length")?
                    <= limit,
                "source response exceeds byte limit"
            );
        }
        let mut bytes = Vec::new();
        for byte in response.take(limit + 1) {
            bytes.push(byte?.0);
        }
        ensure!(bytes.len() <= limit, "source response exceeds byte limit");
        Ok(Some(bytes))
    }

    fn get(&self, path: &str, limit: usize) -> Result<Vec<u8>, Error> {
        self.get_optional(path, limit)?
            .with_context(|| format!("source GET {path}: not found"))
    }

    fn json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        serde_json::from_slice(&self.get(path, SOURCE_MAX_JSON_BYTES)?)
            .with_context(|| format!("invalid source JSON: {path}"))
    }

    pub fn height(&self) -> Result<u64, Error> {
        std::str::from_utf8(&self.get("/blocks/tip/height", 32)?)?
            .trim()
            .parse()
            .context("invalid source tip height")
    }

    pub fn block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        BlockHash::from_str(
            std::str::from_utf8(&self.get(&format!("/block-height/{height}"), 128)?)?.trim(),
        )
        .context("invalid source block hash")
    }

    fn block(&self, hash: BlockHash) -> Result<(Block, usize), Error> {
        let bytes = self.get(&format!("/block/{hash}/raw"), SOURCE_MAX_BLOCK_BYTES)?;
        let block: Block = deserialize(&bytes).context("invalid source raw block")?;
        transport::validate_block_for_network(&block, hash, self.network)?;
        Ok((block, bytes.len()))
    }

    fn transaction(&self, txid: Txid) -> Result<(Transaction, Vec<u8>), Error> {
        self.transaction_optional(txid)?
            .with_context(|| format!("source transaction {txid}: not found"))
    }

    fn transaction_optional(&self, txid: Txid) -> Result<Option<(Transaction, Vec<u8>)>, Error> {
        let Some(bytes) = self.get_optional(&format!("/tx/{txid}/raw"), SOURCE_MAX_BLOCK_BYTES)?
        else {
            return Ok(None);
        };
        let tx: Transaction = deserialize(&bytes).context("invalid source raw transaction")?;
        ensure!(tx.compute_txid() == txid, "source transaction ID mismatch");
        Ok(Some((tx, bytes)))
    }

    pub fn transaction_bundle(&self, txids: &[Txid]) -> Result<(Vec<u8>, Value), Error> {
        ensure!(
            !txids.is_empty() && txids.len() <= Limits::RECORDS,
            "transaction fetch requires 1..={} transaction IDs",
            Limits::RECORDS
        );
        let mut records = Vec::new();
        let mut observations = Vec::new();
        let mut fetched_bytes = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for &txid in txids {
            ensure!(seen.insert(txid), "duplicate transaction ID");
            let (tx, raw) = self.transaction(txid)?;
            fetched_bytes = fetched_bytes
                .checked_add(raw.len())
                .context("fetch byte overflow")?;
            ensure!(
                fetched_bytes <= 8_000_000,
                "transaction fetch exceeds byte limit"
            );
            let status: TxStatus = self.json(&format!("/tx/{txid}/status"))?;
            status.validate()?;
            for input in &tx.input {
                if envelope::is_candidate(&input.witness) {
                    envelope::extract_reveal(&tx)?;
                    let (commit, commit_raw) =
                        self.transaction(tx.input[0].previous_output.txid)?;
                    fetched_bytes = fetched_bytes
                        .checked_add(commit_raw.len())
                        .context("fetch byte overflow")?;
                    ensure!(
                        fetched_bytes <= 8_000_000,
                        "transaction fetch exceeds byte limit"
                    );
                    let record = envelope::verify_reveal(&tx, &commit)?.record;
                    ensure!(
                        records.len() < Limits::RECORDS,
                        "bundle record limit reached"
                    );
                    container::inspect_header(&record)?;
                    records.push(record);
                }
            }
            observations.push(json!({
                "txid": txid.to_string(), "wtxid": tx.compute_wtxid().to_string(),
                "raw_bytes": raw.len(),
                "state": if status.confirmed { "provider_reported_confirmed" } else { "provider_reported_pending" },
                "block_height": status.block_height,
                "block_hash": status.block_hash.map(|h| h.to_string())
            }));
        }
        ensure!(
            !records.is_empty(),
            "no private URMA records in fetched transactions"
        );
        let bundle = container::pack(&records)?;
        let report = json!({
            "status": "fetched", "network": self.network.to_string(), "provider": self.url,
            "transactions": observations, "records": records.len(), "fetched_bytes": fetched_bytes,
            "bundle_bytes": bundle.len(), "chain_inclusion_verified": false,
            "content_authenticated": false, "evidence": "provider_transaction_bytes",
            "note": "Transient provider availability, not atomic/global mempool membership or block inclusion. Authenticate/decrypt the bundle separately; no key or sender journal was used to fetch it."
        });
        Ok((bundle, report))
    }

    fn observe_transaction(
        &self,
        tx: &Transaction,
        raw: &[u8],
        tip_height: u64,
    ) -> Result<Value, Error> {
        let txid = tx.compute_txid();
        let Some((found, found_raw)) = self.transaction_optional(txid)? else {
            return Ok(json!({"txid": txid.to_string(), "state": "unknown", "confirmations": 0}));
        };
        ensure!(
            found == *tx && found_raw == raw,
            "source transaction witness differs from prepared plan"
        );
        let status: TxStatus = self.json(&format!("/tx/{txid}/status"))?;
        let confirmations = self.verify_confirmation(&found, &status, tip_height)?;
        Ok(
            json!({"txid": txid.to_string(), "state": if status.confirmed {"confirmed"} else {"pending"},
            "confirmations": confirmations, "block_height": status.block_height, "block_hash": status.block_hash.map(|h| h.to_string())}),
        )
    }

    fn verify_confirmation(
        &self,
        tx: &Transaction,
        status: &TxStatus,
        tip: u64,
    ) -> Result<u64, Error> {
        if !status.confirmed {
            status.validate()?;
            return Ok(0);
        }
        let height = status
            .block_height
            .context("confirmed source status lacks block height")?;
        let hash = status
            .block_hash
            .context("confirmed source status lacks block hash")?;
        ensure!(height <= tip, "confirmation is beyond source tip snapshot");
        ensure!(
            self.block_hash(height)? == hash,
            "source confirmation block is not active"
        );
        let (block, _) = self.block(hash)?;
        ensure!(
            block.txdata.iter().any(|candidate| candidate == tx),
            "source transaction or witness absent from claimed block"
        );
        Ok(tip - height + 1)
    }

    pub fn funding(
        &self,
        address: &str,
        allow_unconfirmed: bool,
    ) -> Result<(Funding, Value), Error> {
        let address = Address::from_str(address)?.require_network(self.network)?;
        ensure!(
            address.script_pubkey().is_p2wpkh(),
            "funding requires a native P2WPKH address"
        );
        let tip_height = self.height()?;
        let tip_hash = self.block_hash(tip_height)?;
        let mut utxos: Vec<Utxo> = self.json(&format!("/address/{address}/utxo"))?;
        ensure!(utxos.len() <= SOURCE_MAX_UTXOS, "source UTXO limit reached");
        utxos.retain(|u| u.status.confirmed || allow_unconfirmed);
        utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
        let utxo = utxos.first().context(
            "no eligible source UTXO; pending funding requires explicit prepare-only opt-in",
        )?;
        let (tx, raw) = self.transaction(utxo.txid)?;
        ensure!(
            !tx.is_coinbase(),
            "coinbase funding is unsupported; use a regular faucet output"
        );
        let output = tx
            .output
            .get(usize::try_from(utxo.vout)?)
            .context("source funding vout is absent")?;
        ensure!(
            output.script_pubkey == address.script_pubkey(),
            "source funding address/script mismatch"
        );
        ensure!(
            output.value.to_sat() == utxo.value && utxo.value > 0,
            "source funding amount mismatch"
        );
        let status: TxStatus = self.json(&format!("/tx/{}/status", utxo.txid))?;
        ensure!(
            status.confirmed == utxo.status.confirmed
                && status.block_hash == utxo.status.block_hash
                && status.block_height == utxo.status.block_height,
            "source funding status changed; retry"
        );
        let confirmations = self.verify_confirmation(&tx, &status, tip_height)?;
        let outspend: Value = self.json(&format!("/tx/{}/outspend/{}", utxo.txid, utxo.vout))?;
        ensure!(
            outspend["spent"].as_bool() == Some(false),
            "source funding output is spent or status is missing"
        );
        ensure!(
            self.block_hash(tip_height)? == tip_hash,
            "source chain changed during funding lookup; retry"
        );
        let report = json!({
            "network": self.network.to_string(), "provider": self.url, "genesis": self.genesis.to_string(),
            "status": if status.confirmed { "confirmed" } else { "pending" }, "confirmed": status.confirmed,
            "txid": utxo.txid.to_string(), "vout": utxo.vout, "outpoint": format!("{}:{}", utxo.txid, utxo.vout),
            "value_sats": utxo.value, "height": status.block_height, "confirmations": confirmations,
            "tip_height": tip_height, "tip_hash": tip_hash.to_string(), "start_height": tip_height,
            "recommended_start_height": tip_height, "prepare_only": !status.confirmed,
            "verification": if status.confirmed {
                "raw transaction and confirmed block contents verified; provider trusted for chain selection and unspentness; header-chain difficulty transitions are not independently validated"
            } else {
                "raw transaction verified; provider reports pending and unspent; no confirmed block inclusion verified; provider trusted for chain selection and unspentness"
            }
        });
        Ok((
            Funding {
                raw_transaction: hex::encode(raw),
                vout: utxo.vout,
            },
            report,
        ))
    }

    pub fn scan(&self, key: &[u8; 32], start_height: u64) -> Result<Scan, Error> {
        Scan::from_recovery(backend::recover(
            &ExplorerRecords {
                source: self,
                start_height,
            },
            key,
        )?)
    }

    fn read_records(
        &self,
        start_height: u64,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        self.read_range(
            start_height,
            u64::MAX,
            &mut |height| {
                tracing::trace!(height, "scan progress");
                Ok(())
            },
            emit,
        )
    }

    pub fn read_range(
        &self,
        start_height: u64,
        tip_height: u64,
        progress: &mut dyn FnMut(u64) -> Result<(), Error>,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        let current = self.height()?;
        let tip_height = if tip_height == u64::MAX {
            current
        } else {
            tip_height
        };
        ensure!(tip_height <= current, "end height beyond source tip");
        ensure!(
            start_height <= tip_height,
            "start height is beyond source tip"
        );
        ensure!(
            tip_height - start_height < SOURCE_MAX_SCAN_BLOCKS,
            "scan block limit reached; narrow starting height"
        );
        let tip_hash = self.block_hash(tip_height)?;
        let mut previous = if start_height == 0 {
            BlockHash::all_zeros()
        } else {
            self.block_hash(start_height - 1)?
        };
        let mut scanned_bytes = 0usize;
        for height in start_height..=tip_height {
            progress(height)?;
            let hash = self.block_hash(height)?;
            let (block, length) = self
                .block(hash)
                .with_context(|| format!("source block {height}"))?;
            scanned_bytes = scanned_bytes
                .checked_add(length)
                .context("scan byte overflow")?;
            ensure!(
                scanned_bytes <= SOURCE_MAX_SCAN_BYTES,
                "scan byte limit reached; narrow starting height"
            );
            ensure!(
                block.header.prev_blockhash == previous,
                "source chain changed during scan"
            );
            previous = hash;
            self.emit_verified_records(&block, emit)?;
        }
        ensure!(
            previous == tip_hash && self.block_hash(tip_height)? == tip_hash,
            "source chain changed during scan; retry recovery"
        );
        Ok(Observation {
            backend: Family::Bitcoin,
            locator: Locator::BlockRange {
                network: self.network.to_string(),
                start_height,
                tip_height,
                tip_hash: tip_hash.to_string(),
            },
            evidence: Evidence::CommitmentsAndProviderChain,
            scanned_bytes,
        })
    }

    pub fn status_plan(&self, plan: &Plan) -> Result<Value, Error> {
        let mut report = transport::validate_plan(plan)?;
        ensure!(
            plan.network == self.network.to_string(),
            "source network differs from plan network"
        );
        let tip_height = self.height()?;
        let tip_hash = self.block_hash(tip_height)?;
        let mut statuses = Vec::new();
        for encoded in std::iter::once(&plan.commit).chain(plan.reveals.iter()) {
            let raw = hex::decode(encoded)?;
            let tx: Transaction = deserialize(&raw)?;
            statuses.push(self.observe_transaction(&tx, &raw, tip_height)?);
        }
        ensure!(
            self.block_hash(tip_height)? == tip_hash,
            "source chain changed during status lookup; retry"
        );
        let commit = &statuses[0];
        let reveals = &statuses[1..];
        let status = if commit["state"] == "unknown" {
            ensure!(
                reveals.iter().all(|s| s["state"] == "unknown"),
                "source knows reveal while commit is absent"
            );
            "prepared"
        } else if commit["state"] == "pending" {
            ensure!(
                reveals.iter().all(|s| s["state"] != "confirmed"),
                "source confirms reveal while commit is pending"
            );
            "commit_pending"
        } else if reveals.iter().all(|s| s["state"] == "confirmed") {
            "confirmed"
        } else if reveals.iter().any(|s| s["state"] == "unknown") {
            "awaiting_reveals"
        } else {
            "confirming"
        };
        report["status"] = json!(status);
        report["provider"] = json!(self.url);
        report["tip_height"] = json!(tip_height);
        report["tip_hash"] = json!(tip_hash.to_string());
        report["commit_status"] = commit.clone();
        report["reveal_statuses"] = json!(reveals);
        let known_count = statuses.iter().filter(|s| s["state"] != "unknown").count();
        let confirmed_count = statuses
            .iter()
            .filter(|s| s["state"] == "confirmed")
            .count();
        report["verified_transaction_count"] = json!(known_count);
        report["verified_confirmed_transaction_count"] = json!(confirmed_count);
        report["verification"] = json!(format!(
            "{known_count} source transactions matched prepared bytes and witnesses; {confirmed_count} confirmed transactions verified inside blocks; provider trusted for chain selection; header-chain difficulty transitions are not independently validated"
        ));
        Ok(report)
    }
}

pub struct ExplorerRecords<'a> {
    pub source: &'a Source,
    pub start_height: u64,
}

impl RecordSource for ExplorerRecords<'_> {
    fn read_records(
        &self,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        self.source.read_records(self.start_height, emit)
    }
}

fn checked_url(input: &str) -> Result<String, Error> {
    let url = url::Url::parse(input).context("invalid source URL")?;
    match (url.password(), url.query(), url.fragment()) {
        (None, None, None) => {}
        components => {
            tracing::warn!(
                component_count = [components.0, components.1, components.2].iter().count(),
                "forbidden URL components"
            );
            bail!("URL credentials, query and fragment are forbidden");
        }
    }
    ensure!(
        url.username().is_empty(),
        "source URL cannot contain credentials, query, or fragment"
    );
    let local = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain == "localhost",
        None => return Err(Error::Missing("source URL has no host".into())),
    };
    match url.scheme() {
        "https" => (),
        "http" if local => (),
        _ => bail!("source requires HTTPS; HTTP is allowed only on localhost"),
    }

    Ok(url.as_str().trim_end_matches('/').to_owned())
}

impl TxStatus {
    fn validate(&self) -> Result<(), Error> {
        match (&self.block_hash, self.block_height) {
            (Some(hash), Some(height)) => ensure!(
                self.confirmed,
                "unconfirmed transaction includes block {hash} at {height}"
            ),
            (None, None) => ensure!(
                !self.confirmed,
                "confirmed transaction lacks block location"
            ),
            (Some(hash), None) => bail!("block {hash} lacks height"),
            (None, Some(height)) => bail!("block at height {height} lacks hash"),
        }
        Ok(())
    }
}

impl Source {
    fn emit_verified_records(
        &self,
        block: &Block,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for tx in &block.txdata {
            if !tx
                .input
                .iter()
                .any(|input| envelope::is_candidate(&input.witness))
            {
                continue;
            }
            match envelope::extract_reveal(tx) {
                Ok(parsed) => {
                    tracing::trace!(author=%parsed.author, "candidate with canonical transaction shape")
                }
                Err(error) => {
                    tracing::warn!(%error, "invalid reveal rejected");
                    continue;
                }
            }
            let (commit, raw) = self.transaction(tx.input[0].previous_output.txid)?;
            ensure!(
                raw.len() <= SOURCE_MAX_BLOCK_BYTES,
                "commit proof exceeds capacity"
            );
            match envelope::verify_reveal(tx, &commit) {
                Ok(parsed) => emit(&parsed.record)?,
                Err(error) => tracing::warn!(%error, "invalid author proof rejected"),
            }
        }
        Ok(())
    }
}
