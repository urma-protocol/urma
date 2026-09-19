use crate::commitment::{PreparedReveal, transaction};
use crate::config::Limits;
use crate::config::MempoolPresence;
use crate::config::{BITCOIN_MAX_FEE_RATE, BITCOIN_MAX_FEE_SATS, BITCOIN_RETURN_SATS};
use crate::config::{RevealSelection, RpcScope, TxPresence};
use crate::error::{Context, Error, bail, ensure};
use crate::format::Urma;
use crate::journal::decode_transaction;
pub use crate::journal::{Funding, Plan, validate_plan};
use crate::{
    backend::{self, Evidence, Family, Locator, Observation, RecordSource},
    container::{self, PrivateObject},
    envelope,
};
use bitcoin::{
    Address, Amount, Block, BlockHash, Network, OutPoint, Transaction, TxOut, Txid, Witness,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, str::FromStr};

pub struct Node {
    rpc: Client,
    network: Network,
}

impl Node {
    pub fn connect(url: &str, cookie: &Path, wallet: RpcScope<'_>) -> Result<Self, Error> {
        let mut endpoint = url.trim_end_matches('/').to_owned();
        if let RpcScope::Wallet(wallet) = wallet {
            ensure!(
                !wallet.is_empty()
                    && wallet
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "wallet name must contain only letters, numbers, '-' or '_'"
            );
            endpoint.push_str(&format!("/wallet/{wallet}"));
        }
        let rpc = Client::new(&endpoint, Auth::CookieFile(cookie.to_path_buf()))?;
        let info: Value = rpc.call("getblockchaininfo", &[])?;
        let network = supported_network(info["chain"].as_str().context("missing node chain")?)?;
        Ok(Self { rpc, network })
    }

    pub fn connect_for_network(
        url: &str,
        cookie: &Path,
        wallet: RpcScope<'_>,
        network: Network,
    ) -> Result<Self, Error> {
        ensure!(
            matches!(network, Network::Regtest | Network::Testnet4),
            "only regtest and testnet4 are supported"
        );
        let node = Self::connect(url, cookie, wallet)?;
        ensure!(
            node.network == network,
            "RPC node network differs from requested network"
        );
        Ok(node)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        self.rpc
            .call(method, args)
            .with_context(|| format!("Bitcoin RPC {method}"))
    }

    fn height(&self) -> Result<u64, Error> {
        self.call("getblockcount", &[])?
            .as_u64()
            .context("invalid block count")
    }

    fn block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        let value = self.call("getblockhash", &[json!(height)])?;
        BlockHash::from_str(value.as_str().context("invalid block hash")?).map_err(Into::into)
    }

    fn address(&self) -> Result<Address, Error> {
        let value = self.call("getnewaddress", &[json!("urma-lab"), json!("bech32m")])?;
        Ok(
            Address::from_str(value.as_str().context("invalid address")?)?
                .require_network(self.network)?,
        )
    }

    fn require_owned(&self, address: &Address) -> Result<(), Error> {
        let info = self.call("getaddressinfo", &[json!(address.to_string())])?;
        ensure!(
            info["ismine"] == true && info["solvable"] == true,
            "wallet does not own and solve address {address}"
        );
        Ok(())
    }

    fn confirmations(&self, txid: Txid) -> Result<TxPresence, Error> {
        match self
            .rpc
            .call::<Value>("gettransaction", &[json!(txid.to_string())])
        {
            Ok(value) => Ok(TxPresence::Observed(
                value["confirmations"]
                    .as_i64()
                    .context("missing confirmations")?,
            )),
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                e,
            ))) if e.code == -5 => {
                tracing::warn!(code = e.code, "transaction absent");
                Ok(TxPresence::Missing)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn submit(&self, raw: &str) -> Result<Txid, Error> {
        let tx: Transaction = deserialize(&hex::decode(raw)?)?;
        let txid = tx.compute_txid();
        match self.confirmations(txid)? {
            TxPresence::Observed(n) if n < 0 => {
                bail!("transaction {txid} conflicts with the active chain")
            }
            TxPresence::Observed(n) if n > 0 => return Ok(txid),
            TxPresence::Observed(count) => ensure!(count == 0, "invalid confirmation count"),
            TxPresence::Missing => (),
        }
        match self
            .rpc
            .call::<Value>("getmempoolentry", &[json!(txid.to_string())])
        {
            Ok(entry) => {
                ensure!(entry.is_object(), "invalid mempool entry");
                return Ok(txid);
            }
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                e,
            ))) if e.code == -5 => {
                tracing::warn!(code = e.code, "transaction absent from mempool");
            }
            Err(error) => return Err(error.into()),
        }
        let acceptance = self.call("testmempoolaccept", &[json!([raw])])?;
        ensure!(
            acceptance[0]["allowed"] == true,
            "policy rejected {txid}: {}",
            acceptance[0]
        );
        let result = self.call("sendrawtransaction", &[json!(raw)])?;
        ensure!(
            result == txid.to_string(),
            "broadcast returned a different transaction ID"
        );
        Ok(txid)
    }

    fn mine(&self, destination: &str) -> Result<(), Error> {
        ensure!(
            self.network == Network::Regtest,
            "mining is restricted to regtest"
        );
        self.call("generatetoaddress", &[json!(1), json!(destination)])?;
        Ok(())
    }
}

pub(crate) fn supported_network(network: &str) -> Result<Network, Error> {
    match network {
        "regtest" => Ok(Network::Regtest),
        "testnet4" => Ok(Network::Testnet4),
        _ => bail!("only regtest and testnet4 are supported"),
    }
}

pub fn prepare(node: &Node, records: &[Vec<u8>], input_bytes: usize) -> Result<Plan, Error> {
    ensure!(
        node.network == Network::Regtest,
        "testnet4 preparation requires explicit funding"
    );
    let unspent = node.call("listunspent", &[json!(1)])?;
    let coins = unspent.as_array().context("invalid unspent response")?;
    let mut eligible = Vec::new();
    for coin in coins {
        if !coin["spendable"]
            .as_bool()
            .context("missing spendable flag")?
        {
            continue;
        }
        let script = coin["scriptPubKey"]
            .as_str()
            .context("missing coin script")?;
        if !script.starts_with("0014") {
            continue;
        }
        let amount = Amount::from_btc(coin["amount"].as_f64().context("missing coin amount")?)?;
        eligible.push((amount, coin));
    }
    let selected = eligible
        .iter()
        .max_by_key(|(amount, coin)| (*amount, coin["txid"].to_string()))
        .context("wallet has no confirmed spendable native P2WPKH coin")?
        .1;
    let previous = node.call("gettransaction", &[selected["txid"].clone()])?;
    let funding = Funding {
        raw_transaction: previous["hex"]
            .as_str()
            .context("missing funding transaction")?
            .to_owned(),
        vout: u32::try_from(selected["vout"].as_u64().context("missing funding vout")?)?,
    };
    prepare_with_funding(node, records, input_bytes, &funding, 1)
}

pub fn prepare_with_funding(
    node: &Node,
    records: &[Vec<u8>],
    input_bytes: usize,
    funding: &Funding,
    fee_rate: u64,
) -> Result<Plan, Error> {
    validate_preparation(records, input_bytes, fee_rate)?;
    let (funding_outpoint, funding_output) = funding.prevout()?;
    let funding_address = Address::from_script(&funding_output.script_pubkey, node.network)?;
    node.require_owned(&funding_address)?;
    let start_height = node.height()?;
    let return_address = node.address()?;
    node.require_owned(&return_address)?;
    let mut pending = Vec::with_capacity(records.len());
    for record in records {
        pending.push(PreparedReveal::new(
            record,
            &return_address.script_pubkey(),
            fee_rate,
            &mut OsRng,
        )?);
    }
    let outputs: Vec<TxOut> = pending.iter().map(PreparedReveal::output).collect();
    let reveal_fee_sats: u64 = pending.iter().map(|item| item.fee).sum();
    let (commit_tx, commit_fee_sats) = fund_commit(
        funding_outpoint,
        &funding_output,
        &return_address,
        outputs,
        fee_rate,
        reveal_fee_sats,
    )?;
    let commit_tx = sign_commit(node, &commit_tx, funding_outpoint, &funding_output)?;
    ensure!(
        commit_fee_sats >= u64::try_from(commit_tx.vsize())? * fee_rate,
        "signed commit exceeds fee estimate"
    );
    let mut reveals = Vec::with_capacity(pending.len());
    for (index, prepared) in pending.into_iter().enumerate() {
        reveals.push(hex::encode(serialize(&prepared.sign(
            &commit_tx,
            u32::try_from(index)?,
            &return_address.script_pubkey(),
        )?)));
    }
    let plan = Plan {
        version: Urma::VERSION,
        network: node.network.to_string(),
        object_id: hex::encode(container::inspect_header(&records[0])?.id),
        start_height,
        input_bytes,
        fee_sats: commit_fee_sats + reveal_fee_sats,
        commit_fee_sats,
        reveal_fee_sats,
        fee_rate_sat_vb: fee_rate,
        funding: funding.clone(),
        commit: hex::encode(serialize(&commit_tx)),
        reveals,
        mining_address: return_address.to_string(),
    };
    validate_plan(&plan)?;
    Ok(plan)
}

fn validate_plan_for_node(node: &Node, plan: &Plan) -> Result<(), Error> {
    validate_plan(plan)?;
    ensure!(
        node.network == supported_network(&plan.network)?,
        "journal and RPC networks differ"
    );
    let payout = Address::from_str(&plan.mining_address)?.require_network(node.network)?;
    node.require_owned(&payout)?;
    let (_, previous) = plan.funding.prevout()?;
    node.require_owned(&Address::from_script(
        &previous.script_pubkey,
        node.network,
    )?)?;
    Ok(())
}

fn transaction_status(node: &Node, raw: &str) -> Result<Value, Error> {
    let id = decode_transaction(raw)?.compute_txid();
    let confirmations = node.confirmations(id)?;
    let in_mempool = match node
        .rpc
        .call::<Value>("getmempoolentry", &[json!(id.to_string())])
    {
        Ok(entry) => {
            ensure!(entry.is_object(), "invalid mempool entry");
            MempoolPresence::Present
        }
        Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
            error,
        ))) if error.code == -5 => {
            tracing::warn!(?error, "transaction absent from mempool");
            MempoolPresence::Absent
        }
        Err(error) => return Err(error.into()),
    };
    let status = match (confirmations, in_mempool) {
        (TxPresence::Observed(n), _) if n < 0 => "conflicted",
        (TxPresence::Observed(n), _) if n > 0 => "confirmed",
        (_, MempoolPresence::Present) => "mempool",
        (TxPresence::Observed(0), MempoolPresence::Absent) => "unconfirmed_not_in_mempool",
        (TxPresence::Observed(n), MempoolPresence::Absent) => bail!("unexpected confirmations {n}"),
        (TxPresence::Missing, MempoolPresence::Absent) => "unknown",
    };
    let count = match confirmations {
        TxPresence::Missing => Value::Null,
        TxPresence::Observed(n) => json!(n),
    };
    Ok(
        json!({"txid": id.to_string(), "status": status, "confirmations": count,
        "in_mempool": matches!(in_mempool, MempoolPresence::Present)}),
    )
}

pub fn status_plan(node: &Node, plan: &Plan) -> Result<Value, Error> {
    validate_plan(plan)?;
    ensure!(
        node.network == supported_network(&plan.network)?,
        "journal and RPC networks differ"
    );
    let commit = transaction_status(node, &plan.commit)?;
    let reveals = plan
        .reveals
        .iter()
        .map(|raw| transaction_status(node, raw))
        .collect::<Result<Vec<_>, Error>>()?;
    let confirmed = reveals
        .iter()
        .filter(|status| status["status"] == "confirmed")
        .count();
    let conflicted =
        commit["status"] == "conflicted" || reveals.iter().any(|s| s["status"] == "conflicted");
    let status = if conflicted {
        "conflicted"
    } else if confirmed == reveals.len() && commit["status"] == "confirmed" {
        "confirmed"
    } else if commit["status"] == "confirmed" {
        "reveals_pending"
    } else if commit["status"] == "mempool" {
        "commit_pending"
    } else if commit["status"] == "unconfirmed_not_in_mempool" {
        "commit_unconfirmed_not_in_mempool"
    } else if reveals.iter().all(|reveal| reveal["status"] == "unknown") {
        "unknown"
    } else {
        "inconsistent_node_view"
    };
    Ok(json!({"status": status,
        "network": plan.network, "object_id": plan.object_id, "start_height": plan.start_height,
        "planned_fee_sats": plan.fee_sats, "confirmed_chunks": confirmed, "total_chunks": reveals.len(),
        "source": "local_rpc", "commit": commit, "reveals": reveals}))
}

pub fn broadcast_plan(
    node: &Node,
    plan: &Plan,
    reveal_limit: RevealSelection,
) -> Result<Value, Error> {
    validate_plan_for_node(node, plan)?;
    let commit_id = decode_transaction(&plan.commit)?.compute_txid();
    if !node.confirmations(commit_id)?.confirmed() {
        let (outpoint, previous) = plan.funding.prevout()?;
        let coin = node.call(
            "gettxout",
            &[
                json!(outpoint.txid.to_string()),
                json!(outpoint.vout),
                json!(false),
            ],
        )?;
        ensure!(
            coin["confirmations"]
                .as_u64()
                .context("missing funding confirmations")?
                >= 1,
            "funding must be confirmed and unspent in the node's chain before broadcast"
        );
        ensure!(
            coin["scriptPubKey"]["hex"] == hex::encode(previous.script_pubkey.as_bytes())
                && Amount::from_btc(coin["value"].as_f64().context("missing funding value")?)?
                    == previous.value,
            "funding node response differs from supplied previous transaction"
        );
    }
    node.submit(&plan.commit)?;
    if node.confirmations(commit_id)?.confirmed() {
        for raw in plan
            .reveals
            .iter()
            .take(reveal_limit.count(plan.reveals.len()))
        {
            node.submit(raw)?;
        }
    }
    status_plan(node, plan)
}

pub fn publish_plan(
    node: &Node,
    plan: &Plan,
    reveal_limit: RevealSelection,
) -> Result<Value, Error> {
    ensure!(
        node.network == Network::Regtest && plan.network == "regtest",
        "mining publication is restricted to regtest"
    );
    validate_plan_for_node(node, plan)?;
    let commit_id = node.submit(&plan.commit)?;
    if !node.confirmations(commit_id)?.confirmed() {
        node.mine(&plan.mining_address)?;
    }
    ensure!(
        node.confirmations(commit_id)?.confirmed(),
        "commit not confirmed; resume later"
    );
    let limit = reveal_limit.count(plan.reveals.len());
    let mut ids = Vec::new();
    let mut needs_mining = false;
    for raw in plan.reveals.iter().take(limit) {
        let id = node.submit(raw)?;
        needs_mining |= !node.confirmations(id)?.confirmed();
        ids.push(id);
    }
    if needs_mining {
        node.mine(&plan.mining_address)?;
    }
    for id in &ids {
        ensure!(
            node.confirmations(*id)?.confirmed(),
            "reveal {id} not confirmed; resume later"
        );
    }
    Ok(
        json!({ "status": if limit == plan.reveals.len() { "confirmed" } else { "interrupted" },
        "network": "regtest", "object_id": plan.object_id, "start_height": plan.start_height,
        "input_bytes": plan.input_bytes, "total_chunks": plan.reveals.len(),
        "confirmed_selected_chunks": ids.len(), "planned_fee_sats": plan.fee_sats,
        "commit_txid": commit_id.to_string(), "reveal_txids": ids.iter().map(ToString::to_string).collect::<Vec<_>>() }),
    )
}

pub fn validate_block(block: &Block, expected_hash: BlockHash) -> Result<(), Error> {
    ensure!(block.block_hash() == expected_hash, "block hash mismatch");
    ensure!(
        block.check_merkle_root(),
        "transaction Merkle root mismatch"
    );
    ensure!(
        block.check_witness_commitment(),
        "witness commitment mismatch"
    );
    block
        .header
        .validate_pow(block.header.target())
        .context("block proof of work")?;
    Ok(())
}

pub fn validate_block_for_network(
    block: &Block,
    expected_hash: BlockHash,
    network: Network,
) -> Result<(), Error> {
    ensure!(
        matches!(network, Network::Regtest | Network::Testnet4),
        "only regtest and testnet4 are supported"
    );
    ensure!(
        block.header.target() <= network.params().max_attainable_target,
        "block target exceeds network proof-of-work limit"
    );
    validate_block(block, expected_hash)
}

pub fn collect_records(
    block: &Block,
    key: &[u8; 32],
    objects: &mut BTreeMap<[u8; 32], PrivateObject>,
) -> Result<u64, Error> {
    let mut rejected = 0;
    for tx in &block.txdata {
        for input in &tx.input {
            if !envelope::is_candidate(&input.witness) {
                continue;
            }
            match envelope::extract(&input.witness) {
                Ok(parsed) => rejected += backend::accept_record(key, &parsed.record, objects)?,
                Err(error) => {
                    tracing::warn!(%error, "invalid URMA envelope rejected");
                    rejected += 1;
                }
            }
        }
    }
    Ok(rejected)
}

pub struct Scan {
    pub objects: BTreeMap<[u8; 32], PrivateObject>,
    pub start_height: u64,
    pub tip_height: u64,
    pub tip_hash: BlockHash,
    pub scanned_bytes: usize,
    pub rejected_records: u64,
}

impl Scan {
    pub fn from_recovery(recovery: backend::Recovery) -> Result<Self, Error> {
        let Locator::BlockRange {
            start_height,
            tip_height,
            tip_hash,
            ..
        } = recovery.observation.locator
        else {
            bail!("Bitcoin scan requires a block-range observation");
        };
        Ok(Self {
            objects: recovery.objects,
            rejected_records: recovery.rejected_records,
            start_height,
            tip_height,
            tip_hash: tip_hash.parse()?,
            scanned_bytes: recovery.observation.scanned_bytes,
        })
    }
}

pub struct BitcoinRecords<'a> {
    pub node: &'a Node,
    pub start_height: u64,
}

impl RecordSource for BitcoinRecords<'_> {
    fn read_records(
        &self,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        read_records(self.node, self.start_height, emit)
    }
}

pub fn emit_core_validated_records(
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
            Ok(parsed) => emit(&parsed.record)?,
            Err(error) => tracing::warn!(%error, "invalid URMA reveal rejected"),
        }
    }
    Ok(())
}

pub fn scan(node: &Node, key: &[u8; 32], start: u64) -> Result<Scan, Error> {
    Scan::from_recovery(backend::recover(
        &BitcoinRecords {
            node,
            start_height: start,
        },
        key,
    )?)
}

fn read_records(
    node: &Node,
    start: u64,
    emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<Observation, Error> {
    let tip_height = node.height()?;
    ensure!(start <= tip_height, "start height is beyond the chain tip");
    let tip_hash = node.block_hash(tip_height)?;
    let mut previous = if start == 0 {
        BlockHash::all_zeros()
    } else {
        node.block_hash(start - 1)?
    };
    let mut scanned_bytes = 0;
    for height in start..=tip_height {
        let hash = node.block_hash(height)?;
        let value = node.call("getblock", &[json!(hash.to_string()), json!(0)])?;
        let encoded = value.as_str().context("invalid raw block")?;
        ensure!(encoded.len() <= 8_000_000, "block exceeds byte limit");
        let raw = hex::decode(encoded)?;
        scanned_bytes += raw.len();
        let block: Block = deserialize(&raw)?;
        validate_block_for_network(&block, hash, node.network)
            .with_context(|| format!("validate block {height}"))?;
        ensure!(
            block.header.prev_blockhash == previous,
            "chain changed during scan"
        );
        previous = hash;
        emit_core_validated_records(&block, emit)?;
    }
    ensure!(
        previous == tip_hash && node.block_hash(tip_height)? == tip_hash,
        "chain changed during scan; retry recovery"
    );
    Ok(Observation {
        backend: Family::Bitcoin,
        locator: Locator::BlockRange {
            network: node.network.to_string(),
            start_height: start,
            tip_height,
            tip_hash: tip_hash.to_string(),
        },
        evidence: Evidence::CommitmentsAndCoreChain,
        scanned_bytes,
    })
}

fn sign_commit(
    node: &Node,
    commit_tx: &Transaction,
    funding_outpoint: OutPoint,
    funding_output: &TxOut,
) -> Result<Transaction, Error> {
    let signed = node.call(
        "signrawtransactionwithwallet",
        &[
            json!(hex::encode(serialize(&commit_tx))),
            json!([{
                "txid": funding_outpoint.txid.to_string(), "vout": funding_outpoint.vout,
                "scriptPubKey": hex::encode(funding_output.script_pubkey.as_bytes()),
                "amount": funding_output.value.to_btc()
            }]),
            json!("ALL"),
        ],
    )?;
    ensure!(
        signed["complete"] == true,
        "wallet did not fully sign commit"
    );
    let commit = signed["hex"]
        .as_str()
        .context("missing signed commit")?
        .to_owned();
    let commit_tx: Transaction = deserialize(&hex::decode(&commit)?)?;
    Ok(commit_tx)
}
fn validate_preparation(
    records: &[Vec<u8>],
    input_bytes: usize,
    fee_rate: u64,
) -> Result<(), Error> {
    if input_bytes > Limits::INPUT_BYTES {
        return Err(Error::Capacity("client input capacity exceeded".into()));
    }

    ensure!(
        (1..=Limits::INPUT_BYTES).contains(&input_bytes)
            && records.len() == input_bytes.div_ceil(Urma::CHUNK_BYTES),
        "invalid publication input size/count"
    );
    let first = container::inspect_header(&records[0])?;
    for (index, record) in records.iter().enumerate() {
        let header = container::inspect_header(record)?;
        ensure!(
            header.id == first.id
                && header.discovery_tag == first.discovery_tag
                && usize::try_from(header.index)? == index
                && usize::try_from(header.count)? == records.len(),
            "publication requires one ordered complete opaque record set"
        );
    }
    ensure!(
        (1..=BITCOIN_MAX_FEE_RATE).contains(&fee_rate),
        "fee rate must be 1..={BITCOIN_MAX_FEE_RATE} sat/vB"
    );
    Ok(())
}
fn fund_commit(
    funding_outpoint: OutPoint,
    funding_output: &TxOut,
    return_address: &Address,
    outputs: Vec<TxOut>,
    fee_rate: u64,
    reveal_fee_sats: u64,
) -> Result<(Transaction, u64), Error> {
    let mut commit_tx = transaction(funding_outpoint, &return_address.script_pubkey());
    commit_tx.output = outputs.clone();
    commit_tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: return_address.script_pubkey(),
    });
    commit_tx.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    let commit_fee_sats = u64::try_from(commit_tx.vsize())? * fee_rate;
    commit_tx.input[0].witness = Witness::new();
    let output_sats = outputs.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let change = funding_output
        .value
        .to_sat()
        .checked_sub(output_sats + commit_fee_sats)
        .context("funding coin does not cover outputs and fees")?;
    ensure!(
        change >= BITCOIN_RETURN_SATS,
        "funding coin must leave at least {BITCOIN_RETURN_SATS} sats change"
    );
    commit_tx
        .output
        .last_mut()
        .context("commit change missing")?
        .value = Amount::from_sat(change);
    ensure!(
        commit_fee_sats + reveal_fee_sats <= BITCOIN_MAX_FEE_SATS,
        "client fee cap exceeded"
    );
    Ok((commit_tx, commit_fee_sats))
}
