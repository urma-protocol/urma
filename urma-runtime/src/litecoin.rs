use crate::commitment::PreparedReveal;
use crate::config::Limits;
use crate::config::{
    LITECOIN_MAX_FEE_LITOSHIS, LITECOIN_MAX_SCAN_BLOCKS, LITECOIN_MAX_SCAN_BYTES, LITECOIN_NETWORK,
    LITECOIN_RETURN_LITOSHIS,
};
use crate::config::{RpcScope, ScanEnd, confirmations};
use crate::error::{Context, Error, bail, ensure};
use crate::journal;
use crate::transaction::{decode as decode_transaction, transaction};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Transaction, TxOut, Witness,
    consensus::serialize,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, str::FromStr};
use urma_core::envelope;
use urma_core::format::RecordKind;
use urma_core::format::Urma;
use urma_wallet::funding::Funding;

use crate::{
    backend::{Evidence, Family, Locator, Observation, RecordSource},
    container,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quote {
    pub network: String,
    pub records: usize,
    pub fee_rate_litoshi_vb: u64,
    pub commit_fee_litoshis: u64,
    pub reveal_fee_litoshis: u64,
    pub total_fee_litoshis: u64,
    pub minimum_funding_litoshis: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub network: String,
    pub version: u8,
    pub input_bytes: usize,
    pub start_height: u64,
    pub fee_rate_litoshi_vb: u64,
    pub funding: Funding,
    pub commit: String,
    pub reveals: Vec<String>,
}

fn decode(raw: &str) -> Result<Transaction, Error> {
    ensure!(
        raw.len() <= 800_000,
        "transparent transaction exceeds limit"
    );
    decode_transaction(raw, 800_000).map_err(|cause| match cause {
        Error::Context { cause, .. } => Error::Context {
            message: "invalid transparent transaction (MWEB funding is unsupported)".into(),
            cause,
        },
        cause => cause,
    })
}

pub fn quote(input_bytes: usize, rate: u64) -> Result<Quote, Error> {
    if input_bytes > Limits::INPUT_BYTES {
        return Err(Error::Capacity("client input capacity exceeded".into()));
    }

    ensure!(
        (1..=Limits::INPUT_BYTES).contains(&input_bytes),
        "input exceeds client publication capacity"
    );
    ensure!(
        (1..=100).contains(&rate),
        "fee rate must be 1..100 litoshi/vB"
    );
    let count = input_bytes.div_ceil(Urma::CHUNK_BYTES);
    let secp = Secp256k1::new();
    let signer = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
    let mut sizing_record = vec![0; Urma::PRIVATE_RECORD_BYTES];
    sizing_record[..8].copy_from_slice(&RecordKind::Private.prefix());
    sizing_record[60..64].copy_from_slice(&1u32.to_le_bytes());
    let (script, info) = envelope::build(&sizing_record, &signer)?;
    let payout = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0; 20]));
    let mut reveal = transaction(
        OutPoint::null(),
        TxOut {
            value: Amount::from_sat(LITECOIN_RETURN_LITOSHIS),
            script_pubkey: payout.clone(),
        },
    );
    reveal.input[0].witness = envelope::witness(&[0; 64], &script, &info)?;
    let reveal_fee = u64::try_from(reveal.vsize())? * rate;
    let mut commit = transaction(
        OutPoint::null(),
        TxOut {
            value: Amount::from_sat(LITECOIN_RETURN_LITOSHIS),
            script_pubkey: payout.clone(),
        },
    );
    commit.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key())
        };
        count
    ];
    commit.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: payout,
    });
    commit.input[0].witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    let commit_fee = u64::try_from(commit.vsize())? * rate;
    let total = commit_fee + reveal_fee * u64::try_from(count)?;
    ensure!(
        total <= LITECOIN_MAX_FEE_LITOSHIS,
        "client fee cap exceeded"
    );
    Ok(Quote {
        network: LITECOIN_NETWORK.into(),
        records: count,
        fee_rate_litoshi_vb: rate,
        commit_fee_litoshis: commit_fee,
        reveal_fee_litoshis: reveal_fee * u64::try_from(count)?,
        total_fee_litoshis: total,
        minimum_funding_litoshis: total + LITECOIN_RETURN_LITOSHIS * (u64::try_from(count)? + 1),
    })
}

pub fn prepare<R: RngCore + CryptoRng>(
    records: &[Vec<u8>],
    input_bytes: usize,
    funding: Funding,
    rate: u64,
    start_height: u64,
    rng: &mut R,
) -> Result<Plan, Error> {
    let costs = quote(input_bytes, rate)?;
    ensure!(
        records.len() == costs.records,
        "record count disagrees with input length"
    );
    let first = container::inspect_header(&records[0])?;
    for (i, record) in records.iter().enumerate() {
        let h = container::inspect_header(record)?;
        ensure!(
            h.id == first.id
                && h.discovery_tag == first.discovery_tag
                && usize::try_from(h.index)? == i
                && usize::try_from(h.count)? == records.len(),
            "expected one ordered complete opaque object"
        );
    }
    let (outpoint, previous) = funding.prevout()?;
    ensure!(
        previous.value.to_sat() >= costs.minimum_funding_litoshis,
        "insufficient test funding"
    );
    let payout = &previous.script_pubkey;
    let mut pending = Vec::new();
    let mut commit = transaction(
        outpoint,
        TxOut {
            value: Amount::from_sat(LITECOIN_RETURN_LITOSHIS),
            script_pubkey: payout.clone(),
        },
    );
    commit.output.clear();
    for record in records {
        let prepared = PreparedReveal::new(record, payout, rate, LITECOIN_RETURN_LITOSHIS, rng)?;
        commit.output.push(prepared.output());
        pending.push(prepared);
    }
    commit.output.push(TxOut {
        value: Amount::from_sat(
            previous.value.to_sat()
                - costs.total_fee_litoshis
                - LITECOIN_RETURN_LITOSHIS * u64::try_from(costs.records)?,
        ),
        script_pubkey: payout.clone(),
    });
    let mut reveals = Vec::new();
    for (index, prepared) in pending.into_iter().enumerate() {
        reveals.push(hex::encode(serialize(&prepared.sign(
            &commit,
            u32::try_from(index)?,
            payout,
        )?)));
    }
    let plan = Plan {
        network: LITECOIN_NETWORK.into(),
        version: Urma::VERSION,
        input_bytes,
        start_height,
        fee_rate_litoshi_vb: rate,
        funding,
        commit: hex::encode(serialize(&commit)),
        reveals,
    };
    inspect(&plan, false)?;
    Ok(plan)
}

pub fn inspect(plan: &Plan, signed: bool) -> Result<Value, Error> {
    ensure!(
        plan.network == LITECOIN_NETWORK,
        "only Litecoin testnet plans are accepted"
    );
    let costs = quote(plan.input_bytes, plan.fee_rate_litoshi_vb)?;
    ensure!(plan.reveals.len() == costs.records, "invalid reveal count");
    let (_, previous) = plan.funding.prevout()?;
    let reveal = decode(&plan.reveals[0])?;
    let witness = &reveal
        .input
        .first()
        .context("missing reveal input")?
        .witness;
    let record = envelope::extract(witness)?.record;
    let header = container::inspect_header(&record)?;
    let common = journal::Plan {
        version: plan.version,
        network: LITECOIN_NETWORK.into(),
        object_id: hex::encode(header.id),
        start_height: plan.start_height,
        input_bytes: plan.input_bytes,
        fee_sats: costs.total_fee_litoshis,
        commit_fee_sats: costs.commit_fee_litoshis,
        reveal_fee_sats: costs.reveal_fee_litoshis,
        fee_rate_sat_vb: plan.fee_rate_litoshi_vb,
        funding: plan.funding.clone(),
        commit: plan.commit.clone(),
        reveals: plan.reveals.clone(),
        mining_address: String::new(),
    };
    let checked = journal::validate_transparent_plan(&common, &previous.script_pubkey, signed)?;
    Ok(
        json!({"network":LITECOIN_NETWORK, "status":if signed {"signed"} else {"draft"},
        "broadcast":false, "object_id":checked["object_id"], "start_height":plan.start_height,
        "commit_txid":checked["commit_txid"], "reveal_txids":checked["reveal_txids"],
        "commit_vsize":checked["commit_vsize"], "reveal_vsizes":checked["reveal_vsizes"],
        "quote":costs, "funding_litoshis":previous.value.to_sat(),
        "content_authenticated":false, "chain_status_checked":false}),
    )
}

pub fn is_signed(plan: &Plan) -> Result<bool, Error> {
    Ok(!decode(&plan.commit)?
        .input
        .first()
        .context("missing commit input")?
        .witness
        .is_empty())
}

pub trait Rpc {
    fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error>;
}

pub struct Core {
    client: Client,
}

impl Core {
    pub fn connect(endpoint: &str, cookie: &Path, wallet: RpcScope<'_>) -> Result<Self, Error> {
        let mut url = url::Url::parse(endpoint).context("invalid local RPC URL")?;
        match (url.password(), url.query(), url.fragment()) {
            (None, None, None) => {}
            components => {
                bail!("URL credentials, query and fragment are forbidden: {components:?}")
            }
        }
        ensure!(
            url.scheme() == "http" && url.username().is_empty() && url.path() == "/",
            "RPC requires a plain local HTTP origin and cookie authentication"
        );
        let host = url.host_str().context("missing RPC host")?;
        let host = host.trim_matches(['[', ']']);
        ensure!(
            host.parse::<std::net::IpAddr>()?.is_loopback(),
            "RPC must use a loopback IP"
        );
        if let RpcScope::Wallet(wallet) = wallet {
            ensure!(!wallet.is_empty(), "wallet name is empty");
            url.path_segments_mut()
                .map_err(|unit| Error::Invalid(format!("invalid wallet URL: {unit:?}")))?
                .push("wallet")
                .push(wallet);
        }
        let client = Client::new(url.as_str(), Auth::CookieFile(cookie.to_owned()))
            .context("cannot configure local cookie-authenticated RPC")?;
        let core = Self { client };
        check_node(&core, false)?;
        Ok(core)
    }
}

impl Rpc for Core {
    fn call(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        ensure!(
            [
                "getblockchaininfo",
                "getblockhash",
                "getblock",
                "getrawtransaction",
                "gettxout",
                "getaddressinfo",
                "getnewaddress",
                "signrawtransactionwithwallet",
                "testmempoolaccept",
                "sendrawtransaction"
            ]
            .contains(&method),
            "unsupported Litecoin RPC method"
        );
        match self.client.call::<Value>(method, args) {
            Ok(v) => Ok(v),
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(e)))
                if method == "getrawtransaction" && e.code == -5 =>
            {
                tracing::warn!(code = e.code, "transaction absent from node");
                Ok(Value::Null)
            }
            Err(error) => Err(error.into()),
        }
    }
}

pub fn check_node(rpc: &dyn Rpc, require_ready: bool) -> Result<Value, Error> {
    let info = rpc.call("getblockchaininfo", &[])?;
    ensure!(info["chain"] == "test", "RPC must be Litecoin testnet");
    ensure!(
        rpc.call("getblockhash", &[json!(0)])?
            == urma_chain::observation::Chain::LitecoinTestnet
                .genesis()?
                .0
                .to_string(),
        "Litecoin testnet genesis mismatch"
    );
    if require_ready {
        ensure!(
            info["initialblockdownload"] == false
                && info["blocks"].as_u64().context("missing block height")? > 0,
            "node is not synchronized"
        );
        ensure!(
            info["softforks"]["segwit"]["active"] == true
                && info["softforks"]["taproot"]["active"] == true,
            "SegWit and Taproot must be active"
        );
    }
    Ok(info)
}

pub fn receiving_address(rpc: &dyn Rpc) -> Result<String, Error> {
    check_node(rpc, false)?;
    let value = rpc.call(
        "getnewaddress",
        &[json!("urma-litecoin-testnet"), json!("bech32")],
    )?;
    let address = value.as_str().context("missing testnet address")?;
    ensure!(
        address.starts_with("tltc1q"),
        "wallet returned a non-testnet/non-P2WPKH address"
    );
    let info = rpc.call("getaddressinfo", &[json!(address)])?;
    let script = ScriptBuf::from_bytes(hex::decode(
        info["scriptPubKey"]
            .as_str()
            .context("missing address script")?,
    )?);
    ensure!(
        info["ismine"] == true && script.is_p2wpkh(),
        "address must belong to a transparent test wallet"
    );
    Ok(address.to_owned())
}

pub fn sign(rpc: &dyn Rpc, draft: &Plan) -> Result<Plan, Error> {
    inspect(draft, false)?;
    check_node(rpc, false)?;
    let (outpoint, previous) = draft.funding.prevout()?;
    let result = rpc.call("signrawtransactionwithwallet", &[json!(draft.commit), json!([{
        "txid":outpoint.txid, "vout":outpoint.vout, "scriptPubKey":hex::encode(previous.script_pubkey.as_bytes()),
        "amount":coin_value(previous.value.to_sat())?
    }]), json!("ALL")])?;
    ensure!(
        result["complete"] == true,
        "wallet did not fully sign commit"
    );
    let mut signed = draft.clone();
    signed.commit = result["hex"]
        .as_str()
        .context("missing signed commit")?
        .to_owned();
    ensure!(
        decode(&signed.commit)?.compute_txid() == decode(&draft.commit)?.compute_txid(),
        "signer changed commit body"
    );
    inspect(&signed, true)?;
    Ok(signed)
}

fn coin_value(litoshis: u64) -> Result<Value, Error> {
    serde_json::from_str(&format!(
        "{}.{:08}",
        litoshis / 100_000_000,
        litoshis % 100_000_000
    ))
    .map_err(Into::into)
}

fn litoshis(value: &Value) -> Result<u64, Error> {
    let text = value.to_string();
    Amount::from_str_in(&text, bitcoin::Denomination::Bitcoin)
        .map(|amount| amount.to_sat())
        .context("invalid whole-litoshi RPC amount")
}

pub struct LitecoinRecords<'a> {
    pub rpc: &'a dyn Rpc,
    pub start_height: u64,
}

impl RecordSource for LitecoinRecords<'_> {
    fn read_records(
        &self,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        self.read_range(
            ScanEnd::Tip,
            &mut |height| {
                tracing::trace!(height, "scan progress");
                Ok(())
            },
            emit,
        )
    }
}

impl LitecoinRecords<'_> {
    pub fn read_range(
        &self,
        end: ScanEnd,
        progress: &mut dyn FnMut(u64) -> Result<(), Error>,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Observation, Error> {
        let info = check_node(self.rpc, true)?;
        let current_tip = info["blocks"].as_u64().context("missing tip height")?;
        let tip = match end {
            ScanEnd::Tip => current_tip,
            ScanEnd::Height(height) => height,
        };
        ensure!(tip <= current_tip, "end height beyond tip");
        ensure!(
            self.start_height <= tip && tip - self.start_height < LITECOIN_MAX_SCAN_BLOCKS,
            "scan interval exceeds limits"
        );
        let tip_hash = self.rpc.call("getblockhash", &[json!(tip)])?;
        let tip_hash = parse_hash(&tip_hash)?;
        let mut previous = if self.start_height == 0 {
            bitcoin::BlockHash::all_zeros()
        } else {
            parse_hash(
                &self
                    .rpc
                    .call("getblockhash", &[json!(self.start_height - 1)])?,
            )?
        };
        let mut scanned_bytes = 0usize;
        for height in self.start_height..=tip {
            progress(height)?;
            let hash = parse_hash(&self.rpc.call("getblockhash", &[json!(height)])?)?;
            let block = self
                .rpc
                .call("getblock", &[json!(hash.to_string()), json!(2)])?;
            let bytes = serde_json::to_vec(&block)?.len();
            ensure!(bytes <= 32 * 1024 * 1024, "block JSON exceeds limit");
            scanned_bytes = scanned_bytes
                .checked_add(bytes)
                .context("scan byte overflow")?;
            ensure!(
                scanned_bytes <= LITECOIN_MAX_SCAN_BYTES,
                "scan byte limit exceeded"
            );
            ensure!(
                parse_hash(&block["hash"])? == hash
                    && block["height"] == height
                    && block["confirmations"]
                        .as_i64()
                        .context("missing block confirmations")?
                        > 0,
                "invalid selected block response"
            );
            if height > 0 {
                ensure!(
                    parse_hash(&block["previousblockhash"])? == previous,
                    "chain changed during scan"
                );
            }
            emit_block_records(&block, emit)?;
            previous = hash;
        }
        ensure!(
            previous == tip_hash
                && parse_hash(&self.rpc.call("getblockhash", &[json!(tip)])?)? == tip_hash,
            "chain changed during scan"
        );
        Ok(Observation {
            backend: Family::Litecoin,
            locator: Locator::BlockRange {
                network: LITECOIN_NETWORK.into(),
                start_height: self.start_height,
                tip_height: tip,
                tip_hash: tip_hash.to_string(),
            },
            evidence: Evidence::LitecoinCoreTrusted,
            scanned_bytes,
        })
    }
}

fn parse_hash(value: &Value) -> Result<bitcoin::BlockHash, Error> {
    bitcoin::BlockHash::from_str(value.as_str().context("missing block hash")?)
        .context("invalid block hash")
}

fn transaction_status(rpc: &dyn Rpc, raw: &str) -> Result<Value, Error> {
    let expected = decode(raw)?;
    let txid = expected.compute_txid();
    let value = rpc.call("getrawtransaction", &[json!(txid.to_string()), json!(true)])?;
    if value.is_null() {
        return Ok(json!({"txid":txid, "state":"unknown", "confirmations":0}));
    }
    let observed = decode(
        value["hex"]
            .as_str()
            .context("missing observed transaction")?,
    )?;
    ensure!(
        observed == expected,
        "node returned different transaction/witness bytes"
    );
    let confirmations = confirmations(&value)?;
    ensure!(confirmations >= 0, "transaction conflicted or reorganized");
    if confirmations > 0 {
        let hash = parse_hash(&value["blockhash"])?;
        let block = rpc.call("getblock", &[json!(hash.to_string()), json!(1)])?;
        let height = block["height"]
            .as_u64()
            .context("missing confirmation height")?;
        ensure!(
            parse_hash(&rpc.call("getblockhash", &[json!(height)])?)? == hash
                && block["tx"]
                    .as_array()
                    .context("missing txids")?
                    .contains(&json!(txid.to_string())),
            "confirmation not in selected chain"
        );
    }
    Ok(
        json!({"txid":txid, "state":if confirmations > 0 {"confirmed"} else {"pending"}, "confirmations":confirmations}),
    )
}

pub fn status(rpc: &dyn Rpc, plan: &Plan) -> Result<Value, Error> {
    inspect(plan, true)?;
    check_node(rpc, true)?;
    let commit = transaction_status(rpc, &plan.commit)?;
    let reveals = plan
        .reveals
        .iter()
        .map(|raw| transaction_status(rpc, raw))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(
        json!({"network":LITECOIN_NETWORK, "commit":commit, "reveals":reveals,
        "evidence":"litecoin_core_trusted", "quote":quote(plan.input_bytes,plan.fee_rate_litoshi_vb)?}),
    )
}

pub fn broadcast(rpc: &dyn Rpc, plan: &Plan, budget: u64) -> Result<Value, Error> {
    inspect(plan, true)?;
    ensure!(
        quote(plan.input_bytes, plan.fee_rate_litoshi_vb)?.total_fee_litoshis <= budget
            && budget <= LITECOIN_MAX_FEE_LITOSHIS,
        "explicit fee budget missing or exceeded"
    );
    check_node(rpc, true)?;
    let state = transaction_status(rpc, &plan.commit)?;
    if state["state"] == "unknown" {
        let (outpoint, previous) = plan.funding.prevout()?;
        let coin = rpc.call(
            "gettxout",
            &[json!(outpoint.txid), json!(outpoint.vout), json!(true)],
        )?;
        ensure!(
            coin["confirmations"]
                .as_u64()
                .context("missing funding confirmations")?
                > 0
                && (coin["coinbase"] == false
                    || (coin["coinbase"] == true
                        && coin["confirmations"]
                            .as_u64()
                            .context("missing coinbase confirmations")?
                            >= 100))
                && coin["scriptPubKey"]["hex"] == hex::encode(previous.script_pubkey.as_bytes())
                && litoshis(&coin["value"])? == previous.value.to_sat(),
            "funding must be confirmed, unspent and match the plan"
        );
        submit(rpc, &plan.commit)?;
        return Ok(
            json!({"network":LITECOIN_NETWORK, "status":"commit_submitted", "commit_txid":state["txid"], "broadcast":true}),
        );
    }
    if state["state"] == "pending" {
        return Ok(
            json!({"network":LITECOIN_NETWORK,"status":"awaiting_commit_confirmation","broadcast":false}),
        );
    }
    let mut submitted = Vec::new();
    for raw in &plan.reveals {
        let observed = transaction_status(rpc, raw)?;
        if observed["state"] == "unknown" {
            submitted.push(submit(rpc, raw)?);
        }
    }
    Ok(
        json!({"network":LITECOIN_NETWORK,"status":"reveals_checked","submitted_txids":submitted,
        "note":"Submission is not confirmation or successful recovery; check status and recover independently."}),
    )
}

fn submit(rpc: &dyn Rpc, raw: &str) -> Result<String, Error> {
    let expected = decode(raw)?.compute_txid().to_string();
    let acceptance = rpc.call("testmempoolaccept", &[json!([raw])])?;
    ensure!(
        acceptance[0]["allowed"] == true && acceptance[0]["txid"] == expected,
        "node policy rejected transaction; nothing submitted"
    );
    let returned = rpc.call("sendrawtransaction", &[json!(raw)])?;
    ensure!(
        returned == expected,
        "ambiguous submission result; inspect status before retrying"
    );
    Ok(expected)
}
fn emit_block_records(
    block: &Value,
    emit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let transactions = block["tx"]
        .as_array()
        .context("missing block transactions")?;
    for tx in transactions {
        for input in tx["vin"].as_array().context("missing transparent inputs")? {
            let Some(stack) = input.get("txinwitness") else {
                continue;
            };
            let stack = stack.as_array().context("invalid witness array")?;
            if stack.len() != 3 {
                continue;
            }
            let mut parts = Vec::with_capacity(3);
            for (i, part) in stack.iter().enumerate() {
                let encoded = part.as_str().context("invalid witness hex")?;
                let limit = [128, (Urma::PRIVATE_RECORD_BYTES + 1024) * 2, 66][i];
                if encoded.len() > limit {
                    break;
                }
                parts.push(hex::decode(encoded)?);
            }
            if parts.len() == 3 {
                let witness = Witness::from_slice(&parts);
                if envelope::is_candidate(&witness) {
                    match extract_core_envelope(tx, &witness) {
                        Ok(parsed) => emit(&parsed.record)?,
                        Err(error) => {
                            tracing::warn!(%error, "invalid URMA envelope rejected")
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn extract_core_envelope(tx: &Value, witness: &Witness) -> Result<envelope::ParsedEnvelope, Error> {
    let inputs = tx["vin"].as_array().context("missing transparent inputs")?;
    let outputs = tx["vout"]
        .as_array()
        .context("missing transparent outputs")?;
    let version = i32::try_from(
        tx["version"]
            .as_i64()
            .context("invalid reveal transaction shape")?,
    )?;
    envelope::validate_reveal_shape(version, inputs.len(), outputs.len())?;
    let script_sig = ScriptBuf::from_bytes(hex::decode(
        inputs[0]["scriptSig"]["hex"]
            .as_str()
            .context("missing scriptSig")?,
    )?);
    let script = ScriptBuf::from_bytes(hex::decode(
        outputs[0]["scriptPubKey"]["hex"]
            .as_str()
            .context("missing return script")?,
    )?);
    envelope::validate_reveal_scripts(&script_sig, &script)?;
    Ok(envelope::extract(witness)?)
}
