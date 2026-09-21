use crate::config;
use crate::error::{Context, Error, ensure};
use crate::storage;
use crate::transaction::decode;
use crate::{
    node::{Node, Presence},
    plan::PublicationPlan,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use urma_chain::observation::Chain;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    pub txid: String,
    pub presence: Presence,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishReport {
    pub plan_id: String,
    pub root_txid: String,
    pub complete: bool,
    pub confirmed: bool,
    pub blocked_reason: String,
    pub transactions: Vec<TransactionStatus>,
}

pub(crate) fn store(path: &Path, report: &PublishReport) -> Result<(), Error> {
    urma_io::write_replace(path, &serde_json::to_vec_pretty(report)?).map_err(Error::from)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MempoolCheck {
    Allowed,
    Rejected(String),
    Unavailable(String),
}

pub fn test_accept(node: &Node, raw: &str) -> Result<MempoolCheck, Error> {
    let transaction = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?;
    ensure!(
        transaction.weight().to_wu() <= config::STANDARD_TX_WEIGHT,
        "transaction exceeds standard weight"
    );
    let acceptance = match node.call("testmempoolaccept", &[json!([raw])]) {
        Ok(value) => value,
        Err(cause) if node.is_public() => {
            tracing::warn!(%cause, "public mempool preflight unavailable");
            return Ok(MempoolCheck::Unavailable(cause.to_string()));
        }
        Err(cause) => return Err(cause),
    };
    let rows = acceptance
        .as_array()
        .context("missing mempool acceptance")?;
    ensure!(rows.len() == 1, "incorrect mempool acceptance count");
    let result = &rows[0];
    ensure!(
        result["txid"] == json!(transaction.compute_txid()),
        "mempool preflight TXID mismatch"
    );
    match result["allowed"]
        .as_bool()
        .context("missing mempool decision")?
    {
        true => Ok(MempoolCheck::Allowed),
        false => Ok(MempoolCheck::Rejected(
            result["reject-reason"]
                .as_str()
                .context("mempool policy rejected transaction without reason")?
                .to_owned(),
        )),
    }
}

pub(crate) fn broadcast(node: &Node, raw: &str) -> Result<String, Error> {
    match test_accept(node, raw)? {
        MempoolCheck::Allowed => (),
        MempoolCheck::Rejected(reason) => return Ok(reason),
        MempoolCheck::Unavailable(reason) => {
            tracing::warn!(%reason, "broadcast has no node mempool preflight evidence");
            tracing::debug!(target: "urma_progress", "Endpoint does not provide testmempoolaccept; acceptance is unverified until submission.");
        }
    }
    let transaction = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?;
    let txid = transaction.compute_txid();
    match node.call("sendrawtransaction", &[json!(raw)]) {
        Ok(result) => ensure!(
            result == json!(txid),
            "broadcast RPC returned unexpected TXID"
        ),
        Err(error) => {
            tracing::warn!(txid = %txid, "broadcast reply unavailable; reconciling exact signed transaction");
            match node.presence(txid)? {
                Presence::Missing => {
                    if temporary_rejection(&error) {
                        return Ok("mempool full".into());
                    }
                    return Err(error);
                }
                Presence::Mempool | Presence::Confirmed { .. } => {}
            }
        }
    }
    Ok(String::new())
}

fn temporary_rejection(error: &Error) -> bool {
    match error {
        Error::Rpc(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(
            rejection,
        ))) => rejection.code == -26 && rejection.message == "mempool full",
        _ => false,
    }
}

pub fn publish(
    node: &Node,
    plan: &PublicationPlan,
    approved_id: &str,
    journal: &Path,
) -> Result<PublishReport, Error> {
    let (mut report, anchor) = start(
        node,
        plan.id()?,
        &plan.root_txid,
        plan.chain,
        approved_id,
        journal,
    )?;
    let mut raw_transactions = Vec::new();
    for pair in &plan.records {
        raw_transactions.push(&pair.commit);
        raw_transactions.push(&pair.reveal);
    }
    for raw in &raw_transactions {
        if !advance(node, raw, &mut report)? {
            store(journal, &report)?;
            return Ok(report);
        }
        let presence = &report
            .transactions
            .last()
            .context("transaction observation missing")?
            .presence;
        if matches!(presence, Presence::Missing) {
            report.blocked_reason =
                "transaction missing after submission; resume exact plan".into();
            store(journal, &report)?;
            return Ok(report);
        }
        if plan.records.len() != 1 && !matches!(presence, Presence::Confirmed { .. }) {
            report.blocked_reason =
                "awaiting one confirmation before dependent publication or recovery".into();
            store(journal, &report)?;
            return Ok(report);
        }
        store(journal, &report)?;
    }
    ensure!(
        node.block_hash(anchor.0)?.to_string() == anchor.1,
        "chain changed during publication reconciliation; resume against the new chain"
    );
    report.confirmed = report
        .transactions
        .iter()
        .all(|transaction| matches!(transaction.presence, Presence::Confirmed { .. }));
    report.complete = report.confirmed;
    if !report.confirmed {
        report.blocked_reason = "awaiting confirmations for commit and reveal".into();
    }
    store(journal, &report)?;
    Ok(report)
}

pub(crate) fn advance(node: &Node, raw: &str, report: &mut PublishReport) -> Result<bool, Error> {
    let transaction = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?;
    let txid = transaction.compute_txid();
    let mut presence = node.presence(txid)?;
    if matches!(presence, Presence::Missing) {
        let reason = broadcast(node, raw)?;
        if !reason.is_empty() {
            report.blocked_reason = reason;
            report.transactions.push(TransactionStatus {
                txid: txid.to_string(),
                presence,
            });
            return Ok(false);
        }
        presence = node.presence(txid)?;
    }
    report.transactions.push(TransactionStatus {
        txid: txid.to_string(),
        presence,
    });
    Ok(true)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn ensure_journal_distinct(plan_path: &Path, journal_path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    let plan = std::fs::canonicalize(plan_path)?;
    if journal_path.try_exists()? {
        let journal = std::fs::canonicalize(journal_path)?;
        ensure!(
            plan != journal,
            "journal must differ from immutable plan input"
        );
        let input = std::fs::metadata(&plan)?;
        let output = std::fs::metadata(&journal)?;
        ensure!(
            input.dev() != output.dev() || input.ino() != output.ino(),
            "journal must not be a hard link to immutable plan input"
        );
    } else {
        let parent = std::fs::canonicalize(urma_io::output_parent(journal_path))?;
        let name = journal_path
            .file_name()
            .context("journal filename missing")?;
        ensure!(
            plan != parent.join(name),
            "journal must differ from immutable plan input"
        );
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn ensure_journal_distinct(plan_path: &Path, journal_path: &Path) -> Result<(), Error> {
    Err(Error::Unsupported(format!(
        "native journal path validation is unavailable on WASM: {} and {}",
        plan_path.display(),
        journal_path.display()
    )))
}

pub(crate) fn start(
    node: &Node,
    id: String,
    root_txid: &str,
    chain: Chain,
    approved_id: &str,
    journal: &Path,
) -> Result<(PublishReport, (u64, String)), Error> {
    ensure!(
        approved_id == id,
        "approval does not match exact immutable signed plan"
    );
    node.verify_network()?;
    node.require_txindex()?;
    let anchor = node.tip()?;
    ensure!(
        node.chain().genesis()? == chain.genesis()?,
        "publication network mismatch"
    );
    if journal.try_exists()? {
        let old: PublishReport =
            serde_json::from_slice(&storage::read_bounded(journal, 1024 * 1024)?)?;
        ensure!(old.plan_id == id, "journal belongs to another plan");
    }
    let report = PublishReport {
        plan_id: id,
        root_txid: root_txid.to_owned(),
        complete: false,
        confirmed: false,
        blocked_reason: String::new(),
        transactions: Vec::new(),
    };
    store(journal, &report)?;
    Ok((report, anchor))
}
