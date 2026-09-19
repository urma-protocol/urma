use crate::{
    node::{Node, Presence},
    plan::PublicationPlan,
};
use bitcoin::{Transaction, consensus::deserialize};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs::File, io::Write, path::Path};
use urma::error::{Context, Error, ensure};

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

fn store(path: &Path, report: &PublishReport) -> Result<(), Error> {
    let parent = urma::config::output_parent(path);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&serde_json::to_vec_pretty(report)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn broadcast(node: &Node, raw: &str) -> Result<String, Error> {
    let acceptance = node.call("testmempoolaccept", &[json!([raw])])?;
    let result = acceptance
        .as_array()
        .and_then(|entries| entries.first())
        .context("missing mempool acceptance")?;
    if result["allowed"] != true {
        return Ok(result["reject-reason"]
            .as_str()
            .context("mempool policy rejected transaction without reason")?
            .to_owned());
    }
    let result = node.call("sendrawtransaction", &[json!(raw)])?;
    let transaction: Transaction = deserialize(&hex::decode(raw)?)?;
    ensure!(
        result == json!(transaction.compute_txid()),
        "broadcast RPC returned unexpected TXID"
    );
    Ok(String::new())
}

pub fn publish(
    node: &Node,
    plan: &PublicationPlan,
    approved_id: &str,
    journal: &Path,
) -> Result<PublishReport, Error> {
    let id = plan.id()?;
    ensure!(
        approved_id == id,
        "approval does not match exact immutable signed plan"
    );
    node.verify_network()?;
    node.require_txindex()?;
    ensure!(
        node.chain().genesis()? == plan.chain.genesis()?,
        "publication network mismatch"
    );
    if journal.try_exists()? {
        let old: PublishReport =
            serde_json::from_slice(&urma::storage::read_bounded(journal, 1024 * 1024)?)?;
        ensure!(old.plan_id == id, "journal belongs to another plan");
    }
    let mut report = PublishReport {
        plan_id: id,
        root_txid: plan.root_txid.clone(),
        complete: false,
        confirmed: false,
        blocked_reason: String::new(),
        transactions: Vec::new(),
    };
    store(journal, &report)?;
    let mut raw_transactions = Vec::new();
    for pair in &plan.records {
        raw_transactions.push(&pair.commit);
        raw_transactions.push(&pair.reveal);
    }
    for (index, raw) in raw_transactions.iter().enumerate() {
        if !advance(node, raw, &mut report)? {
            store(journal, &report)?;
            return Ok(report);
        }
        let last = index + 1 == raw_transactions.len();
        let presence = &report
            .transactions
            .last()
            .context("transaction observation missing")?
            .presence;
        if !matches!(presence, Presence::Confirmed { .. }) {
            report.complete = last && !matches!(presence, Presence::Missing);
            report.blocked_reason =
                "awaiting one confirmation before dependent publication or recovery".into();
            store(journal, &report)?;
            return Ok(report);
        }
        store(journal, &report)?;
    }
    report.complete = true;
    report.confirmed = true;
    store(journal, &report)?;
    Ok(report)
}

fn advance(node: &Node, raw: &str, report: &mut PublishReport) -> Result<bool, Error> {
    let transaction: Transaction = deserialize(&hex::decode(raw)?)?;
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
        let parent = std::fs::canonicalize(urma::config::output_parent(journal_path))?;
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
