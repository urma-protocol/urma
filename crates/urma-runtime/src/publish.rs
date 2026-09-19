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
    node.call("sendrawtransaction", &[json!(raw)])?;
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
        complete: true,
        confirmed: true,
        blocked_reason: String::new(),
        transactions: Vec::new(),
    };
    store(journal, &report)?;
    for pair in &plan.records {
        for raw in [&pair.commit, &pair.reveal] {
            let transaction: Transaction = deserialize(&hex::decode(raw)?)?;
            let txid = transaction.compute_txid();
            let mut presence = node.presence(txid)?;
            if matches!(presence, Presence::Missing) {
                let reason = broadcast(node, raw)?;
                if !reason.is_empty() {
                    report.complete = false;
                    report.confirmed = false;
                    report.blocked_reason = reason;
                    report.transactions.push(TransactionStatus {
                        txid: txid.to_string(),
                        presence,
                    });
                    store(journal, &report)?;
                    return Ok(report);
                }
                presence = node.presence(txid)?;
            }
            report.confirmed &= matches!(presence, Presence::Confirmed { .. });
            report.complete &= !matches!(presence, Presence::Missing);
            report.transactions.push(TransactionStatus {
                txid: txid.to_string(),
                presence,
            });
            store(journal, &report)?;
        }
    }
    Ok(report)
}
