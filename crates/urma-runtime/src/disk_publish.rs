use crate::disk_journal;
use crate::{
    disk_plan::DiskPlan,
    node::{Node, Presence},
    publish::{PublishReport, advance, store},
};
use bitcoin::{Transaction, consensus::deserialize};
use std::path::Path;
use urma::{
    error::{Context, Error, ensure},
    publication::PublicPlan,
};
use urma_core::multipart::{MultipartRecord, VerifiedRecord};

pub fn publish(
    node: &Node,
    plan: &DiskPlan,
    approved_id: &str,
    journal: &Path,
) -> Result<PublishReport, Error> {
    plan.validate()?;
    disk_journal::guard(plan, journal)?;
    let id = plan.id()?;
    ensure!(
        approved_id == id,
        "approval does not match exact immutable signed plan"
    );
    node.verify_network()?;
    node.require_txindex()?;
    let anchor = node.tip()?;
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
    reconcile(node, plan, journal, &mut report)?;
    ensure!(
        node.block_hash(anchor.0)?.to_string() == anchor.1,
        "chain changed during publication reconciliation; resume against the new chain"
    );
    disk_journal::observe(node, journal, &report)?;
    store(journal, &report)?;
    Ok(report)
}

fn reconcile(
    node: &Node,
    plan: &DiskPlan,
    journal: &Path,
    report: &mut PublishReport,
) -> Result<(), Error> {
    let mut data_confirmed = true;
    let mut leaves_confirmed = true;
    let mut root_confirmed = false;
    let mut pending_commits = 0u32;
    for index in 0..plan.record_count {
        let pair = plan.record(index)?;
        report.transactions.clear();
        if !advance(node, &pair.commit, report)? {
            return Ok(());
        }
        let commit_confirmed = confirmed(report)?;
        if !known(report)? {
            report.blocked_reason =
                "commit submission is not yet observable; resume before spending its change".into();
            return Ok(());
        }
        if !commit_confirmed {
            pending_commits += 1;
        }
        let kind = record(&pair)?;
        let dependencies = match &kind {
            MultipartRecord::Data(_) => true,
            MultipartRecord::Leaf(_) => data_confirmed,
            MultipartRecord::Root(_) => data_confirmed && leaves_confirmed,
        };
        let eligible = commit_confirmed && dependencies;
        let mut reveal_confirmed = false;
        if eligible {
            if !advance(node, &pair.reveal, report)? {
                return Ok(());
            }
            reveal_confirmed = confirmed(report)?;
        }
        match kind {
            MultipartRecord::Data(_) => data_confirmed &= reveal_confirmed,
            MultipartRecord::Leaf(_) => leaves_confirmed &= reveal_confirmed,
            MultipartRecord::Root(_) => root_confirmed = reveal_confirmed,
        }
        disk_journal::observe(node, journal, report)?;
        store(journal, report)?;
        if pending_commits >= 8 {
            report.blocked_reason = "eight funding commits are pending; resume after confirmation to advance the bounded pipeline".into();
            return Ok(());
        }
    }
    report.complete = data_confirmed && leaves_confirmed && root_confirmed;
    report.confirmed = report.complete;
    if !report.complete {
        report.blocked_reason =
            "awaiting confirmations; resume to publish eligible reveals and dependent manifests"
                .into();
    }
    Ok(())
}

fn confirmed(report: &PublishReport) -> Result<bool, Error> {
    Ok(matches!(
        &report
            .transactions
            .last()
            .context("transaction observation missing")?
            .presence,
        Presence::Confirmed { .. }
    ))
}

fn known(report: &PublishReport) -> Result<bool, Error> {
    Ok(!matches!(
        &report
            .transactions
            .last()
            .context("transaction observation missing")?
            .presence,
        Presence::Missing
    ))
}

fn record(pair: &PublicPlan) -> Result<MultipartRecord, Error> {
    let commit: Transaction = deserialize(&hex::decode(&pair.commit)?)?;
    let reveal: Transaction = deserialize(&hex::decode(&pair.reveal)?)?;
    let record = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
    Ok(record.decode()?)
}
