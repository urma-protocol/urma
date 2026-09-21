use crate::config;
use crate::disk_journal;
use crate::error::{Context, Error, ensure};
use crate::publication::PublicPlan;
use crate::transaction::decode;
use crate::{
    disk_plan::DiskPlan,
    node::{Node, Presence},
    publish::{PublishReport, advance, start, store},
};
use std::path::Path;
use urma_core::multipart::{MultipartRecord, VerifiedRecord};

pub fn publish(
    node: &Node,
    plan: &DiskPlan,
    approved_id: &str,
    journal: &Path,
) -> Result<PublishReport, Error> {
    plan.validate()?;
    disk_journal::guard(plan, journal)?;
    let (mut report, anchor) = start(
        node,
        plan.id()?,
        &plan.root_txid,
        plan.chain,
        approved_id,
        journal,
    )?;
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
            report.blocked_reason = ConfirmationWait::Visibility.reason().into();
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
            report.blocked_reason = ConfirmationWait::Commits.reason().into();
            return Ok(());
        }
    }
    report.complete = data_confirmed && leaves_confirmed && root_confirmed;
    report.confirmed = report.complete;
    if !report.complete {
        report.blocked_reason = ConfirmationWait::Reveals.reason().into();
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
    let commit = decode(
        &pair.commit,
        usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
    )?;
    let reveal = decode(
        &pair.reveal,
        usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
    )?;
    let record = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
    Ok(record.decode()?)
}

enum ConfirmationWait {
    Visibility,
    Commits,
    Reveals,
}

impl ConfirmationWait {
    fn reason(&self) -> &'static str {
        match self {
            Self::Visibility => {
                "commit submission is not yet observable; resume before spending its change"
            }
            Self::Commits => {
                "eight funding commits are pending; resume after confirmation to advance the bounded pipeline"
            }
            Self::Reveals => {
                "awaiting confirmations; resume to publish eligible reveals and dependent manifests"
            }
        }
    }
}

pub fn may_resume_automatically(report: &PublishReport) -> bool {
    !report.complete
        && [
            ConfirmationWait::Visibility,
            ConfirmationWait::Commits,
            ConfirmationWait::Reveals,
        ]
        .iter()
        .any(|state| state.reason() == report.blocked_reason)
}
