use crate::error::{Error, ensure};
use crate::publication::PublicPlan;
use crate::transaction::decode;
use crate::{config, disk_journal, publication_progress};
use crate::{
    disk_plan::DiskPlan,
    node::{Node, Presence},
    publication_progress::{Observation, Progress, State, Target},
    publish::{PublishReport, TransactionStatus, broadcast, store},
};
use std::{collections::HashMap, path::Path};
use urma_core::multipart::{MultipartRecord, VerifiedRecord};

pub fn publish(
    node: &Node,
    plan: &DiskPlan,
    approved_id: &str,
    journal: &Path,
) -> Result<PublishReport, Error> {
    Ok(
        publish_progress(node, plan, approved_id, journal, &mut |progress| {
            tracing::debug!(target: "urma_progress", "{}", progress.summary());
            Ok(())
        })?
        .report,
    )
}

pub fn publish_progress(
    node: &Node,
    plan: &DiskPlan,
    approved_id: &str,
    journal: &Path,
    progress: &mut impl FnMut(&Progress) -> Result<(), Error>,
) -> Result<Progress, Error> {
    ensure!(
        approved_id == plan.id()?,
        "approval does not match exact immutable signed plan"
    );
    disk_journal::guard(plan, journal)?;
    reconcile(node, plan, journal, true, progress)
}

pub fn watch(
    node: &Node,
    plan: &DiskPlan,
    journal: &Path,
    progress: &mut impl FnMut(&Progress) -> Result<(), Error>,
) -> Result<Progress, Error> {
    reconcile(node, plan, journal, false, progress)
}

struct Session<'a> {
    node: &'a Node,
    journal: &'a Path,
    submit: bool,
    history: HashMap<String, Presence>,
    progress: Progress,
}

fn reconcile(
    node: &Node,
    plan: &DiskPlan,
    journal: &Path,
    submit: bool,
    notify: &mut impl FnMut(&Progress) -> Result<(), Error>,
) -> Result<Progress, Error> {
    plan.validate()?;
    node.verify_network()?;
    node.require_txindex()?;
    ensure!(
        node.chain().genesis()? == plan.chain.genesis()?,
        "publication network mismatch"
    );
    let anchor = node.tip()?;
    let id = plan.id()?;
    let mut session = Session {
        node,
        journal,
        submit,
        history: disk_journal::history(journal, &id)?,
        progress: Progress {
            report: PublishReport {
                plan_id: id,
                root_txid: plan.root_txid.clone(),
                complete: false,
                confirmed: false,
                blocked_reason: String::new(),
                transactions: Vec::new(),
            },
            total: usize::try_from(plan.record_count)? * 2,
            observations: Vec::new(),
            retryable: true,
        },
    };
    session.walk(plan, notify)?;
    if node.block_hash(anchor.0)?.to_string() != anchor.1 {
        session.progress.observations.clear();
        session.progress.report.transactions.clear();
        session.progress.report.blocked_reason =
            "chain changed during reconciliation; waiting for fresh observations".into();
    }
    session.progress.report.complete = session.progress.reached(Target::Confirmed);
    session.progress.report.confirmed = session.progress.report.complete;
    if !session.progress.report.complete && session.progress.report.blocked_reason.is_empty() {
        session.progress.report.blocked_reason = if submit {
            "awaiting confirmations; eligible transactions will be reconciled on the next pass"
        } else {
            "read-only watch; prepared or missing transactions require publish/resume in another process"
        }.into();
    }
    if submit {
        store(journal, &session.progress.report)?;
    }
    notify(&session.progress)?;
    Ok(session.progress)
}

impl Session<'_> {
    fn walk(
        &mut self,
        plan: &DiskPlan,
        notify: &mut impl FnMut(&Progress) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut data_confirmed = true;
        let mut leaves_confirmed = true;
        let mut pending_commits = 0u32;
        let mut can_submit = self.submit;
        for index in 0..plan.record_count {
            notify(&self.progress)?;
            let pair = plan.record(index)?;
            let kind = record(&pair)?;
            self.progress.report.transactions.clear();
            let commit = self.transaction(&pair.commit, "commit", can_submit)?;
            if !self.progress.retryable {
                break;
            }
            can_submit &= self.progress.retryable && self.progress.report.blocked_reason.is_empty();
            if commit == State::Mempool {
                pending_commits += 1;
            }
            if !matches!(commit, State::Confirmed | State::Mempool) {
                can_submit = false;
            }
            let (role, dependencies) = match kind {
                MultipartRecord::Data(_) => ("data", true),
                MultipartRecord::Leaf(_) => ("leaf", data_confirmed),
                MultipartRecord::Root(_) => ("root", data_confirmed && leaves_confirmed),
            };
            notify(&self.progress)?;
            let reveal = self.transaction(
                &pair.reveal,
                role,
                can_submit && commit == State::Confirmed && dependencies,
            )?;
            if !self.progress.retryable {
                break;
            }
            match kind {
                MultipartRecord::Data(_) => data_confirmed &= reveal == State::Confirmed,
                MultipartRecord::Leaf(_) => leaves_confirmed &= reveal == State::Confirmed,
                MultipartRecord::Root(_) => (),
            }
            if !self.progress.report.blocked_reason.is_empty() {
                can_submit = false;
            }
            if pending_commits >= 8 {
                can_submit = false;
                if self.progress.report.blocked_reason.is_empty() {
                    self.progress.report.blocked_reason =
                        "eight funding commits pending; waiting for confirmation".into();
                }
            }
            notify(&self.progress)?;
        }
        Ok(())
    }

    fn transaction(&mut self, raw: &str, role: &str, eligible: bool) -> Result<State, Error> {
        let txid = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?.compute_txid();
        let mut presence = match self.node.presence(txid) {
            Ok(presence) => presence,
            Err(error) => {
                self.progress.observations.push(Observation {
                    txid: txid.to_string(),
                    role: role.into(),
                    state: State::SourceUnavailable {
                        reason: error.to_string(),
                    },
                });
                self.progress.report.blocked_reason = format!("source unavailable: {error}");
                self.progress.retryable = false;
                tracing::warn!(%error, "publication source unavailable; not treating as missing");
                return Ok(State::SourceUnavailable {
                    reason: error.to_string(),
                });
            }
        };
        if eligible && matches!(presence, Presence::Missing) {
            self.remember(txid.to_string(), presence.clone())?;
            let reason = broadcast(self.node, raw)?;
            if reason.is_empty() {
                presence = self.node.presence(txid)?;
                if matches!(presence, Presence::Missing) {
                    self.progress.report.blocked_reason =
                        "submission not yet observable; waiting before spending its change".into();
                }
            } else {
                self.progress.retryable = reason == "mempool full";
                self.progress.report.blocked_reason = format!("{reason}; approved fees unchanged");
            }
        }
        let attempted = self.history.contains_key(&txid.to_string());
        let state = publication_progress::state(&presence, attempted);
        if self.submit && (attempted || !matches!(presence, Presence::Missing)) {
            self.remember(txid.to_string(), presence.clone())?;
        }
        self.progress.report.transactions.push(TransactionStatus {
            txid: txid.to_string(),
            presence,
        });
        self.progress.observations.push(Observation {
            txid: txid.to_string(),
            role: role.into(),
            state: state.clone(),
        });
        Ok(state)
    }

    fn remember(&mut self, txid: String, presence: Presence) -> Result<(), Error> {
        let previous = self.history.get(&txid);
        let unchanged = previous.iter().any(|previous| **previous == presence);
        if unchanged {
            return Ok(());
        }
        let mut event = self.progress.report.clone();
        event.transactions = vec![TransactionStatus {
            txid: txid.clone(),
            presence: presence.clone(),
        }];
        disk_journal::observe(self.node, self.journal, &event)?;
        store(self.journal, &event)?;
        self.history.insert(txid, presence);
        Ok(())
    }
}

fn record(pair: &PublicPlan) -> Result<MultipartRecord, Error> {
    let limit = usize::try_from(config::STANDARD_TX_WEIGHT)? * 2;
    let commit = decode(&pair.commit, limit)?;
    let reveal = decode(&pair.reveal, limit)?;
    Ok(VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?.decode()?)
}

pub fn may_resume_automatically(report: &PublishReport) -> bool {
    !report.complete
        && (report.blocked_reason.starts_with("awaiting confirmations;")
            || report.blocked_reason == "eight funding commits pending; waiting for confirmation"
            || report.blocked_reason
                == "submission not yet observable; waiting before spending its change"
            || report.blocked_reason == "mempool full; approved fees unchanged")
        || (!report.complete
            && report.blocked_reason
                == "chain changed during reconciliation; waiting for fresh observations")
}
