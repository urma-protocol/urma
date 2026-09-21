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
    blocks: HashMap<String, Presence>,
    progress: Progress,
}

struct BufferedPair {
    role: &'static str,
    commit_weight: u64,
    reveal_weight: u64,
}

struct Buffer {
    weight: u64,
    broadcast_weight: u64,
    commits: usize,
    commit_vbytes: u64,
}

impl Buffer {
    fn new(pairs: &[BufferedPair], observations: &[Observation]) -> Self {
        let mut buffer = Self {
            weight: 0,
            broadcast_weight: 0,
            commits: 0,
            commit_vbytes: 0,
        };
        for (pair, rows) in pairs.iter().zip(observations.chunks_exact(2)) {
            if rows[0].state == State::Mempool {
                buffer.weight += pair.commit_weight;
                buffer.broadcast_weight += pair.commit_weight;
                buffer.commits += 1;
                buffer.commit_vbytes += pair.commit_weight.div_ceil(4);
            }
            if rows[1].state == State::Mempool {
                buffer.broadcast_weight += pair.reveal_weight;
            }
            if rows[1].state != State::Confirmed
                && (matches!(rows[0].state, State::Confirmed | State::Mempool)
                    || rows[1].state == State::Mempool)
            {
                buffer.weight += pair.reveal_weight;
            }
        }
        buffer
    }

    fn admits(&self, pair: &BufferedPair) -> bool {
        self.commits < config::PUBLICATION_PENDING_COMMITS
            && self.commit_vbytes + pair.commit_weight.div_ceil(4)
                <= config::PUBLICATION_COMMIT_VBYTES
            && self.weight + pair.commit_weight + pair.reveal_weight
                <= config::PUBLICATION_BUFFER_WEIGHT
    }

    fn add(&mut self, pair: &BufferedPair) {
        self.commits += 1;
        self.commit_vbytes += pair.commit_weight.div_ceil(4);
        self.weight += pair.commit_weight + pair.reveal_weight;
        self.broadcast_weight += pair.commit_weight;
    }
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
        blocks: HashMap::new(),
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
    session.walk(plan, &anchor, notify)?;
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
        anchor: &(u64, String),
        notify: &mut impl FnMut(&Progress) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pairs = self.inventory(plan, notify)?;
        if !self.submit || !self.progress.retryable {
            return Ok(());
        }
        if self.node.block_hash(anchor.0)?.to_string() != anchor.1 {
            self.progress.report.blocked_reason =
                "chain changed during reconciliation; waiting for fresh observations".into();
            return Ok(());
        }
        let mut buffer = Buffer::new(&pairs, &self.progress.observations);
        let mut data_available = true;
        let mut leaves_available = true;
        let mut parent_available = true;
        let mut limited = false;
        for (index, pair) in pairs.iter().enumerate() {
            notify(&self.progress)?;
            let offset = index * 2;
            let mut commit = self.progress.observations[offset].state.clone();
            if matches!(commit, State::Prepared | State::Missing) && parent_available {
                if buffer.admits(pair) && self.progress.report.blocked_reason.is_empty() {
                    commit = self.submit_record(plan, index, offset, true)?;
                    if commit == State::Mempool {
                        buffer.add(pair);
                    }
                } else {
                    limited = true;
                }
            }
            parent_available = matches!(commit, State::Confirmed | State::Mempool);
            let dependencies = match pair.role {
                "leaf" => data_available,
                "root" => data_available && leaves_available,
                _ => true,
            };
            let mut reveal = self.progress.observations[offset + 1].state.clone();
            if commit == State::Confirmed
                && dependencies
                && self.progress.retryable
                && self.progress.report.blocked_reason.is_empty()
                && matches!(reveal, State::Prepared | State::Missing)
            {
                if buffer.broadcast_weight + pair.reveal_weight <= config::PUBLICATION_BUFFER_WEIGHT
                {
                    reveal = self.submit_record(plan, index, offset + 1, false)?;
                    if reveal == State::Mempool {
                        buffer.broadcast_weight += pair.reveal_weight;
                    }
                } else {
                    limited = true;
                }
            }
            match pair.role {
                "data" => data_available &= matches!(reveal, State::Confirmed | State::Mempool),
                "leaf" => leaves_available &= matches!(reveal, State::Confirmed | State::Mempool),
                _ => (),
            }
            notify(&self.progress)?;
            if !self.progress.retryable || !self.progress.report.blocked_reason.is_empty() {
                break;
            }
        }
        if limited && self.progress.report.blocked_reason.is_empty() {
            self.progress.report.blocked_reason =
                "Publication buffer full; waiting for blockchain confirmation. Publication continues automatically while watching; no user input needed.".into();
        }
        Ok(())
    }

    fn inventory(
        &mut self,
        plan: &DiskPlan,
        notify: &mut impl FnMut(&Progress) -> Result<(), Error>,
    ) -> Result<Vec<BufferedPair>, Error> {
        let mut pairs = Vec::new();
        for index in 0..plan.record_count {
            notify(&self.progress)?;
            let pair = plan.record(index)?;
            let role = match record(&pair)? {
                MultipartRecord::Data(_) => "data",
                MultipartRecord::Leaf(_) => "leaf",
                MultipartRecord::Root(_) => "root",
            };
            let limit = usize::try_from(config::STANDARD_TX_WEIGHT)? * 2;
            let commit = decode(&pair.commit, limit)?;
            let reveal = decode(&pair.reveal, limit)?;
            pairs.push(BufferedPair {
                role,
                commit_weight: commit.weight().to_wu(),
                reveal_weight: reveal.weight().to_wu(),
            });
            self.progress.report.transactions.clear();
            self.transaction(&pair.commit, "commit", false)?;
            if !self.progress.retryable {
                break;
            }
            self.transaction(&pair.reveal, role, false)?;
            if !self.progress.retryable {
                break;
            }
        }
        notify(&self.progress)?;
        Ok(pairs)
    }

    fn submit_record(
        &mut self,
        plan: &DiskPlan,
        index: usize,
        offset: usize,
        commit: bool,
    ) -> Result<State, Error> {
        let pair = plan.record(u32::try_from(index)?)?;
        let role = self.progress.observations[offset].role.clone();
        let raw = if commit { &pair.commit } else { &pair.reveal };
        let state = self.transaction(raw, &role, true)?;
        self.progress
            .observations
            .truncate(self.progress.observations.len() - 1);
        self.progress.observations[offset].state = state.clone();
        Ok(state)
    }

    fn transaction(&mut self, raw: &str, role: &str, eligible: bool) -> Result<State, Error> {
        let txid = decode(raw, usize::try_from(config::STANDARD_TX_WEIGHT)? * 2)?.compute_txid();
        let mut presence = match self.node.presence_cached(txid, &mut self.blocks) {
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
                presence = self.node.presence_cached(txid, &mut self.blocks)?;
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
            || report
                .blocked_reason
                .starts_with("Publication buffer full;")
            || report.blocked_reason.starts_with("Commit window full (8);")
            || report.blocked_reason
                == "submission not yet observable; waiting before spending its change"
            || report.blocked_reason == "mempool full; approved fees unchanged")
        || (!report.complete
            && report.blocked_reason
                == "chain changed during reconciliation; waiting for fresh observations")
}
