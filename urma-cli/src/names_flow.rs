use crate::{
    approve_publication,
    config::{self, IndexChoice},
    node_cli::chain_name,
    print_report, progress,
};
use bitcoin::{Transaction, Txid, consensus::deserialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use urma_core::{envelope, format::PublicRecord};
use urma_names::{error::NamesError, index::NamesIndex, payload::Payload};
use urma_runtime::{
    error::{Context, Error, bail, ensure},
    node::{Node, Presence},
    plan::PublicationPlan,
    publish::{self, PublishReport, RevealTiming},
};

pub(crate) struct Publication<'a> {
    pub(crate) plan: &'a Path,
    pub(crate) journal: &'a Path,
    pub(crate) index: Option<PathBuf>,
    pub(crate) label: &'a str,
    pub(crate) yes: bool,
    pub(crate) watch: bool,
}

enum RevealWindow {
    Unchecked,
    Blocks(u64),
}

pub(crate) fn names_error(cause: NamesError) -> Error {
    match cause {
        NamesError::Protocol(cause) => Error::Protocol(cause),
        NamesError::Block(cause) => Error::from(cause),
        NamesError::Io(cause) => Error::from(cause),
        NamesError::Json(cause) => Error::Json(cause),
        NamesError::Integer(cause) => Error::Integer(cause),
        NamesError::Hash(cause) => Error::Hash(cause),
        NamesError::Invalid(message) => Error::Invalid(message),
        NamesError::Missing(message) => Error::Missing(message),
    }
}

pub(crate) fn names_record(bytes: &[u8]) -> Result<Payload, Error> {
    Ok(Payload::from_record(&PublicRecord::decode(bytes)?)?)
}

pub(crate) fn registry_of(payload: &Payload) -> Result<Txid, Error> {
    match payload {
        Payload::Genesis(..) => Err(Error::Missing("genesis records have no registry".into())),
        Payload::Claim(op) | Payload::Update(op) | Payload::Renew(op) => Ok(op.registry),
        Payload::Approve(approval) => Ok(approval.registry),
        Payload::Suspend(op) | Payload::Restore(op) => Ok(op.registry),
    }
}

fn planned(plan: &PublicationPlan) -> Result<(Transaction, Transaction), Error> {
    ensure!(
        plan.records.len() == 1,
        "names plans carry exactly one record"
    );
    let commit: Transaction = deserialize(&hex::decode(&plan.records[0].commit)?)?;
    let reveal: Transaction = deserialize(&hex::decode(&plan.records[0].reveal)?)?;
    Ok((commit, reveal))
}

impl RevealWindow {
    fn of(node: &Node, plan: &PublicationPlan, index: Option<PathBuf>) -> Result<Self, Error> {
        let reveal = planned(plan)?.1;
        let payload = names_record(&envelope::extract_reveal(&reveal)?.record)?;
        let Payload::Genesis(..) = payload else {
            let registry = registry_of(&payload)?;
            let network = chain_name(node.chain())?;
            let path = config::names_index(
                IndexChoice {
                    path: index,
                    registry: Some(registry),
                },
                &network,
            )?;
            return Self::from_index(&path, registry);
        };
        Ok(Self::Unchecked)
    }

    fn from_index(path: &Path, registry: Txid) -> Result<Self, Error> {
        if !path.try_exists()? {
            tracing::warn!(index = %path.display(), "no names index; the reveal window is not checked");
            return Ok(Self::Unchecked);
        }
        let index = NamesIndex::load(path).map_err(names_error)?;
        if index.registry.genesis() != registry {
            tracing::warn!(index = %path.display(), "names index belongs to another registry; the reveal window is not checked");
            return Ok(Self::Unchecked);
        }
        Ok(Self::Blocks(u64::from(
            index.registry.rules().reveal_max_blocks,
        )))
    }

    fn check(&self, node: &Node, plan: &PublicationPlan) -> Result<(), Error> {
        let Self::Blocks(window) = self else {
            return Ok(());
        };
        let (commit, reveal) = planned(plan)?;
        match node.presence(reveal.compute_txid())? {
            Presence::Missing => {}
            Presence::Mempool | Presence::Confirmed { .. } => return Ok(()),
        }
        let Presence::Confirmed { height, .. } = node.presence(commit.compute_txid())? else {
            return Ok(());
        };
        let age = node
            .tip_height()?
            .checked_add(1)
            .context("height overflow")?
            .checked_sub(height)
            .context("commit above the tip")?;
        ensure!(
            age <= *window,
            "commit confirmed at {height} is too old for the reveal window ({age} > {window}); encode and plan a new record"
        );
        Ok(())
    }
}

fn waiting(report: &PublishReport) -> bool {
    report.blocked_reason.starts_with("awaiting")
        || report.blocked_reason == "mempool full"
        || report.blocked_reason == "transaction missing after submission; resume exact plan"
}

pub(crate) fn follow(node: &Node, publication: Publication<'_>) -> Result<Value, Error> {
    publish::ensure_journal_distinct(publication.plan, publication.journal)?;
    let plan = PublicationPlan::load(publication.plan)?;
    let id = plan.id()?;
    approve_publication(publication.label, &id, plan.total_fee, publication.yes)?;
    let window = RevealWindow::of(node, &plan, publication.index)?;
    loop {
        window.check(node, &plan)?;
        let report = publish::publish_with(
            node,
            &plan,
            &id,
            publication.journal,
            RevealTiming::AfterConfirmation,
        )?;
        if report.complete {
            print_report(serde_json::to_value(&report)?)?;
            return Ok(Value::Null);
        }
        if !publication.watch || !waiting(&report) {
            print_report(serde_json::to_value(&report)?)?;
            bail!(
                "publication paused: {}; inspect report and resume exact plan",
                report.blocked_reason
            );
        }
        progress(format!(
            "{}; checking again in {}s",
            report.blocked_reason,
            config::names_watch_interval().as_secs()
        ));
        std::thread::sleep(config::names_watch_interval());
    }
}
