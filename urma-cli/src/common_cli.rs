use crate::{approve_publication, node_cli::NodeArgs, print_report};
use serde_json::Value;
use std::path::Path;
use urma_runtime::error::{Error, ensure};
use urma_runtime::{backend, plan::PublicationPlan, publish};

pub(crate) fn export_recovery(recovery: backend::Recovery, output: &Path) -> Result<(), Error> {
    let exported = backend::export(recovery, output)?;
    print_report(exported.report)?;
    ensure!(
        exported.complete,
        "recovery incomplete or invalid objects; see JSON report"
    );
    Ok(())
}

pub(crate) fn publish_plan(
    node: &NodeArgs,
    plan_path: &Path,
    journal: &Path,
    yes: bool,
    label: &str,
) -> Result<Value, Error> {
    publish::ensure_journal_distinct(plan_path, journal)?;
    let plan = PublicationPlan::load(plan_path)?;
    let node = node.connect()?;
    let id = plan.id()?;
    approve_publication(label, &id, plan.total_fee, yes)?;
    let report = publish::publish(&node, &plan, &id, journal)?;
    print_report(serde_json::to_value(&report)?)?;
    ensure!(
        report.complete,
        "publication paused; inspect report and resume exact plan"
    );
    Ok(Value::Null)
}
