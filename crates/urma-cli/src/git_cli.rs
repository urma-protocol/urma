use crate::{key_cli::VaultAccess, node_cli::NodeArgs, print_json};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use urma::error::Error;
use urma_git::{inventory::Limits, workflows};
use urma_runtime::plan::PlanLimits;

#[derive(Args)]
pub(crate) struct GitLimits {
    #[arg(long)]
    limits: Option<PathBuf>,
}

impl GitLimits {
    fn load(&self) -> Result<Limits, Error> {
        let mut limits = Limits::default();
        for path in self.limits.iter() {
            limits = serde_json::from_slice(&urma::storage::read_bounded(path, 4096)?)?;
        }
        Ok(limits)
    }
}

#[derive(Args)]
pub(crate) struct PrepareArgs {
    #[arg(long)]
    repo: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    resources: GitLimits,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long)]
    max_fee: u64,
    #[arg(long, default_value_t = 1024)]
    max_records: u32,
}

#[derive(Args)]
pub(crate) struct ResumeArgs {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    approve: String,
    #[command(flatten)]
    node: NodeArgs,
}

#[derive(Args)]
pub(crate) struct RecoverArgs {
    root: String,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    resources: GitLimits,
}

#[derive(Subcommand)]
pub(crate) enum GitCommand {
    Prepare(PrepareArgs),
    Inspect {
        #[arg(long)]
        plan: PathBuf,
    },
    Review {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        classify_public_test_material: Vec<String>,
    },
    Publish(ResumeArgs),
    Resume(ResumeArgs),
    Recover(RecoverArgs),
    Fetch(RecoverArgs),
    InspectRoot(RecoverArgs),
    Clone {
        root: String,
        directory: PathBuf,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        resources: GitLimits,
    },
    Verify {
        #[arg(long)]
        snapshot: PathBuf,
        #[command(flatten)]
        resources: GitLimits,
    },
}

fn boundary(error: urma_git::error::Error) -> Error {
    Error::Io(std::io::Error::other(error))
}

fn prepare(args: PrepareArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let report = workflows::prepare(
        &node,
        &signer,
        &args.repo,
        &args.output,
        &args.resources.load()?,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: args.max_records,
        },
    )
    .map_err(boundary)?;
    Ok(serde_json::to_value(report)?)
}

fn publish(args: ResumeArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let report = workflows::publish(&node, &args.plan, &args.approve).map_err(boundary)?;
    let value = serde_json::to_value(&report)?;
    if !report.complete {
        print_json(value)?;
        return Err(Error::Missing(format!(
            "Git publication remains incomplete: {}",
            report.blocked_reason
        )));
    }
    Ok(value)
}

fn recover(args: RecoverArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let root = workflows::parse_root(&node, &args.root).map_err(boundary)?;
    Ok(serde_json::to_value(
        workflows::recover(&node, root, &args.output, &args.resources.load()?).map_err(boundary)?,
    )?)
}

fn review(plan: &Path, classifications: &[String]) -> Result<Value, Error> {
    let report = workflows::inspect_plan(plan).map_err(boundary)?;
    let hash = workflows::record_review(plan, classifications).map_err(boundary)?;
    Ok(json!({"plan_id":hash,"review_recorded":true,"broadcast":false,"report":report}))
}

pub(crate) fn run(command: GitCommand) -> Result<Value, Error> {
    match command {
        GitCommand::Prepare(args) => prepare(args),
        GitCommand::Inspect { plan } => Ok(serde_json::to_value(
            workflows::inspect_plan(&plan).map_err(boundary)?,
        )?),
        GitCommand::Review {
            plan,
            classify_public_test_material,
        } => review(&plan, &classify_public_test_material),
        GitCommand::Publish(args) | GitCommand::Resume(args) => publish(args),
        GitCommand::Recover(args) | GitCommand::Fetch(args) | GitCommand::InspectRoot(args) => {
            recover(args)
        }
        GitCommand::Clone {
            root,
            directory,
            node,
            resources,
        } => {
            let node = node.connect()?;
            let root = workflows::parse_root(&node, &root).map_err(boundary)?;
            Ok(serde_json::to_value(
                workflows::clone_root(&node, root, &directory, &resources.load()?)
                    .map_err(boundary)?,
            )?)
        }
        GitCommand::Verify {
            snapshot,
            resources,
        } => Ok(serde_json::to_value(
            workflows::verify(&snapshot, &resources.load()?).map_err(boundary)?,
        )?),
    }
}
