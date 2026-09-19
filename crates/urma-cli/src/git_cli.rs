use crate::{
    approve_publication, config, key_cli::VaultAccess, node_cli::NodeArgs, print_report, progress,
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use urma::error::Error;
use urma_git::{inventory::Limits, workflows};
use urma_runtime::plan::PlanLimits;

#[derive(Args)]
pub(crate) struct GitLimits {}

impl GitLimits {
    fn load(&self) -> Result<Limits, Error> {
        config::git_limits()
    }
}

#[derive(Args)]
pub(crate) struct PrepareArgs {
    #[arg(default_value = ".")]
    repo: PathBuf,
    #[arg(long, help = "Public repository name [default: source directory name]")]
    name: Option<String>,
    #[arg(long, default_value = ".urma-plan")]
    output: PathBuf,
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    resources: GitLimits,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(
        long,
        default_value_t = 100_000,
        help = "Maximum total fee in litoshis; planning never broadcasts"
    )]
    max_fee: u64,
}

#[derive(Args)]
pub(crate) struct ResumeArgs {
    #[arg(long, default_value = ".urma-plan")]
    plan: PathBuf,
    #[arg(long)]
    #[arg(
        short,
        help = "Approve the displayed plan and exact fee without a prompt"
    )]
    yes: bool,
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
    #[command(about = "Freeze HEAD, scan content and quote publication (no broadcast)")]
    Prepare(PrepareArgs),
    #[command(about = "Show the frozen content, funding and fee")]
    Inspect {
        #[arg(long, default_value = ".urma-plan")]
        plan: PathBuf,
    },
    #[command(about = "Record content review for the frozen plan")]
    Review {
        #[arg(long, default_value = ".urma-plan")]
        plan: PathBuf,
        #[arg(long)]
        classify_public_test_material: Vec<String>,
    },
    #[command(about = "Approve and publish the reviewed plan")]
    Publish(ResumeArgs),
    #[command(about = "Continue the same publication after confirmation")]
    Resume(ResumeArgs),
    #[command(about = "Recover content and transaction proofs without checkout")]
    Recover(RecoverArgs),
    #[command(
        about = "Clone a published Git snapshot into an editable repository",
        after_help = "Examples:
  urma git clone <TXID>
  urma git clone <TXID> --testnet
  urma git clone <TXID> my-project

Litecoin mainnet is the default. No wallet or account is needed to clone."
    )]
    Clone {
        #[arg(value_name = "TXID", help = "URMA Git root transaction ID")]
        root: bitcoin::Txid,
        #[arg(
            help = "Destination directory [default: published repository name; TXID for unnamed roots]"
        )]
        directory: Option<PathBuf>,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        resources: GitLimits,
    },
    #[command(about = "Verify retained transaction proofs and Git content offline")]
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
    let name = urma_git::config::publication_name(
        &args.repo,
        urma_git::config::PublicationName(args.name),
    )
    .map_err(boundary)?;
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let report = workflows::prepare_named(
        &node,
        &signer,
        &args.repo,
        &args.output,
        &args.resources.load()?,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: urma_runtime::plan::PublicationPlan::MAX_RECORDS,
        },
        &name,
    )
    .map_err(boundary)?;
    Ok(serde_json::to_value(report)?)
}

fn publish(args: ResumeArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let reviewed = workflows::inspect_plan(&args.plan).map_err(boundary)?;
    approve_publication(
        "Publish Git snapshot",
        &reviewed.plan_id,
        reviewed.total_fee,
        args.yes,
    )?;
    let report = workflows::publish(&node, &args.plan, &reviewed.plan_id).map_err(boundary)?;
    let mut value = serde_json::to_value(&report)?;
    value["publication_plan_id"] = json!(report.plan_id);
    value["plan_id"] = json!(reviewed.plan_id);
    if !report.complete {
        print_report(value)?;
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
        GitCommand::Recover(args) => recover(args),
        GitCommand::Clone {
            root,
            directory,
            node,
            resources,
        } => {
            let requested = urma_git::config::CloneDestination(directory);
            urma_git::config::staging_parent(&requested).map_err(boundary)?;
            progress(format!("Connecting to {}...", node.chain()?.label()));
            let node = node.connect()?;
            progress("Receiving and verifying URMA objects...".into());
            let (report, directory) =
                workflows::clone_root_named(&node, root, requested, &resources.load()?)
                    .map_err(boundary)?;
            progress(format!("Cloning into '{}'...", directory.display()));
            progress(format!(
                "Receiving objects: {} bytes, done.",
                report.snapshot.descriptor.pack_length
            ));
            progress("Verifying signatures, hashes and Git PACK: done.".into());
            progress(format!(
                "Checking out {}: done.",
                hex::encode(&report.snapshot.descriptor.head)
            ));
            progress(format!("Ready in '{}'.", directory.display()));
            Ok(Value::Null)
        }
        GitCommand::Verify {
            snapshot,
            resources,
        } => Ok(serde_json::to_value(
            workflows::verify(&snapshot, &resources.load()?).map_err(boundary)?,
        )?),
    }
}
