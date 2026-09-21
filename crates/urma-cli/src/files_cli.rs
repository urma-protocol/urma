use crate::common_cli::publish_plan;
use crate::print_report;
use crate::{config, key_cli::VaultAccess, node_cli::NodeArgs};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma_files::{
    capture::Capture,
    ingest::{self, IngestRequest},
    inventory::Inventory,
    recover::{self, ObjectSource},
};
use urma_identity::keys::RecoverySecret;
use urma_runtime::error::{Error, ensure};

#[derive(Args)]
pub(crate) struct IngestArgs {
    #[arg(required = true)]
    pub(crate) input: Vec<PathBuf>,
    #[arg(long, default_value = "archive.urma")]
    pub(crate) output: PathBuf,
    #[arg(long, default_value = "My files")]
    pub(crate) collection: String,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    #[arg(default_value = "archive.urma")]
    pub(crate) bundle: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverArgs {
    #[arg(default_value = "archive.urma")]
    pub(crate) bundle: PathBuf,
    #[arg(long)]
    pub(crate) output: PathBuf,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    #[command(about = "Encrypt files and directories into a local collection")]
    Ingest(IngestArgs),
    #[command(about = "Authenticate and show a collection catalog")]
    Inspect(InspectArgs),
    #[command(about = "Restore a local encrypted collection")]
    Recover(RecoverArgs),
    #[command(about = "Quote and prepare collection publication (no broadcast)")]
    Plan(PlanArgs),
    #[command(about = "Approve and publish the prepared collection")]
    Publish(PublishArgs),
    #[command(about = "Continue the same collection publication")]
    Resume(PublishArgs),
    #[command(about = "Discover and recover your private collections from the chain")]
    RecoverChain(RecoverChainArgs),
}

pub(crate) fn run(command: Command) -> Result<Value, Error> {
    match command {
        Command::Ingest(args) => ingest_collection(args, Capture::Files),
        Command::Inspect(args) => inspect(args, "urma.private-files"),
        Command::Recover(args) => recover_collection(args, "urma.private-files"),
        Command::Plan(args) => plan(args, "urma.private-files"),
        Command::Publish(args) | Command::Resume(args) => publish(args),
        Command::RecoverChain(args) => recover_chain(args, "urma.private-files"),
    }
}

pub(crate) fn ingest_collection(args: IngestArgs, capture: Capture) -> Result<Value, Error> {
    let secret = RecoverySecret::import(urma_workflows::archive::read_key(
        &config::require_archive_key()?,
    )?);
    let inventory = ingest::ingest(
        &secret,
        IngestRequest {
            inputs: &args.input,
            output: &args.output,
            collection: &args.collection,
            capture,
        },
    )?;
    Ok(
        json!({"status":"sealed_locally", "broadcast":false, "bundle":args.output, "catalog":inventory.catalog, "objects":inventory.objects.len(), "originals_unchanged":true}),
    )
}

pub(crate) fn inspect(args: InspectArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(urma_workflows::archive::read_key(
        &config::require_archive_key()?,
    )?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(
        catalog.schema == schema,
        "bundle belongs to another profile"
    );
    Ok(json!({"status":"authenticated_catalog", "chain_observation":false, "catalog":catalog}))
}

pub(crate) fn recover_collection(args: RecoverArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(urma_workflows::archive::read_key(
        &config::require_archive_key()?,
    )?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(
        catalog.schema == schema,
        "bundle belongs to another profile"
    );
    let inventory = Inventory::load(&args.bundle)?;
    let report = recover::recover(
        ObjectSource::Encrypted {
            directory: &args.bundle,
            secret: &secret,
        },
        &inventory.catalog,
        &args.output,
    )?;
    print_report(json!({"output":args.output, "report":report}))?;
    ensure!(
        report.complete,
        "collection recovery incomplete; see report"
    );
    Ok(Value::Null)
}

#[derive(Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    identity: VaultAccess,
    #[arg(default_value = "archive.urma")]
    bundle: PathBuf,
    #[arg(long, default_value = "archive-plan.json")]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long, default_value_t = 100_000)]
    max_fee: u64,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, default_value = "archive-plan.json")]
    plan: PathBuf,
    #[arg(short, long, help = "Approve the displayed exact plan and fee")]
    yes: bool,
    #[arg(long, default_value = "archive-progress.json")]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverChainArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    catalog: Option<String>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_height: u64,
    #[arg(long, default_value_t = 1000)]
    max_blocks: u64,
}

pub(crate) fn plan(args: PlanArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(urma_workflows::archive::read_key(
        &config::require_archive_key()?,
    )?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(
        catalog.schema == schema,
        "bundle belongs to another profile"
    );
    ensure!(!args.output.try_exists()?, "plan output already exists");
    let inventory = Inventory::load(&args.bundle)?;
    let mut records = Vec::new();
    for object in urma_files::inventory::authenticated_objects(
        &args.bundle,
        &secret,
        usize::try_from(urma_runtime::plan::PublicationPlan::MAX_RECORDS)?,
    )? {
        records.extend(object.records);
    }
    let vault = args.identity.open()?;
    let signer = vault.keyring().active()?;
    let node = args.node.connect()?;
    let plan = urma_runtime::plan::prepare_private_records(
        &node,
        &signer,
        &records,
        urma_runtime::plan::PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: urma_runtime::plan::PublicationPlan::MAX_RECORDS,
        },
    )?;
    plan.save_new(&args.output)?;
    Ok(
        json!({"status":"prepared", "broadcast":false, "plan":args.output, "plan_id":plan.id()?, "catalog":inventory.catalog, "records":plan.records.len(), "total_fee":plan.total_fee, "maximum_fee":plan.maximum_fee, "start_height":node.tip_height()?, "author":plan.author, "review_required":true}),
    )
}

pub(crate) fn publish(args: PublishArgs) -> Result<Value, Error> {
    publish_plan(
        &args.node,
        &args.plan,
        &args.journal,
        args.yes,
        "Publish private collection",
    )
}

pub(crate) fn recover_chain(args: RecoverChainArgs, schema: &str) -> Result<Value, Error> {
    ensure!(
        !args.output.try_exists()?,
        "export requires a new directory"
    );
    let secret = RecoverySecret::import(urma_workflows::archive::read_key(
        &config::require_archive_key()?,
    )?);
    let node = args.node.connect()?;
    let scan = urma_files::chain::scan(&node, &secret, args.start_height, args.max_blocks)?;
    let id = select_catalog(&scan, args.catalog, schema)?;
    let catalog = urma_files::chain::catalog(&scan, &id)?;
    ensure!(
        catalog.schema == schema,
        "catalog belongs to another profile"
    );
    let report = recover::recover(
        ObjectSource::Authenticated {
            objects: &scan.objects,
        },
        &id,
        &args.output,
    )?;
    print_report(
        json!({"output":args.output, "catalog":id, "report":report, "start_height":scan.start_height, "tip_height":scan.tip_height, "tip_hash":scan.tip_hash, "rejected_records":scan.rejected_records, "chain_evidence":node.inclusion_evidence(),"private_objects":"authenticated"}),
    )?;
    ensure!(
        report.complete,
        "collection recovery incomplete; see report"
    );
    Ok(Value::Null)
}

fn select_catalog(
    scan: &urma_files::chain::ChainRecovery,
    selected: Option<String>,
    schema: &str,
) -> Result<String, Error> {
    match selected {
        Some(id) => Ok(id),
        None => {
            let mut candidates = Vec::new();
            for id in urma_files::chain::catalogs(scan)? {
                if urma_files::chain::catalog(scan, &id)?.schema == schema {
                    candidates.push(id);
                }
            }
            ensure!(
                candidates.len() == 1,
                "supply --catalog: found {} matching catalogs: {}",
                candidates.len(),
                candidates.join(",")
            );
            candidates
                .pop()
                .ok_or_else(|| Error::Missing("catalog not found".into()))
        }
    }
}
