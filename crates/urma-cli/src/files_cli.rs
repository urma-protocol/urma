use crate::{key_cli::VaultAccess, node_cli::NodeArgs, print_json};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma::{
    error::{Error, ensure},
    storage,
};
use urma_files::{
    capture::Capture,
    ingest::{self, IngestRequest},
    inventory::Inventory,
    recover::{self, ObjectSource},
};
use urma_identity::keys::RecoverySecret;

#[derive(Args)]
pub(crate) struct IngestArgs {
    #[arg(long, required = true)]
    pub(crate) input: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long)]
    pub(crate) output: PathBuf,
    #[arg(long)]
    pub(crate) collection: String,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    #[arg(long)]
    pub(crate) bundle: PathBuf,
    #[arg(long)]
    pub(crate) key: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverArgs {
    #[arg(long)]
    pub(crate) bundle: PathBuf,
    #[arg(long)]
    pub(crate) key: PathBuf,
    #[arg(long)]
    pub(crate) output: PathBuf,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Ingest(IngestArgs),
    Inspect(InspectArgs),
    Recover(RecoverArgs),
    Plan(PlanArgs),
    Publish(PublishArgs),
    Resume(PublishArgs),
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
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
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
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(
        catalog.schema == schema,
        "bundle belongs to another profile"
    );
    Ok(json!({"status":"authenticated_catalog", "chain_observation":false, "catalog":catalog}))
}

pub(crate) fn recover_collection(args: RecoverArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
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
    print_json(json!({"output":args.output, "report":report}))?;
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
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long)]
    max_fee: u64,
    #[arg(long, default_value_t = 1024)]
    max_records: u32,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    approve: String,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverChainArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    key: PathBuf,
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
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
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
        usize::try_from(args.max_records)?,
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
            max_records: args.max_records,
        },
    )?;
    plan.save_new(&args.output)?;
    Ok(
        json!({"status":"prepared", "broadcast":false, "plan":args.output, "plan_id":plan.id()?, "catalog":inventory.catalog, "records":plan.records.len(), "total_fee":plan.total_fee, "maximum_fee":plan.maximum_fee, "start_height":node.tip_height()?, "author":plan.author, "review_required":true}),
    )
}

pub(crate) fn publish(args: PublishArgs) -> Result<Value, Error> {
    urma_runtime::publish::ensure_journal_distinct(&args.plan, &args.journal)?;
    let plan = urma_runtime::plan::PublicationPlan::load(&args.plan)?;
    let report =
        urma_runtime::publish::publish(&args.node.connect()?, &plan, &args.approve, &args.journal)?;
    print_json(serde_json::to_value(&report)?)?;
    ensure!(
        report.complete,
        "publication paused; inspect report and resume exact plan"
    );
    Ok(Value::Null)
}

pub(crate) fn recover_chain(args: RecoverChainArgs, schema: &str) -> Result<Value, Error> {
    ensure!(
        !args.output.try_exists()?,
        "export requires a new directory"
    );
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
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
    print_json(
        json!({"output":args.output, "catalog":id, "report":report, "start_height":scan.start_height, "tip_height":scan.tip_height, "tip_hash":scan.tip_hash, "rejected_records":scan.rejected_records, "evidence":"local_validating_node_and_authenticated_private_objects"}),
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
