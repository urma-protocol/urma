use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma::{error::{Error, ensure}, storage};
use urma_files::{capture::Capture, ingest::{self, IngestRequest}, inventory::Inventory, recover::{self, ObjectSource}};
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
}

pub(crate) fn run(command: Command) -> Result<Value, Error> {
    match command {
        Command::Ingest(args) => ingest_collection(args, Capture::Files),
        Command::Inspect(args) => inspect(args, "urma.private-files"),
        Command::Recover(args) => recover_collection(args, "urma.private-files"),
    }
}

pub(crate) fn ingest_collection(args: IngestArgs, capture: Capture) -> Result<Value, Error> {
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
    let inventory = ingest::ingest(&secret, IngestRequest { inputs: &args.input, output: &args.output, collection: &args.collection, capture })?;
    Ok(json!({"status":"sealed_locally", "broadcast":false, "bundle":args.output, "catalog":inventory.catalog, "objects":inventory.objects.len(), "originals_unchanged":true}))
}

pub(crate) fn inspect(args: InspectArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(catalog.schema == schema, "bundle belongs to another profile");
    Ok(json!({"status":"authenticated_catalog", "chain_observation":false, "catalog":catalog}))
}

pub(crate) fn recover_collection(args: RecoverArgs, schema: &str) -> Result<Value, Error> {
    let secret = RecoverySecret::import(storage::read_key(&args.key)?);
    let catalog = recover::inspect_bundle(&args.bundle, &secret)?;
    ensure!(catalog.schema == schema, "bundle belongs to another profile");
    let inventory = Inventory::load(&args.bundle)?;
    let report = recover::recover(ObjectSource::Encrypted { directory: &args.bundle, secret: &secret }, &inventory.catalog, &args.output)?;
    crate::print_json(json!({"output":args.output, "report":report}))?;
    ensure!(report.complete, "collection recovery incomplete; see report");
    Ok(Value::Null)
}
