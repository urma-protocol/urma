#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
use crate::common_cli::export_recovery;
use crate::{config as cli_config, print_report as print};
use clap::{Args, Subcommand};
use rand::rngs::OsRng;
use serde_json::json;
use std::path::{Path, PathBuf};
use urma_runtime::config;
use urma_runtime::error::{Context, Error, ensure};
use urma_runtime::{
    backend, container,
    litecoin::{self, Core, Plan},
    storage,
};

#[derive(Args)]
pub(crate) struct RpcArgs {}
impl RpcArgs {
    fn core(&self, wallet: Option<&str>) -> Result<Core, Error> {
        {
            let local = cli_config::expert_node()?;
            Core::connect(&local.rpc_url, &local.cookie_file, wallet.into())
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Quote(QuoteArgs),
    Address(AddressArgs),
    Prepare(PrepareArgs),
    Inspect(InspectArgs),
    Sign(SignArgs),
    Status(StatusArgs),
    Broadcast(BroadcastArgs),
    Recover(RecoverArgs),
}

fn read_plan(path: &Path) -> Result<Plan, Error> {
    serde_json::from_slice(&storage::read_bounded(
        path,
        config::LITECOIN_MAX_JOURNAL_BYTES,
    )?)
    .context("invalid Litecoin journal")
}
pub(crate) fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Quote(args) => quote(args),
        Command::Address(args) => address(args),
        Command::Prepare(args) => prepare(args),
        Command::Inspect(args) => inspect(args),
        Command::Sign(args) => sign(args),
        Command::Status(args) => status(args),
        Command::Broadcast(args) => broadcast(args),
        Command::Recover(args) => recover(args),
    }
}

#[derive(Args)]
pub(crate) struct QuoteArgs {
    #[arg(long)]
    input_bytes: usize,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
}

#[derive(Args)]
pub(crate) struct AddressArgs {
    #[command(flatten)]
    rpc: RpcArgs,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    input_bytes: usize,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
}

#[derive(Args)]
pub(crate) struct PrepareArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    input_bytes: usize,
    #[arg(long)]
    funding: PathBuf,
    #[arg(long)]
    start_height: u64,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct SignArgs {
    #[command(flatten)]
    rpc: RpcArgs,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct StatusArgs {
    #[command(flatten)]
    rpc: RpcArgs,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct BroadcastArgs {
    #[command(flatten)]
    rpc: RpcArgs,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    max_fee_litoshis: u64,
}

#[derive(Args)]
pub(crate) struct RecoverArgs {
    #[command(flatten)]
    rpc: RpcArgs,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    start_height: u64,
    #[arg(long)]
    output_dir: PathBuf,
}

fn quote(args: QuoteArgs) -> Result<(), Error> {
    let QuoteArgs {
        input_bytes,
        fee_rate,
    } = args;
    print(serde_json::to_value(litecoin::quote(
        input_bytes,
        fee_rate,
    )?)?)
}

fn address(args: AddressArgs) -> Result<(), Error> {
    let AddressArgs {
        rpc,
        wallet,
        input_bytes,
        fee_rate,
    } = args;

    let costs = litecoin::quote(input_bytes, fee_rate)?;
    let address = litecoin::receiving_address(&rpc.core(Some(&wallet))?)?;
    print(
        json!({"network":config::LITECOIN_NETWORK,"receiving_address":address,"quote":costs,"broadcast":false}),
    )
}

fn prepare(args: PrepareArgs) -> Result<(), Error> {
    let PrepareArgs {
        bundle,
        input_bytes,
        funding,
        start_height,
        fee_rate,
        journal,
    } = args;

    ensure!(!journal.try_exists()?, "journal already exists");
    let records = container::unpack(&storage::read_bounded(
        &bundle,
        urma_runtime::config::Limits::CONTAINER_BYTES,
    )?)?;
    let funding = serde_json::from_slice(&storage::read_bounded(&funding, 1_000_000)?)?;
    let plan = litecoin::prepare(
        &records,
        input_bytes,
        funding,
        fee_rate,
        start_height,
        &mut OsRng,
    )?;
    let report = litecoin::inspect(&plan, false)?;
    storage::write_new(&journal, &serde_json::to_vec_pretty(&plan)?)?;
    print(report)
}

fn inspect(args: InspectArgs) -> Result<(), Error> {
    let InspectArgs { journal } = args;

    let plan = read_plan(&journal)?;
    print(litecoin::inspect(&plan, litecoin::is_signed(&plan)?)?)
}

fn sign(args: SignArgs) -> Result<(), Error> {
    let SignArgs {
        rpc,
        wallet,
        journal,
        output,
    } = args;

    ensure!(
        !output.try_exists()?,
        "signed journal output already exists"
    );
    let draft = read_plan(&journal)?;
    litecoin::inspect(&draft, false)?;
    let plan = litecoin::sign(&rpc.core(Some(&wallet))?, &draft)?;
    storage::write_new(&output, &serde_json::to_vec_pretty(&plan)?)?;
    print(litecoin::inspect(&plan, true)?)
}

fn status(args: StatusArgs) -> Result<(), Error> {
    let StatusArgs { rpc, journal } = args;

    let plan = read_plan(&journal)?;
    litecoin::inspect(&plan, true)?;
    print(litecoin::status(&rpc.core(None)?, &plan)?)
}

fn broadcast(args: BroadcastArgs) -> Result<(), Error> {
    let BroadcastArgs {
        rpc,
        journal,
        max_fee_litoshis,
    } = args;

    let plan = read_plan(&journal)?;
    litecoin::inspect(&plan, true)?;
    print(litecoin::broadcast(
        &rpc.core(None)?,
        &plan,
        max_fee_litoshis,
    )?)
}

fn recover(args: RecoverArgs) -> Result<(), Error> {
    let RecoverArgs {
        rpc,
        key,
        start_height,
        output_dir,
    } = args;

    ensure!(!output_dir.try_exists()?, "output directory already exists");
    let key = urma_workflows::archive::read_key(&key)?;
    let node = rpc.core(None)?;
    export_recovery(
        backend::recover(
            &litecoin::LitecoinRecords {
                rpc: &node,
                start_height,
            },
            &key,
        )?,
        &output_dir,
    )
}
