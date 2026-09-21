#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
use crate::common_cli::export_recovery;
use crate::{config, files_cli, litecoin_cli, print_report};
use bitcoin::{Network, Txid};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use urma_runtime::error::{Context, Error, bail, ensure};
use urma_runtime::journal::{self, Plan};
use urma_runtime::{
    backend::{self, DirectorySource, Family},
    bitcoin_rpc::{self as transport, Node},
    container,
    source::Source,
    storage,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, ValueEnum)]
enum Chain {
    Regtest,
    Testnet4,
}

impl From<Chain> for Network {
    fn from(chain: Chain) -> Self {
        match chain {
            Chain::Regtest => Self::Regtest,
            Chain::Testnet4 => Self::Testnet4,
        }
    }
}

#[derive(Args)]
struct Rpc {
    #[arg(long, value_enum, default_value_t = Chain::Regtest)]
    network: Chain,
}

impl Rpc {
    fn node(&self, wallet: Option<&str>) -> Result<Node, Error> {
        let local = config::expert_node()?;
        Node::connect_for_network(
            &local.rpc_url,
            &local.cookie_file,
            wallet.into(),
            self.network.into(),
        )
    }
}

#[derive(Args)]
struct Publisher {
    #[command(flatten)]
    rpc: Rpc,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    mine: bool,
    #[arg(long)]
    stop_after_chunks: Option<usize>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Files {
        #[command(subcommand)]
        command: files_cli::Command,
    },
    Litecoin {
        #[command(subcommand)]
        command: litecoin_cli::Command,
    },
    BroadcastSource(BroadcastSourceArgs),
    FetchTransactions(FetchTransactionsArgs),
    Backends,
    StoreLocal(StoreLocalArgs),
    RecoverLocal(RecoverLocalArgs),
    Seal(SealArgs),
    Open(OpenArgs),
    Prepare(PrepareArgs),
    Inspect(InspectArgs),
    Broadcast(BroadcastArgs),
    Status(StatusArgs),
    Publish(PublishArgs),
    Resume(ResumeArgs),
    Recover(RecoverArgs),
}

fn read_plan(path: &std::path::Path) -> Result<Plan, Error> {
    let plan = serde_json::from_slice(&storage::read_bounded(
        path,
        12 * urma_runtime::config::Limits::CONTAINER_BYTES,
    )?)?;
    journal::validate_plan(&plan)?;
    Ok(plan)
}

pub(crate) fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Files { command } => print_report(files_cli::run(command)?)?,
        Command::Litecoin { command } => litecoin_cli::run(command)?,
        Command::BroadcastSource(args) => broadcast_source(args)?,
        Command::FetchTransactions(args) => fetch_transactions(args)?,
        Command::Backends => print_report(json!({
            "policy": backend::Policy::default(),
            "adapters": ([Family::Litecoin, Family::Bitcoin, Family::Directory, Family::Ethereum,
                Family::Storj, Family::GoogleDrive, Family::S3].map(|family| json!({
                    "backend": family, "implemented": matches!(family, Family::Litecoin | Family::Bitcoin | Family::Directory)
                }))),
            "note": "Litecoin testnet adapter is available through urma archive litecoin; live-node validation is pending. No automatic backend fallback; this binary's prepare/broadcast remain Bitcoin-only."
        }))?,
        Command::StoreLocal(args) => store_local(args)?,
        Command::RecoverLocal(args) => recover_local(args)?,
        Command::Seal(args) => seal(args)?,
        Command::Open(args) => open(args)?,
        Command::Prepare(args) => prepare(args)?,
        Command::Inspect(args) => inspect(args)?,
        Command::Broadcast(args) => broadcast(args)?,
        Command::Status(args) => status(args)?,
        Command::Publish(args) => publish(args)?,
        Command::Resume(args) => resume(args)?,
        Command::Recover(args) => recover(args)?,
    }
    Ok(())
}

#[derive(Clone, Copy, ValueEnum)]
enum PrivateType {
    Opaque,
    Text,
    Image,
    Audio,
    Video,
}
impl From<PrivateType> for urma_core::format::ContentType {
    fn from(value: PrivateType) -> Self {
        match value {
            PrivateType::Opaque => Self::Opaque,
            PrivateType::Text => Self::Text,
            PrivateType::Image => Self::Image,
            PrivateType::Audio => Self::Audio,
            PrivateType::Video => Self::Video,
        }
    }
}

fn select_funding(
    node: &Node,
    rpc: &Rpc,
    records: &[Vec<u8>],
    input_bytes: usize,
    selection: FundingSelection,
) -> Result<(Plan, Option<serde_json::Value>), Error> {
    let FundingSelection {
        source,
        address,
        funding,
        allow_unconfirmed,
        rate,
    } = selection;
    match (source, funding) {
        (Some(url), None) => {
            let source = Source::connect(&url, &rpc.network.into())?;
            let (funding, report) = source.funding(
                address.as_deref().context("missing --address")?,
                allow_unconfirmed,
            )?;
            let mut plan =
                transport::prepare_with_funding(node, records, input_bytes, &funding, rate)?;
            plan.start_height = report["tip_height"]
                .as_u64()
                .context("source omitted tip_height")?;
            Ok((plan, Some(report)))
        }
        (None, Some(path)) => {
            let funding = serde_json::from_slice(&storage::read_bounded(&path, 8_100_000)?)?;
            Ok((
                transport::prepare_with_funding(node, records, input_bytes, &funding, rate)?,
                None,
            ))
        }
        (None, None) => {
            ensure!(
                rate == 1,
                "custom fee rate requires explicit --funding or --source"
            );
            Ok((transport::prepare(node, records, input_bytes)?, None))
        }
        (Some(url), Some(path)) => bail!("source {url} conflicts with funding {}", path.display()),
    }
}

#[derive(Args)]
pub(crate) struct BroadcastSourceArgs {
    #[arg(long, value_enum)]
    network: Chain,
    #[arg(long)]
    source: String,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long)]
    max_fee_sats: u64,
    #[arg(long)]
    accept_provider_trust: bool,
    #[arg(long)]
    allow_unconfirmed_commit: bool,
}

#[derive(Args)]
pub(crate) struct FetchTransactionsArgs {
    #[arg(long, value_enum)]
    network: Chain,
    #[arg(long)]
    source: String,
    #[arg(long, required = true)]
    txid: Vec<Txid>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct StoreLocalArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    directory: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverLocalArgs {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Args)]
pub(crate) struct KeygenArgs {
    #[arg(
        long,
        help = "Override the configured private recovery-key destination"
    )]
    key: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SealArgs {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum, default_value_t = PrivateType::Opaque)]
    content_type: PrivateType,
}

#[derive(Args)]
pub(crate) struct OpenArgs {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct PrepareArgs {
    #[command(flatten)]
    rpc: Rpc,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long, requires = "address", conflicts_with = "funding")]
    source: Option<String>,
    #[arg(long, requires = "source")]
    address: Option<String>,
    #[arg(long, conflicts_with = "source")]
    funding: Option<PathBuf>,
    #[arg(long, requires = "source")]
    allow_unconfirmed_funding: bool,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long, value_enum, default_value_t = PrivateType::Opaque)]
    content_type: PrivateType,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct BroadcastArgs {
    #[command(flatten)]
    rpc: Rpc,
    #[arg(long)]
    wallet: String,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct StatusArgs {
    #[command(flatten)]
    rpc: Rpc,
    #[arg(long)]
    wallet: Option<String>,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    publisher: Publisher,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    journal: PathBuf,
    #[arg(long, value_enum, default_value_t = PrivateType::Opaque)]
    content_type: PrivateType,
}

#[derive(Args)]
pub(crate) struct ResumeArgs {
    #[command(flatten)]
    publisher: Publisher,
    #[arg(long)]
    journal: PathBuf,
}

#[derive(Args)]
pub(crate) struct RecoverArgs {
    #[command(flatten)]
    rpc: Rpc,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_height: u64,
    #[arg(long)]
    output_dir: PathBuf,
}

fn broadcast_source(args: BroadcastSourceArgs) -> Result<(), Error> {
    let BroadcastSourceArgs {
        network,
        source,
        journal,
        max_fee_sats,
        accept_provider_trust,
        allow_unconfirmed_commit,
    } = args;

    print_report(urma_runtime::relay::broadcast_plan(
        &source,
        network.into(),
        &read_plan(&journal)?,
        max_fee_sats,
        accept_provider_trust,
        allow_unconfirmed_commit,
    )?)?;

    Ok(())
}

fn fetch_transactions(args: FetchTransactionsArgs) -> Result<(), Error> {
    let FetchTransactionsArgs {
        network,
        source,
        txid,
        output,
    } = args;

    ensure!(!output.try_exists()?, "bundle output already exists");
    let (bundle, mut report) =
        Source::connect(&source, &network.into())?.transaction_bundle(&txid)?;
    storage::write_new(&output, &bundle)?;
    report["output"] = json!(output);
    print_report(report)?;

    Ok(())
}

fn store_local(args: StoreLocalArgs) -> Result<(), Error> {
    let StoreLocalArgs { input, directory } = args;

    let records = container::unpack(&storage::read_bounded(
        &input,
        urma_runtime::config::Limits::CONTAINER_BYTES,
    )?)?;
    print_report(
        json!({"status": "stored", "observation": backend::store_directory(&directory, &records)?}),
    )?;

    Ok(())
}

fn recover_local(args: RecoverLocalArgs) -> Result<(), Error> {
    let RecoverLocalArgs {
        directory,
        key,
        output_dir,
    } = args;

    ensure!(
        !output_dir.try_exists()?,
        "recovery requires a new output directory"
    );
    let key = urma_workflows::archive::read_key(&key)?;
    export_recovery(
        backend::recover(&DirectorySource { path: &directory }, &key)?,
        &output_dir,
    )?;

    Ok(())
}

pub(crate) fn keygen(args: KeygenArgs) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    let key = config::key_location(config::KeyLocation(args.key))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(urma_io::output_parent(&key))?;
    storage::write_new(&key, container::random_secret()?.as_ref())?;
    print_report(json!({"status": "created", "key_file": key}))?;

    Ok(())
}

fn seal(args: SealArgs) -> Result<(), Error> {
    let SealArgs {
        key,
        input,
        output,
        content_type,
    } = args;

    let key = urma_workflows::archive::read_key(&key)?;
    let bytes = Zeroizing::new(storage::read_bounded(
        &input,
        urma_runtime::config::Limits::INPUT_BYTES,
    )?);
    let secret = urma_identity::keys::RecoverySecret::import(key);
    let records = urma_profiles::private::seal_file(
        &secret,
        urma_profiles::private::FileOriginal {
            bytes: &bytes,
            content_type: content_type.into(),
        },
        &mut rand::rngs::OsRng,
    )?;
    storage::write_new(&output, &container::pack(&records)?)?;
    print_report(json!({"status": "sealed", "chunks": records.len(), "input_bytes": bytes.len()}))?;

    Ok(())
}

fn open(args: OpenArgs) -> Result<(), Error> {
    let OpenArgs { key, input, output } = args;

    let key = urma_workflows::archive::read_key(&key)?;
    let records = container::unpack(&storage::read_bounded(
        &input,
        urma_runtime::config::Limits::CONTAINER_BYTES,
    )?)?;
    let bytes = container::open(&key, &records)?;
    storage::write_new(&output, &bytes)?;
    print_report(
        json!({"status": "complete", "bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(&bytes))}),
    )?;

    Ok(())
}

fn prepare(args: PrepareArgs) -> Result<(), Error> {
    let PrepareArgs {
        rpc,
        wallet,
        key,
        input,
        journal,
        source,
        address,
        funding,
        allow_unconfirmed_funding,
        fee_rate,
        content_type,
    } = args;

    ensure!(
        !journal.try_exists()?,
        "journal already exists; inspect or broadcast it"
    );
    let node = rpc.node(Some(&wallet))?;
    let key = urma_workflows::archive::read_key(&key)?;
    let bytes = Zeroizing::new(storage::read_bounded(
        &input,
        urma_runtime::config::Limits::INPUT_BYTES,
    )?);
    let secret = urma_identity::keys::RecoverySecret::import(key);
    let records = urma_profiles::private::seal_file(
        &secret,
        urma_profiles::private::FileOriginal {
            bytes: &bytes,
            content_type: content_type.into(),
        },
        &mut rand::rngs::OsRng,
    )?;
    let (plan, source_report) = select_funding(
        &node,
        &rpc,
        &records,
        bytes.len(),
        FundingSelection {
            source,
            address,
            funding,
            allow_unconfirmed: allow_unconfirmed_funding,
            rate: fee_rate,
        },
    )?;
    ensure!(
        plan.network == Network::from(rpc.network).to_string(),
        "prepared network mismatch"
    );
    let details = journal::validate_plan(&plan)?;
    for report in source_report.iter() {
        let mut sidecar = journal.as_os_str().to_os_string();
        sidecar.push(".funding.json");
        storage::write_new(&PathBuf::from(sidecar), &serde_json::to_vec_pretty(report)?)?;
    }
    storage::write_new(&journal, &serde_json::to_vec_pretty(&plan)?)?;
    print_report(
        json!({"status":"prepared", "broadcast":false, "journal":journal,
                "network":plan.network, "object_id":plan.object_id, "start_height":plan.start_height,
                "input_bytes":plan.input_bytes, "chunks":plan.reveals.len(), "fee_sats":plan.fee_sats,
                "funding_source":source_report, "validation":details}),
    )?;

    Ok(())
}

fn inspect(args: InspectArgs) -> Result<(), Error> {
    let InspectArgs { journal } = args;

    print_report(journal::validate_plan(&read_plan(&journal)?)?)?;

    Ok(())
}

fn broadcast(args: BroadcastArgs) -> Result<(), Error> {
    let BroadcastArgs {
        rpc,
        wallet,
        journal,
    } = args;

    let node = rpc.node(Some(&wallet))?;
    print_report(transport::broadcast_plan(
        &node,
        &read_plan(&journal)?,
        urma_runtime::config::RevealSelection::All,
    )?)?;

    Ok(())
}

fn status(args: StatusArgs) -> Result<(), Error> {
    let StatusArgs {
        rpc,
        wallet,
        source,
        journal,
    } = args;

    let plan = read_plan(&journal)?;
    match source {
        Some(url) => print_report(Source::connect(&url, &rpc.network.into())?.status_plan(&plan)?)?,
        None => {
            let node = rpc.node(Some(
                wallet
                    .as_deref()
                    .context("--wallet is required for Core status")?,
            ))?;
            print_report(transport::status_plan(&node, &plan)?)?;
        }
    }

    Ok(())
}

fn publish(args: PublishArgs) -> Result<(), Error> {
    let PublishArgs {
        publisher,
        key,
        input,
        journal,
        content_type,
    } = args;

    ensure!(
        publisher.mine,
        "publication requires --mine (local regtest blocks)"
    );
    ensure!(!journal.try_exists()?, "journal already exists; use resume");
    let node = publisher.rpc.node(Some(&publisher.wallet))?;
    let key = urma_workflows::archive::read_key(&key)?;
    let bytes = Zeroizing::new(storage::read_bounded(
        &input,
        urma_runtime::config::Limits::INPUT_BYTES,
    )?);
    let secret = urma_identity::keys::RecoverySecret::import(key);
    let records = urma_profiles::private::seal_file(
        &secret,
        urma_profiles::private::FileOriginal {
            bytes: &bytes,
            content_type: content_type.into(),
        },
        &mut rand::rngs::OsRng,
    )?;
    let plan = transport::prepare(&node, &records, bytes.len())?;
    storage::write_new(&journal, &serde_json::to_vec_pretty(&plan)?)?;
    print_report(
        transport::publish_plan(&node, &plan, publisher.stop_after_chunks.into()).with_context(
            || {
                format!(
                    "publication interrupted; resume using {}",
                    journal.display()
                )
            },
        )?,
    )?;

    Ok(())
}

fn resume(args: ResumeArgs) -> Result<(), Error> {
    let ResumeArgs { publisher, journal } = args;

    ensure!(
        publisher.mine,
        "resuming requires --mine (local regtest blocks)"
    );
    let plan = read_plan(&journal)?;
    let node = publisher.rpc.node(Some(&publisher.wallet))?;
    print_report(transport::publish_plan(
        &node,
        &plan,
        publisher.stop_after_chunks.into(),
    )?)?;

    Ok(())
}

fn recover(args: RecoverArgs) -> Result<(), Error> {
    let RecoverArgs {
        rpc,
        source,
        key,
        start_height,
        output_dir,
    } = args;

    ensure!(
        !output_dir.try_exists()?,
        "recovery requires a new output directory"
    );
    let key = urma_workflows::archive::read_key(&key)?;
    let recovered = match source {
        Some(url) => {
            let source = Source::connect(&url, &rpc.network.into())?;
            backend::recover(
                &urma_runtime::source::ExplorerRecords {
                    source: &source,
                    start_height,
                },
                &key,
            )?
        }
        None => backend::recover(
            &transport::BitcoinRecords {
                node: &rpc.node(None)?,
                start_height,
            },
            &key,
        )?,
    };
    export_recovery(recovered, &output_dir)?;

    Ok(())
}

struct FundingSelection {
    source: Option<String>,
    address: Option<String>,
    funding: Option<PathBuf>,
    allow_unconfirmed: bool,
    rate: u64,
}
