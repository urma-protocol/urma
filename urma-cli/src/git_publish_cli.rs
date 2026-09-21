use crate::funding_cli::{amount, currency};
use crate::{
    approve_publication, config, detail, funding_cli, git_follow_cli, key_cli::VaultAccess,
    node_cli::NodeArgs, progress,
};
use clap::Args;
use serde_json::Value;
use std::path::PathBuf;
use urma_git::{plans::GitPlan, review, workflows};
use urma_runtime::error::{Error, ensure};
use urma_runtime::{node::Node, plan::PlanLimits, quote};

#[derive(Args)]
pub(crate) struct PublishArgs {
    #[arg(
        default_value = ".",
        help = "Repository whose current committed HEAD is published"
    )]
    repo: PathBuf,
    #[arg(long, help = "Publish an existing prepared and reviewed plan")]
    plan: Option<PathBuf>,
    #[arg(
        long,
        help = "Reusable plan directory [default: .urma-plan in the repository]"
    )]
    output: Option<PathBuf>,
    #[arg(long, default_value_t = 1, help = "Fee rate in base units per vbyte")]
    fee_rate: u64,
    #[arg(
        long,
        help = "Optional fee ceiling in base units; otherwise use the calculated quote"
    )]
    max_fee: Option<u64>,
    #[arg(
        short,
        long,
        help = "Approve the displayed exact price without a prompt"
    )]
    yes: bool,
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    follow: git_follow_cli::FollowArgs,
}

fn boundary(error: urma_git::error::Error) -> Error {
    Error::Io(std::io::Error::other(error))
}

fn prepare(
    args: &PublishArgs,
    directory: &std::path::Path,
) -> Result<workflows::PreparedReport, Error> {
    let guard = urma_git::workspace::lock(directory).map_err(boundary)?;
    urma_git::workspace::ensure_unpublished(directory).map_err(boundary)?;
    let limits = config::git_limits()?;
    progress("Preparing committed HEAD and scanning public content...".into());
    let name = urma_git::descriptor::source_name(&args.repo).map_err(boundary)?;
    let snapshot =
        urma_git::workspace::snapshot(&args.repo, directory, &limits, &name).map_err(boundary)?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let length = directory.join("object.bin").metadata()?.len();
    let quote = quote::multipart(length, &signer, args.fee_rate, args.node.chain()?)?;

    progress(format!("Local snapshot: {}", directory.display()));
    progress(format!(
        "Snapshot: {} tree entries, {} PACK bytes; {} records / {} transactions.",
        snapshot.inventory.entries.len(),
        snapshot.descriptor.pack_length,
        quote.records,
        u64::from(quote.records) * 2
    ));
    let ceiling =
        config::publication_fee_ceiling(config::FeeCeiling(args.max_fee), quote.maximum_fee);
    funding_cli::preview(args.node.chain()?, &quote, ceiling);
    ensure!(
        snapshot.scan.findings.is_empty(),
        "scanner found possible secrets; inspect scan.json and prepare/review explicitly before publishing"
    );
    progress("Checking identity funding and freezing exact signed transactions...".into());
    detail(
        2,
        format!(
            "Fee rate: {} base units/vB; payload: {length} bytes; identity slot selected from the active vault.",
            args.fee_rate
        ),
    );
    let node = args.node.connect()?;
    funding_cli::check(&node, &signer, &quote, ceiling)?;
    let report = workflows::prepare_snapshot(
        &node,
        &signer,
        directory,
        &limits,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: quote.maximum_fee,
            max_records: quote.records,
        },
    )
    .map_err(boundary)?;
    funding_cli::preflight(&node, directory)?;
    drop(guard);
    Ok(report)
}

fn describe(
    node: &Node,
    directory: &std::path::Path,
    report: &workflows::PreparedReport,
) -> Result<(), Error> {
    let (plan, _, publication) = GitPlan::load_with_publication(directory).map_err(boundary)?;
    ensure!(
        node.chain().genesis()? == publication.chain.genesis()?,
        "plan network differs; select the matching network before approving"
    );
    let unit = currency(node.chain());
    let funding = publication.record(0)?.funding.prevout()?.1.value.to_sat();
    progress(format!("Network: {}", node.chain().label()));
    progress(format!(
        "Public snapshot: {} / HEAD {}",
        report.snapshot.descriptor.repository_name,
        hex::encode(&report.snapshot.descriptor.head)
    ));
    progress(format!(
        "{} transactions; exact total fee: {} {unit} ({} base units).",
        report.transactions,
        amount(report.total_fee),
        report.total_fee
    ));
    progress(format!(
        "Selected funding: {} {unit}; value retained after fees: {} {unit}.",
        amount(funding),
        amount(funding - report.total_fee)
    ));
    detail(
        1,
        format!("Root: {} / author {}", plan.root_txid, plan.author),
    );
    progress(format!(
        "Plan saved in {}. Only committed HEAD is included; publication is public.",
        directory.display()
    ));
    Ok(())
}

pub(crate) fn run(args: PublishArgs) -> Result<Value, Error> {
    progress(format!(
        "Publication network: {}",
        args.node.chain()?.label()
    ));
    let (directory, report) = match &args.plan {
        Some(path) => (
            path.clone(),
            workflows::inspect_plan(path).map_err(boundary)?,
        ),
        None => {
            let directory = config::publication_directory(
                &args.repo,
                config::PublicationOutput(args.output.clone()),
            )?;
            let report = prepare(&args, &directory)?;
            (directory, report)
        }
    };
    let node = args.node.connect()?;
    describe(&node, &directory, &report)?;
    for maximum in args.max_fee.iter() {
        ensure!(
            report.total_fee <= *maximum,
            "exact fee exceeds --max-fee; nothing submitted"
        );
    }
    let reviewed = directory.join("review.json").try_exists()?;
    if reviewed {
        review::require(&directory, &report.plan_id).map_err(boundary)?;
    } else {
        ensure!(
            report.snapshot.scan.findings.is_empty(),
            "possible secrets need explicit content review before publication"
        );
    }
    approve_publication(
        "Publish this public Git snapshot",
        &report.plan_id,
        report.total_fee,
        args.yes,
    )?;
    if !reviewed {
        workflows::record_review(&directory, &[]).map_err(boundary)?;
    }
    git_follow_cli::publish(&node, &directory, &report.plan_id, &args.follow)?;
    Ok(Value::Null)
}
