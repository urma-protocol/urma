use crate::funding_cli::{amount, currency};
use crate::{
    approve_publication, config, detail, funding_cli, git_follow_cli, is_terminal,
    key_cli::VaultAccess, node_cli::NodeArgs, progress, stage,
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
    #[arg(
        long,
        conflicts_with = "plan",
        help = "Scan the new snapshot for possible secrets; findings require explicit review (default: off)"
    )]
    scan_secrets: bool,
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

fn report_snapshot(
    directory: &std::path::Path,
    snapshot: &urma_git::snapshot::SnapshotReport,
    quote: &quote::Quote,
) {
    if is_terminal() {
        progress(format!(
            "{} {}",
            console::style("Local snapshot:").bold(),
            console::style(directory.display()).cyan()
        ));
        progress(format!(
            "{} {} tree entries, {} PACK bytes; {} records / {} transactions.",
            console::style("Snapshot:").bold(),
            console::style(snapshot.inventory.entries.len()).cyan(),
            console::style(snapshot.descriptor.pack_length).cyan(),
            console::style(quote.records).cyan(),
            console::style(u64::from(quote.records) * 2).cyan()
        ));
    } else {
        progress(format!("Local snapshot: {}", directory.display()));
        progress(format!(
            "Snapshot: {} tree entries, {} PACK bytes; {} records / {} transactions.",
            snapshot.inventory.entries.len(),
            snapshot.descriptor.pack_length,
            quote.records,
            u64::from(quote.records) * 2
        ));
    }
}

fn report_funding_check() {
    if is_terminal() {
        progress(format!(
            "{}",
            console::style("Checking identity funding and freezing exact signed transactions...")
                .bold()
        ));
    } else {
        progress("Checking identity funding and freezing exact signed transactions...".into());
    }
}

fn prepare(
    args: &PublishArgs,
    directory: &std::path::Path,
) -> Result<workflows::PreparedReport, Error> {
    let guard = urma_git::workspace::lock(directory).map_err(boundary)?;
    urma_git::workspace::ensure_unpublished(directory).map_err(boundary)?;
    let mut limits = config::git_limits()?;
    limits.scan_secrets = args.scan_secrets;
    let name = urma_git::descriptor::source_name(&args.repo).map_err(boundary)?;
    let snapshot = stage("Preparing and validating committed HEAD...", || {
        urma_git::workspace::snapshot(&args.repo, directory, &limits, &name)
    })
    .map_err(boundary)?;
    let vault = stage("Unlocking the active identity...", || args.access.open())?;
    let signer = vault.keyring().active()?;
    let length = directory.join("object.bin").metadata()?.len();
    let quote = quote::multipart(length, &signer, args.fee_rate, args.node.chain()?)?;
    report_snapshot(directory, &snapshot, &quote);
    let ceiling =
        config::publication_fee_ceiling(config::FeeCeiling(args.max_fee), quote.maximum_fee);
    funding_cli::preview(args.node.chain()?, &quote, ceiling);
    ensure!(
        snapshot.scan.findings.is_empty(),
        "scanner found possible secrets; inspect scan.json and prepare/review explicitly before publishing"
    );
    report_funding_check();
    detail(
        2,
        format!(
            "Fee rate: {} base units/vB; payload: {length} bytes; identity slot selected from the active vault.",
            args.fee_rate
        ),
    );
    let node = stage("Connecting to the selected network...", || {
        args.node.connect()
    })?;
    funding_cli::check(&node, &signer, &quote, ceiling)?;
    let report = stage("Signing and verifying the publication plan...", || {
        workflows::prepare_snapshot(
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
    })
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
    if is_terminal() {
        progress(format!(
            "{} {}",
            console::style("Network:").bold(),
            console::style(node.chain().label()).cyan()
        ));
        progress(format!(
            "{} {} / HEAD {}",
            console::style("Public snapshot:").bold(),
            console::style(&report.snapshot.descriptor.repository_name).bold(),
            console::style(hex::encode(&report.snapshot.descriptor.head)).cyan()
        ));
        progress(format!(
            "{} transactions; exact total fee: {} ({} base units).",
            console::style(report.transactions).cyan(),
            console::style(format!("{} {unit}", amount(report.total_fee)))
                .yellow()
                .bold(),
            console::style(report.total_fee).dim()
        ));
        progress(format!(
            "Selected funding: {}; value retained after fees: {}.",
            console::style(format!("{} {unit}", amount(funding)))
                .green()
                .bold(),
            console::style(format!("{} {unit}", amount(funding - report.total_fee))).cyan()
        ));
        progress(format!(
            "Plan saved in {}. Only committed HEAD is included; publication is public.",
            console::style(directory.display()).cyan()
        ));
    } else {
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
        progress(format!(
            "Plan saved in {}. Only committed HEAD is included; publication is public.",
            directory.display()
        ));
    }
    detail(
        1,
        format!("Root: {} / author {}", plan.root_txid, plan.author),
    );
    Ok(())
}

pub(crate) fn run(args: PublishArgs) -> Result<Value, Error> {
    if is_terminal() {
        progress(format!(
            "{} {}",
            console::style("Publication network:").bold(),
            console::style(args.node.chain()?.label()).cyan()
        ));
    } else {
        progress(format!(
            "Publication network: {}",
            args.node.chain()?.label()
        ));
    }
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
