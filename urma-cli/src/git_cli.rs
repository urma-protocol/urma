use crate::{
    approve_publication, config, detail, funding_cli, git_follow_cli, git_publish_cli, is_terminal,
    key_cli::{VaultAccess, funding_account},
    node_cli::NodeArgs,
    object_archive, progress, stage,
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use urma_git::{inventory::Limits, workflows};
use urma_runtime::error::Error;
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
    #[arg(
        long,
        help = "Scan the snapshot for possible secrets before review (default: off)"
    )]
    scan_secrets: bool,
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
        help = "Optional total fee ceiling in litoshis; otherwise use the calculated quote. Planning never broadcasts"
    )]
    max_fee: Option<u64>,
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
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    follow: git_follow_cli::FollowArgs,
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
    #[command(about = "Prepare the current repository, show its price and ask before publishing")]
    Publish(git_publish_cli::PublishArgs),
    #[command(about = "Continue the same publication after confirmation")]
    Resume(ResumeArgs),
    #[command(
        about = "Read-only observation until the target; cannot submit prepared or missing transactions"
    )]
    Watch(git_follow_cli::WatchArgs),
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
    let guard = urma_git::workspace::lock(&args.output).map_err(boundary)?;
    urma_git::workspace::ensure_unpublished(&args.output).map_err(boundary)?;
    let name = urma_git::config::publication_name(
        &args.repo,
        urma_git::config::PublicationName(args.name),
    )
    .map_err(boundary)?;
    if is_terminal() {
        progress(format!(
            "Preparing {} on {}. No broadcast.",
            console::style(&name).cyan().bold(),
            console::style(args.node.chain()?.label()).green().bold()
        ));
    } else {
        progress(format!(
            "Preparing {name} on {}. No broadcast.",
            args.node.chain()?.label()
        ));
    }
    detail(
        1,
        format!(
            "Plan directory: {}; rate: {} base units/vB.",
            args.output.display(),
            args.fee_rate
        ),
    );
    let node = stage("Connecting to the selected network...", || {
        args.node.connect()
    })?;
    let vault = stage("Unlocking the active identity...", || args.access.open())?;
    let signer = vault.keyring().active()?;
    let mut limits = args.resources.load()?;
    let funder = funding_account(&vault, node.chain())?;
    limits.scan_secrets = args.scan_secrets;
    stage("Preparing and validating the Git snapshot...", || {
        urma_git::workspace::snapshot(&args.repo, &args.output, &limits, &name)
    })
    .map_err(boundary)?;
    let length = args.output.join("object.bin").metadata()?.len();
    let quote = urma_runtime::quote::multipart(length, &signer, &funder, args.fee_rate)?;
    let ceiling =
        config::publication_fee_ceiling(config::FeeCeiling(args.max_fee), quote.maximum_fee);
    funding_cli::preview(node.chain(), &quote, ceiling);
    funding_cli::check(&node, &funder, &quote, ceiling)?;
    let report = stage("Signing and verifying the publication plan...", || {
        workflows::prepare_snapshot(
            &node,
            &signer,
            &funder,
            &args.output,
            &limits,
            PlanLimits {
                fee_rate: args.fee_rate,
                max_fee: quote.maximum_fee,
                max_records: quote.records,
            },
        )
    })
    .map_err(boundary)?;
    funding_cli::preflight(&node, &args.output)?;
    drop(guard);
    match config::output()? {
        config::Output::Json => Ok(serde_json::to_value(report)?),
        config::Output::Human => {
            progress(format!(
                "Plan ready: {} transactions; fee {} base units; no broadcast.",
                report.transactions, report.total_fee
            ));
            progress(format!(
                "Saved in {}. Review the content before publishing.",
                args.output.display()
            ));
            detail(
                1,
                format!("Plan: {}; root: {}", report.plan_id, report.root_txid),
            );
            Ok(Value::Null)
        }
    }
}

fn resume(args: ResumeArgs) -> Result<Value, Error> {
    let funder = funding_account(&args.access.open()?, args.node.chain()?)?;
    git_publish_cli::require_git_funder(&args.plan, &funder)?;
    let node = args.node.connect()?;
    let reviewed = workflows::inspect_plan(&args.plan).map_err(boundary)?;
    approve_publication(
        "Publish Git snapshot",
        &reviewed.plan_id,
        reviewed.total_fee,
        &git_publish_cli::git_spending(&args.plan)?,
        args.yes,
    )?;
    git_follow_cli::publish(&node, &args.plan, &reviewed.plan_id, &args.follow)?;
    Ok(Value::Null)
}

fn recover(args: RecoverArgs) -> Result<Value, Error> {
    let chain = args.node.chain()?;
    let root = archive_root(chain, &args.root)?;
    let limits = args.resources.load()?;
    if let Some((directory, report)) =
        archived(root, chain, &limits, urma_io::output_parent(&args.output))?
    {
        // Acquisition and all Git checks finished privately. Once publication
        // begins, an I/O error is returned; it cannot trigger another source.
        publish_recovery(directory.path(), &args.output)?;
        let mut value = serde_json::to_value(report)?;
        value["source"] = json!({"kind":"local-node-operator",
            "trust":"content and signatures verified from the local operator archive; chain inclusion not checked"});
        return Ok(value);
    }
    let node = stage("Connecting to the selected network...", || {
        args.node.connect()
    })?;
    let root = workflows::parse_root(&node, &args.root).map_err(boundary)?;
    let report = stage("Recovering content and transaction proofs...", || {
        workflows::recover(&node, root, &args.output, &limits)
    })
    .map_err(boundary)?;
    let mut value = serde_json::to_value(report)?;
    value["source"] = json!({"kind":"autonomous","evidence":node.inclusion_evidence(),
        "providers":node.provider_labels()});
    Ok(value)
}

fn archive_root(chain: urma_chain::observation::Chain, text: &str) -> Result<bitcoin::Txid, Error> {
    let txid = match text.split_once(':') {
        Some((network, txid)) if network == crate::node_cli::chain_name(chain)? => txid,
        Some(_) => return Err(Error::Invalid("locator and selected chain disagree".into())),
        None => text,
    };
    Ok(txid.parse()?)
}

fn archived(
    root: bitcoin::Txid,
    chain: urma_chain::observation::Chain,
    limits: &Limits,
    parent: &Path,
) -> Result<Option<(tempfile::TempDir, workflows::RecoveredReport)>, Error> {
    let Some(settings) = config::load()?.archive else {
        return Ok(None);
    };
    let attempt = || -> Result<_, Error> {
        let directory = object_archive::retain(
            &settings,
            chain,
            root,
            workflows::recovery_limits(limits).map_err(boundary)?,
            parent,
        )?;
        let report = workflows::recover_retained(directory.path(), limits).map_err(boundary)?;
        Ok((directory, report))
    };
    match attempt() {
        Ok(result) => {
            progress("Content and signatures verified from the local operator archive; chain inclusion not checked.".into());
            Ok(Some(result))
        }
        Err(_) => {
            tracing::warn!("optional Git archive unavailable; using autonomous recovery");
            Ok(None)
        }
    }
}

fn publish_recovery(source: &Path, destination: &Path) -> Result<(), Error> {
    // Same new-directory contract as the autonomous recover command. No
    // existing output is replaced; a final disk error can leave a partial new
    // export, but never resumes fallback into that directory.
    urma_io::create_private_directory(destination)?;
    urma_io::create_private_directory(&destination.join("tx"))?;
    for name in [
        "locator.json",
        "object.bin",
        "snapshot.pack",
        "recovery.json",
    ] {
        let path = destination.join(name);
        std::fs::copy(source.join(name), &path)?;
        std::fs::File::open(path)?.sync_all()?;
    }
    for entry in std::fs::read_dir(source.join("tx"))? {
        let entry = entry?;
        let path = destination.join("tx").join(entry.file_name());
        std::fs::copy(entry.path(), &path)?;
        std::fs::File::open(path)?.sync_all()?;
    }
    std::fs::File::open(destination.join("tx"))?.sync_all()?;
    std::fs::File::open(destination)?.sync_all()?;
    std::fs::File::open(urma_io::output_parent(destination))?.sync_all()?;
    Ok(())
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
        GitCommand::Publish(args) => git_publish_cli::run(args),
        GitCommand::Resume(args) => resume(args),
        GitCommand::Watch(args) => git_follow_cli::watch(args),
        GitCommand::Recover(args) => recover(args),
        GitCommand::Clone {
            root,
            directory,
            node,
            resources,
        } => {
            let requested = urma_git::config::CloneDestination(directory);
            let parent = urma_git::config::staging_parent(&requested).map_err(boundary)?;
            let chain = node.chain()?;
            let limits = resources.load()?;
            if let Some((staged, _)) = archived(root, chain, &limits, &parent)? {
                // Installation repeats retained-proof/Git validation and uses
                // the existing no-replace checkout. Never fallback after it.
                let (_, directory) =
                    workflows::clone_retained_named(staged.path(), requested, &limits)
                        .map_err(boundary)?;
                progress(format!("Ready in '{}'.", directory.display()));
                return Ok(Value::Null);
            }
            progress(format!("Connecting to {}...", node.chain()?.label()));
            let node = stage("Connecting to node...", || node.connect())?;
            detail(1, format!("Requested root: {root}"));
            detail(
                3,
                format!(
                    "Observation source: {}; recovery uses bounded parallel batches.",
                    node.inclusion_evidence()
                ),
            );
            let (report, directory) = stage("Receiving and verifying URMA objects...", || {
                workflows::clone_root_named(&node, root, requested, &resources.load()?)
            })
            .map_err(boundary)?;
            progress(format!("Cloning into '{}'...", directory.display()));
            progress(format!(
                "Receiving objects: {} bytes, done.",
                report.snapshot.descriptor.pack_length
            ));
            detail(
                2,
                format!(
                    "Author: {}; Git objects: {}; tree entries: {}; payload SHA256: {}",
                    report.author,
                    report.snapshot.inventory.objects.len(),
                    report.snapshot.inventory.entries.len(),
                    report.snapshot.payload_sha256
                ),
            );
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
