use crate::{
    config::{self, IndexChoice, StoreChoice},
    key_cli::VaultAccess,
    names_cli::{load_index, plan_record, sync_index, write_record},
    names_flow::{self, Publication, names_record},
    node_cli::{NodeArgs, chain_name},
    print_report,
    web_cli::{store_publication, web_error},
};
use bitcoin::{Txid, XOnlyPublicKey};
use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use urma_core::{envelope, multipart::MultipartRecord};
use urma_names::{
    index::NamesIndex,
    name::Name,
    payload::{Approval, Mode, OwnerOp, Payload},
    state::{PendingKind, PendingRecord},
};
use urma_runtime::{
    error::{Context, Error, bail, ensure},
    node::Node,
    plan::PlanLimits,
    recovery,
};
use urma_web::{config::Limits, package::Package, store::Store};

#[derive(Args)]
pub(crate) struct Fees {
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long, default_value_t = 100_000)]
    max_fee: u64,
    #[arg(short, long, help = "Approve the displayed exact plan and fee")]
    yes: bool,
    #[arg(
        long,
        help = "Stay in the foreground until the commit and the reveal are confirmed"
    )]
    watch: bool,
}

#[derive(Args)]
pub(crate) struct RequestArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, help = "Registry genesis TXID")]
    registry: Txid,
    #[arg(long)]
    name: String,
    #[arg(long, help = "Root TXID of the published URMAWEB1 site")]
    target: Txid,
    #[arg(
        long,
        default_value = "names-request",
        help = "New directory for the record, plan and journal"
    )]
    output: PathBuf,
    #[command(flatten)]
    fees: Fees,
}

#[derive(Args)]
pub(crate) struct Pending {
    #[arg(long, help = "Registry genesis TXID")]
    registry: Txid,
    #[arg(long, help = "Reveal TXID of the pending request or update")]
    request: Txid,
    #[arg(long, help = "Names index file; defaults to the registry's local index")]
    index: Option<PathBuf>,
    #[arg(long, help = "Verified store; defaults to the browser's store")]
    store: Option<PathBuf>,
    #[arg(long, default_value_t = Limits::DEFAULT.max_package_bytes)]
    max_bytes: usize,
}

#[derive(Args)]
pub(crate) struct ReviewArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    pending: Pending,
    #[arg(
        long,
        default_value = "names-review",
        help = "New directory receiving every declared file of the requested site"
    )]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct ApproveArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[command(flatten)]
    pending: Pending,
    #[arg(
        long,
        default_value = "names-approval",
        help = "New directory for the reviewed files, the approval record, plan and journal"
    )]
    output: PathBuf,
    #[command(flatten)]
    fees: Fees,
}

struct Reviewed {
    record: PendingRecord,
    summary: Value,
}

fn limits(fees: &Fees) -> PlanLimits {
    PlanLimits {
        fee_rate: fees.fee_rate,
        max_fee: fees.max_fee,
        max_records: 1,
    }
}

fn publish_record(
    node: &Node,
    directory: &Path,
    label: &str,
    fees: &Fees,
) -> Result<Value, Error> {
    names_flow::follow(
        node,
        Publication {
            plan: &directory.join("plan.json"),
            journal: &directory.join("progress.json"),
            index: None,
            label,
            yes: fees.yes,
            watch: fees.watch,
        },
    )
}

pub(crate) fn request(args: RequestArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let root = recovery::verified_record(&node, args.target)?;
    let MultipartRecord::Root(manifest) = root.decode()? else {
        bail!("{} is not a publication root", args.target);
    };
    ensure!(
        manifest.profile == Package::PROFILE,
        "{} is not an URMAWEB1 site",
        args.target
    );
    let name = Name::normalize(&args.name)?;
    urma_io::create_private_directory(&args.output)?;
    let record = args.output.join("request.record");
    write_record(
        &Payload::Claim(OwnerOp {
            registry: args.registry,
            salt: rand::random(),
            name: name.clone(),
            target: args.target,
        }),
        &record,
    )?;
    print_report(plan_record(
        &node,
        &args.access,
        &record,
        &args.output.join("plan.json"),
        limits(&args.fees),
    )?)?;
    let label = format!("Request {name} -> {} (site by {})", args.target, root.author());
    publish_record(&node, &args.output, &label, &args.fees)
}

fn synced_index(node: &Node, pending: &Pending) -> Result<NamesIndex, Error> {
    let network = chain_name(node.chain())?;
    let path = config::names_index(
        IndexChoice {
            path: pending.index.clone(),
            registry: Some(pending.registry),
        },
        &network,
    )?;
    let report = sync_index(node, pending.registry, &path, 10_000)?;
    ensure!(
        report.complete_to_tip,
        "names index stopped at {} of {}; run names scan until it reaches the tip",
        report.height,
        report.tip
    );
    load_index(&network, &path)
}

fn verify_request(node: &Node, registry: Txid, txid: Txid, record: &PendingRecord) -> Result<(), Error> {
    let reveal = node.transaction(txid)?;
    let spent = reveal.input.first().context("request reveal without input")?;
    let commit = node.transaction(spent.previous_output.txid)?;
    let parsed = envelope::verify_reveal(&reveal, &commit)?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&parsed.record)) == record.sha256
            && parsed.author == record.author,
        "request {txid} on chain differs from the indexed record"
    );
    let (Payload::Claim(op) | Payload::Update(op)) = names_record(&parsed.record)? else {
        bail!("{txid} is not a request or an update");
    };
    ensure!(
        op.registry == registry && op.name == record.name && op.target == record.target,
        "request {txid} names another registry, name or target"
    );
    Ok(())
}

fn export_site(node: &Node, store: &Path, target: Txid, output: &Path, max_bytes: usize) -> Result<Value, Error> {
    let summary = store_publication(node, target, store, max_bytes)?;
    let opened = Store::open(store).map_err(web_error)?;
    let verified = opened
        .publication(&chain_name(node.chain())?, &target.to_string(), max_bytes)
        .map_err(web_error)?;
    let site = output.join("site");
    for file in &verified.package.files {
        write_exported(&site, &file.path, &file.bytes)?;
    }
    for pin in &verified.package.pinned {
        let bytes = opened
            .object(&hex::encode(pin.payload_sha256), Store::MAX_OBJECT_BYTES)
            .map_err(web_error)?;
        write_exported(&site, &pin.path, &bytes)?;
    }
    Ok(json!({"directory": site, "publication": serde_json::to_value(summary)?}))
}

fn write_exported(site: &Path, path: &str, bytes: &[u8]) -> Result<(), Error> {
    let target = site.join(path);
    let parent = target.parent().context("exported path without parent")?;
    std::fs::create_dir_all(parent)?;
    urma_io::write_new(&target, bytes)?;
    Ok(())
}

fn reviewed(node: &Node, pending: &Pending, output: &Path) -> Result<Reviewed, Error> {
    let index = synced_index(node, pending)?;
    let Some(record) = index.registry.pending().get(&pending.request) else {
        bail!(
            "{} is not a pending request or update of registry {}",
            pending.request,
            pending.registry
        );
    };
    ensure!(!record.completed, "{} already completed", pending.request);
    verify_request(node, pending.registry, pending.request, record)?;
    urma_io::create_private_directory(output)?;
    let store = config::web_store(StoreChoice(pending.store.clone()))?;
    let site = export_site(node, &store, record.target, output, pending.max_bytes)?;
    let rules = index.registry.rules();
    let summary = json!({
        "registry": pending.registry.to_string(),
        "mode": rules.mode,
        "threshold": rules.threshold,
        "request": pending.request.to_string(),
        "kind": record.kind,
        "name": record.name.as_str(),
        "requester": record.author.to_string(),
        "target": record.target.to_string(),
        "requested_at_height": record.height,
        "approvals": record.approvals.iter().map(XOnlyPublicKey::to_string).collect::<Vec<_>>(),
        "review": site,
        "broadcast": false,
    });
    urma_io::write_new(&output.join("review.json"), &serde_json::to_vec_pretty(&summary)?)?;
    Ok(Reviewed {
        record: record.clone(),
        summary,
    })
}

pub(crate) fn review(args: ReviewArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    Ok(reviewed(&node, &args.pending, &args.output)?.summary)
}

pub(crate) fn approve(args: ApproveArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let approver = args.access.open()?.keyring().active()?.author().0;
    let reviewed = reviewed(&node, &args.pending, &args.output)?;
    let index = synced_index(&node, &args.pending)?;
    let rules = index.registry.rules();
    ensure!(
        rules.mode == Mode::Administered && rules.is_approver(&approver),
        "the active identity {approver} is not an approver of registry {}",
        args.pending.registry
    );
    ensure!(
        !reviewed.record.approvals.contains(&approver),
        "{approver} already approved {}",
        args.pending.request
    );
    print_report(reviewed.summary)?;
    let record = args.output.join("approval.record");
    write_record(
        &Payload::Approve(Approval {
            registry: args.pending.registry,
            record_txid: args.pending.request,
            record_sha256: reviewed.record.sha256,
        }),
        &record,
    )?;
    print_report(plan_record(
        &node,
        &args.access,
        &record,
        &args.output.join("plan.json"),
        limits(&args.fees),
    )?)?;
    let action = match reviewed.record.kind {
        PendingKind::Request => "Approve name",
        PendingKind::Update => "Approve update of",
    };
    let label = format!(
        "{action} {} -> {} requested by {}; reviewed files in {}",
        reviewed.record.name,
        reviewed.record.target,
        reviewed.record.author,
        args.output.join("site").display()
    );
    publish_record(&node, &args.output, &label, &args.fees)
}
