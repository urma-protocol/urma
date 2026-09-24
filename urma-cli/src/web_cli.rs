use crate::{
    approve_publication,
    config::{self, StoreChoice},
    key_cli::VaultAccess,
    node_cli::{NodeArgs, chain_name},
    print_report, progress,
};
use bitcoin::Txid;
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};
use urma_runtime::{
    disk_plan::DiskPlan,
    disk_publish,
    error::{Context, Error, bail, ensure},
    multipart::{RecoveredObject, RecoveryLimits},
    node::Node,
    plan::{PlanLimits, PublicationPlan},
    publication_progress::{Progress, Target},
    recovery, storage,
};
use urma_web::{
    config::Limits,
    error::WebError,
    pack::{PackRequest, pack_directory},
    package::{Package, PinnedEntry},
    store::{Pointer, Served, Store, StoredPublication},
};

#[derive(Subcommand)]
pub(crate) enum WebCommand {
    #[command(about = "Pack a directory into an URMAWEB1 package (offline)")]
    Pack(PackArgs),
    #[command(about = "Validate and describe a package file (offline)")]
    Inspect {
        #[arg(long)]
        package: PathBuf,
        #[arg(long, default_value_t = Limits::DEFAULT.max_package_bytes)]
        max_bytes: usize,
    },
    #[command(about = "Prepare and quote the multipart publication of a package (no broadcast)")]
    Plan(PlanArgs),
    #[command(about = "Approve and publish a prepared package")]
    Publish(PublishArgs),
    #[command(about = "Continue the same package publication after confirmation")]
    Resume(PublishArgs),
    #[command(about = "Recover a publication and its pinned objects into the verified store")]
    Fetch(FetchArgs),
    #[command(
        about = "Re-verify a stored publication's proofs and package; print the declared set"
    )]
    Manifest(LocatorArgs),
    #[command(about = "Read one declared resource from the verified store")]
    Get(GetArgs),
}

#[derive(Args)]
pub(crate) struct PackArgs {
    #[arg(long)]
    dir: PathBuf,
    #[arg(long, default_value = "index.html")]
    entry: String,
    #[arg(long, default_value = "")]
    label: String,
    #[arg(long = "mime", help = "extension=type or path=type")]
    mimes: Vec<String>,
    #[arg(
        long = "pin",
        help = "path:mime:root_txid:payload_sha256 of an already published object"
    )]
    pins: Vec<String>,
    #[arg(long, default_value_t = Limits::DEFAULT.max_file_bytes)]
    max_file_bytes: usize,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    package: PathBuf,
    #[arg(long, default_value_t = Limits::DEFAULT.max_package_bytes)]
    max_bytes: usize,
    #[arg(
        long,
        default_value = "web-plan",
        help = "New directory for the immutable signed plan (plan.json, index.bin, records.bin)"
    )]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,
    #[arg(long, default_value_t = 500_000)]
    max_fee: u64,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, default_value = "web-plan", help = "The signed plan directory")]
    plan: PathBuf,
    #[arg(short, long, help = "Approve the displayed exact plan and fee")]
    yes: bool,
    #[arg(long, default_value = "web-progress.json")]
    journal: PathBuf,
    #[arg(
        long,
        help = "Stay in the foreground, reconciling every few seconds, until every commit and reveal is confirmed"
    )]
    watch: bool,
}

#[derive(Args)]
pub(crate) struct FetchArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, help = "Root manifest reveal TXID of the publication")]
    root: Txid,
    #[arg(long, help = "Verified store; defaults to the browser's store")]
    store: Option<PathBuf>,
    #[arg(long, default_value_t = Limits::DEFAULT.max_package_bytes)]
    max_bytes: usize,
}

#[derive(Args)]
pub(crate) struct LocatorArgs {
    #[arg(long, help = "Verified store; defaults to the browser's store")]
    store: Option<PathBuf>,
    #[arg(long, help = "Chain name as stored, for example litecoin-mainnet")]
    network: String,
    #[arg(long)]
    root: Txid,
    #[arg(long, default_value_t = Limits::DEFAULT.max_package_bytes)]
    max_bytes: usize,
}

#[derive(Args)]
pub(crate) struct GetArgs {
    #[command(flatten)]
    locator: LocatorArgs,
    #[arg(long, help = "URL path inside the publication, for example /app.js")]
    path: String,
    #[arg(long)]
    output: PathBuf,
}

pub(crate) fn web_error(cause: WebError) -> Error {
    match cause {
        WebError::Protocol(cause) => Error::Protocol(cause),
        WebError::Io(cause) => Error::Io(cause),
        WebError::Files(cause) => Error::from(cause),
        WebError::Json(cause) => Error::Json(cause),
        WebError::Integer(cause) => Error::Integer(cause),
        WebError::Hex(cause) => Error::Hex(cause),
        WebError::Hash(cause) => Error::Hash(cause),
        WebError::Transaction(cause) => Error::from(cause),
        WebError::Invalid(message) => Error::Invalid(message),
        WebError::Missing(message) => Error::Missing(message),
    }
}

fn web_result<T>(result: Result<T, WebError>) -> Result<T, Error> {
    result.map_err(web_error)
}

pub(crate) fn run(command: WebCommand) -> Result<Value, Error> {
    match command {
        WebCommand::Pack(args) => pack(args),
        WebCommand::Inspect { package, max_bytes } => {
            let bytes = storage::read_bounded(&package, max_bytes)?;
            let decoded = web_result(Package::decode(&bytes))?;
            summary("valid", &decoded, &bytes, &package)
        }
        WebCommand::Plan(args) => plan(args),
        WebCommand::Publish(args) | WebCommand::Resume(args) => publish(args),
        WebCommand::Fetch(args) => fetch(args),
        WebCommand::Manifest(args) => {
            let store = web_result(Store::open(&config::web_store(StoreChoice(args.store))?))?;
            let verified = web_result(store.publication(
                &args.network,
                &args.root.to_string(),
                args.max_bytes,
            ))?;
            Ok(serde_json::to_value(web_result(store.summary(&verified))?)?)
        }
        WebCommand::Get(args) => get(args),
    }
}

fn parse_pin(rule: &str) -> Result<PinnedEntry, Error> {
    let parts: Vec<&str> = rule.splitn(4, ':').collect();
    ensure!(
        parts.len() == 4,
        "--pin expects path:mime:root_txid:payload_sha256, got {rule:?}"
    );
    Ok(PinnedEntry {
        path: parts[0].to_owned(),
        mime: parts[1].to_owned(),
        root_txid: parts[2].parse()?,
        payload_sha256: hex::decode(parts[3])?.as_slice().try_into()?,
    })
}

fn summary(status: &str, package: &Package, bytes: &[u8], path: &PathBuf) -> Result<Value, Error> {
    web_result(Limits::DEFAULT.check(package))?;
    let files: Vec<Value> = package
        .files
        .iter()
        .map(|file| {
            json!({"path": file.path, "mime": file.mime, "length": file.bytes.len(), "sha256": hex::encode(file.sha256)})
        })
        .collect();
    let pinned: Vec<Value> = package
        .pinned
        .iter()
        .map(|pin| {
            json!({"path": pin.path, "mime": pin.mime, "root_txid": pin.root_txid.to_string(), "payload_sha256": hex::encode(pin.payload_sha256)})
        })
        .collect();
    Ok(json!({
        "status": status,
        "package": path,
        "bytes": bytes.len(),
        "payload_sha256": hex::encode(Sha256::digest(bytes)),
        "profile": "URMAWEB1",
        "revision": Package::REVISION,
        "label": package.label,
        "entry": web_result(package.entry())?.path,
        "files": files,
        "pinned": pinned,
        "client_policy": "within defaults",
    }))
}

fn pack(args: PackArgs) -> Result<Value, Error> {
    let mut mimes = BTreeMap::new();
    for rule in &args.mimes {
        let Some((key, mime)) = rule.split_once('=') else {
            bail!("--mime expects extension=type or path=type, got {rule:?}");
        };
        mimes.insert(key.to_owned(), mime.to_owned());
    }
    let mut pinned = Vec::new();
    for rule in &args.pins {
        pinned.push(parse_pin(rule)?);
    }
    let package = web_result(pack_directory(PackRequest {
        root: &args.dir,
        entry: &args.entry,
        label: &args.label,
        mimes: &mimes,
        pinned,
        max_file_bytes: args.max_file_bytes,
    }))?;
    web_result(Limits::DEFAULT.check(&package))?;
    let bytes = web_result(package.encode())?;
    storage::write_new(&args.output, &bytes)?;
    summary("packed", &package, &bytes, &args.output)
}

fn plan(args: PlanArgs) -> Result<Value, Error> {
    let payload = storage::read_bounded(&args.package, args.max_bytes)?;
    let package = web_result(Package::decode(&payload))?;
    web_result(Limits::DEFAULT.check(&package))?;
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let mut reader = payload.as_slice();
    let plan = DiskPlan::prepare_multipart(
        &node,
        &signer,
        &mut reader,
        u64::try_from(payload.len())?,
        Package::PROFILE,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: DiskPlan::MAX_RECORDS,
        },
        &args.output,
    )?;
    Ok(json!({
        "status": "prepared",
        "plan": args.output,
        "plan_id": plan.id()?,
        "root_txid": plan.root_txid,
        "author": plan.author,
        "records": plan.record_count,
        "transactions": u64::from(plan.record_count) * 2,
        "payload_sha256": hex::encode(Sha256::digest(&payload)),
        "label": package.label,
        "files": package.files.len(),
        "pinned": package.pinned.len(),
        "total_fee": plan.total_fee,
        "maximum_fee": plan.maximum_fee,
        "broadcast": false,
    }))
}

fn read_all(object: &mut RecoveredObject, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let cap = u64::try_from(limit)?
        .checked_add(1)
        .context("limit overflow")?;
    object.by_ref().take(cap).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "recovered object exceeds the byte limit"
    );
    Ok(bytes)
}

fn publish(args: PublishArgs) -> Result<Value, Error> {
    let plan = DiskPlan::load(&args.plan)?;
    let node = args.node.connect()?;
    let id = plan.id()?;
    approve_publication("Publish web package", &id, plan.total_fee, args.yes)?;
    let mut shown = String::new();
    let mut notify = |update: &Progress| {
        let summary = update.summary();
        if summary != shown {
            shown = summary.clone();
            progress(summary);
        }
        Ok(())
    };
    let mut report = disk_publish::publish_progress(&node, &plan, &id, &args.journal, &mut notify)?;
    while args.watch && report.retryable && !report.reached(Target::Confirmed) {
        std::thread::sleep(config::web_watch_interval());
        report = disk_publish::publish_progress(&node, &plan, &id, &args.journal, &mut notify)?;
    }
    print_report(serde_json::to_value(&report.report)?)?;
    ensure!(
        report.retryable,
        "publication needs attention: {}; approved bytes and fees unchanged",
        report.report.blocked_reason
    );
    ensure!(
        report.report.complete,
        "publication in progress; resume the exact plan after the next block, or publish with --watch"
    );
    Ok(Value::Null)
}

fn fetch(args: FetchArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let store = config::web_store(StoreChoice(args.store))?;
    let summary = store_publication(&node, args.root, &store, args.max_bytes)?;
    Ok(json!({
        "status": "stored",
        "store": store,
        "publication": serde_json::to_value(summary)?,
    }))
}

pub(crate) fn store_publication(
    node: &Node,
    root: Txid,
    store: &Path,
    max_bytes: usize,
) -> Result<StoredPublication, Error> {
    let store = web_result(Store::open(store))?;
    let scratch = tempfile::tempdir_in(store.root())?;
    let limits = RecoveryLimits {
        max_payload_bytes: u64::try_from(max_bytes)?,
        max_nodes: PublicationPlan::MAX_RECORDS,
    };
    let mut object = recovery::recover(node, root, limits, scratch.path())?;
    ensure!(
        object.manifest().profile == Package::PROFILE,
        "root {root} is not an URMAWEB1 publication"
    );
    let payload = read_all(&mut object, max_bytes)?;
    let package = web_result(Package::decode(&payload))?;
    web_result(Limits::DEFAULT.check(&package))?;
    store_pins(node, &store, &package, limits, scratch.path(), max_bytes)?;
    for file in &package.files {
        web_result(store.put_object(&file.bytes))?;
    }
    web_result(store.put_object(&payload))?;
    let network = store_proofs(node, &store, root)?;
    let verified = web_result(store.publication(&network, &root.to_string(), max_bytes))?;
    ensure!(
        verified.author == object.author().to_string(),
        "stored proofs name another author than the recovery"
    );
    web_result(store.summary(&verified))
}

fn store_pins(
    node: &Node,
    store: &Store,
    package: &Package,
    limits: RecoveryLimits,
    scratch: &Path,
    max_bytes: usize,
) -> Result<(), Error> {
    for pin in &package.pinned {
        let mut pinned_object = recovery::recover(node, pin.root_txid, limits, scratch)?;
        ensure!(
            pinned_object.manifest().payload_hash == pin.payload_sha256,
            "pinned object {} carries another payload hash than the manifest pin",
            pin.root_txid
        );
        let bytes = read_all(&mut pinned_object, max_bytes)?;
        let sha256 = web_result(store.put_object(&bytes))?;
        ensure!(
            sha256 == hex::encode(pin.payload_sha256),
            "pinned object {} bytes differ from the manifest pin",
            pin.root_txid
        );
    }
    Ok(())
}

fn store_proofs(node: &Node, store: &Store, root: Txid) -> Result<String, Error> {
    let reveal = node.transaction(root)?;
    ensure!(reveal.input.len() == 1, "root reveal must spend one commit");
    let commit = node.transaction(reveal.input[0].previous_output.txid)?;
    web_result(store.put_transaction(&reveal))?;
    let commit_txid = web_result(store.put_transaction(&commit))?;
    let tip = node.tip()?;
    let network = chain_name(node.chain())?;
    web_result(store.put_pointer(&Pointer {
        format: Store::FORMAT.into(),
        network: network.clone(),
        root: root.to_string(),
        commit: commit_txid,
        tip_height: tip.0,
        tip_hash: tip.1,
    }))?;
    Ok(network)
}

fn get(args: GetArgs) -> Result<Value, Error> {
    let store = web_result(Store::open(&config::web_store(StoreChoice(
        args.locator.store,
    ))?))?;
    let verified = web_result(store.publication(
        &args.locator.network,
        &args.locator.root.to_string(),
        args.locator.max_bytes,
    ))?;
    match web_result(store.serve(&verified, &args.path))? {
        Served::Resource {
            mime,
            sha256,
            bytes,
        } => {
            storage::write_new(&args.output, &bytes)?;
            Ok(json!({
                "status": "served",
                "mime": mime,
                "sha256": sha256,
                "length": bytes.len(),
                "output": args.output,
            }))
        }
        Served::Undeclared => Err(Error::Missing(format!(
            "{} is not in the declared set of {}",
            args.path, args.locator.root
        ))),
    }
}
