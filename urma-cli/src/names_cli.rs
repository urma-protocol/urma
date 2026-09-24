use crate::{
    config::{self, IndexChoice},
    key_cli::VaultAccess,
    names_approval::{self, ApproveArgs, RequestArgs, ReviewArgs},
    names_flow::{self, Publication, names_error, names_record},
    node_cli::{NodeArgs, chain_name},
};
use bitcoin::{Block, BlockHash, Transaction, Txid, XOnlyPublicKey};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use urma_core::format::{PublicRecord, Urma};
use urma_names::{
    error::{NamesError, ScanError},
    index::NamesIndex,
    name::Name,
    payload::{Approval, Genesis, Mode, NameOp, OwnerOp, Payload},
    scan::{self, Registration, Source},
};
use urma_runtime::{
    error::{Error, ensure},
    node::{Node, Presence},
    plan::PlanLimits,
    storage,
};

#[derive(Subcommand)]
pub(crate) enum NamesCommand {
    #[command(about = "Scan the chain from a registry genesis into a local names index")]
    Scan(ScanArgs),
    #[command(about = "Resolve a name in the local names index of one network")]
    Resolve {
        #[command(flatten)]
        index: IndexArgs,
        name: String,
    },
    #[command(about = "List pending requests and updates with their approvals")]
    Pending {
        #[command(flatten)]
        index: IndexArgs,
    },
    #[command(about = "Request a name for a published site: encode, plan and publish")]
    Request(RequestArgs),
    #[command(
        about = "Fetch and verify a pending request's site and export every declared file (no broadcast)"
    )]
    Review(ReviewArgs),
    #[command(about = "Review a pending request or update and publish your approval")]
    Approve(ApproveArgs),
    #[command(about = "Encode a names record for publication (no broadcast)")]
    Encode {
        #[command(subcommand)]
        command: EncodeCommand,
    },
    #[command(
        about = "Prepare and quote the publication of an encoded names record (no broadcast)"
    )]
    Plan(PlanArgs),
    #[command(
        about = "Approve and publish a names record; the reveal waits for the commit's block"
    )]
    Publish(PublishArgs),
    #[command(about = "Continue the same names publication after confirmation")]
    Resume(PublishArgs),
}

#[derive(Args)]
pub(crate) struct IndexArgs {
    #[arg(
        long,
        help = "Chain name the index must belong to, for example litecoin-testnet"
    )]
    network: String,
    #[arg(long, help = "Registry genesis TXID; selects its local index")]
    registry: Option<Txid>,
    #[arg(long, help = "Explicit names index file")]
    index: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct ScanArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, help = "Registry genesis reveal TXID")]
    genesis: Txid,
    #[arg(
        long,
        help = "Height of the block that includes the genesis reveal; read from the node when omitted"
    )]
    genesis_height: Option<u64>,
    #[arg(long, help = "Names index file; defaults to the registry's local index")]
    index: Option<PathBuf>,
    #[arg(long, default_value_t = 1000)]
    max_blocks: u64,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum RegistryMode {
    Open,
    Administered,
}

#[derive(Subcommand)]
pub(crate) enum EncodeCommand {
    Genesis {
        #[arg(long, value_enum)]
        mode: RegistryMode,
        #[arg(long)]
        expiry_blocks: u32,
        #[arg(long)]
        reveal_max_blocks: u16,
        #[arg(long, default_value_t = 0)]
        threshold: u8,
        #[arg(long = "approver")]
        approvers: Vec<XOnlyPublicKey>,
        #[arg(long)]
        output: PathBuf,
    },
    Claim(OwnerArgs),
    Update(OwnerArgs),
    Renew(OwnerArgs),
    Approve {
        #[arg(long)]
        registry: Txid,
        #[arg(long, help = "Reveal TXID of the request or update being approved")]
        record_txid: Txid,
        #[arg(long, help = "The exact record file whose bytes are approved")]
        record: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Suspend(NameArgs),
    Restore(NameArgs),
}

#[derive(Args)]
pub(crate) struct OwnerArgs {
    #[arg(long)]
    registry: Txid,
    #[arg(long)]
    name: String,
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000",
        help = "Publication root TXID; all zero reserves the name (open registries only)"
    )]
    target: Txid,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct NameArgs {
    #[arg(long)]
    registry: Txid,
    #[arg(long)]
    name: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, help = "Encoded names record file")]
    record: PathBuf,
    #[arg(long, default_value = "names-plan.json")]
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
    #[arg(long, default_value = "names-plan.json")]
    plan: PathBuf,
    #[arg(short, long, help = "Approve the displayed exact plan and fee")]
    yes: bool,
    #[arg(long, default_value = "names-progress.json")]
    journal: PathBuf,
    #[arg(long, help = "Names index for the reveal window; defaults to the registry's")]
    index: Option<PathBuf>,
    #[arg(
        long,
        help = "Stay in the foreground until the commit and the reveal are confirmed"
    )]
    watch: bool,
}

struct NodeSource<'a>(&'a Node);

impl Source for NodeSource<'_> {
    type Error = Error;

    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(self.0.chain().genesis()?.0)
    }
    fn tip_height(&self) -> Result<u64, Error> {
        self.0.tip_height()
    }
    fn block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        self.0.block_hash(height)
    }
    fn block(&self, height: u64) -> Result<Block, Error> {
        self.0.block(height)
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        self.0.transaction(txid)
    }
}

pub(crate) fn run(command: NamesCommand) -> Result<Value, Error> {
    match command {
        NamesCommand::Scan(args) => scan(args),
        NamesCommand::Resolve { index, name } => resolve(index, &name),
        NamesCommand::Pending { index } => pending(index),
        NamesCommand::Request(args) => names_approval::request(args),
        NamesCommand::Review(args) => names_approval::review(args),
        NamesCommand::Approve(args) => names_approval::approve(args),
        NamesCommand::Encode { command } => encode(command),
        NamesCommand::Plan(args) => plan(args),
        NamesCommand::Publish(args) | NamesCommand::Resume(args) => publish(args),
    }
}

fn names_result<T>(result: Result<T, NamesError>) -> Result<T, Error> {
    result.map_err(names_error)
}

fn scan_result<T>(result: Result<T, ScanError<Error>>) -> Result<T, Error> {
    match result {
        Ok(value) => Ok(value),
        Err(ScanError::Source(cause)) => Err(cause),
        Err(ScanError::Names(cause)) => Err(names_error(cause)),
    }
}

pub(crate) fn confirmed_height(node: &Node, txid: Txid) -> Result<u64, Error> {
    match node.presence(txid)? {
        Presence::Confirmed { height, .. } => Ok(height),
        Presence::Mempool | Presence::Missing => Err(Error::Missing(format!(
            "{txid} has no confirmed inclusion on {}",
            node.chain().label()
        ))),
    }
}

pub(crate) fn sync_index(
    node: &Node,
    genesis: Txid,
    path: &Path,
    max_blocks: u64,
) -> Result<scan::ScanReport, Error> {
    node.require_txindex()?;
    let network = chain_name(node.chain())?;
    let genesis_height = confirmed_height(node, genesis)?;
    for parent in path.parent().iter() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    scan_result(scan::sync(
        &NodeSource(node),
        path,
        Registration {
            network: &network,
            genesis,
            genesis_height,
        },
        max_blocks,
    ))
}

fn scan(args: ScanArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let network = chain_name(node.chain())?;
    let observed = confirmed_height(&node, args.genesis)?;
    for requested in args.genesis_height.iter() {
        ensure!(
            *requested == observed,
            "genesis {} is confirmed at height {observed}, not {requested}",
            args.genesis
        );
    }
    let path = config::names_index(
        IndexChoice {
            path: args.index,
            registry: Some(args.genesis),
        },
        &network,
    )?;
    let report = sync_index(&node, args.genesis, &path, args.max_blocks)?;
    let mut value = serde_json::to_value(report)?;
    value["index"] = json!(path);
    Ok(value)
}

pub(crate) fn load_index(network: &str, path: &Path) -> Result<NamesIndex, Error> {
    let index = names_result(NamesIndex::load(path))?;
    ensure!(
        index.network == network,
        "names index {} belongs to {}, not {network}",
        path.display(),
        index.network
    );
    Ok(index)
}

fn open_index(args: IndexArgs) -> Result<NamesIndex, Error> {
    let path = config::names_index(
        IndexChoice {
            path: args.index,
            registry: args.registry,
        },
        &args.network,
    )?;
    load_index(&args.network, &path)
}

pub(crate) fn pending_records(index: &NamesIndex, name: &str) -> Result<Vec<Value>, Error> {
    let mut rows = Vec::new();
    for (txid, record) in index.registry.pending() {
        if !name.is_empty() && record.name.as_str() != name {
            continue;
        }
        rows.push(json!({"txid": txid.to_string(), "record": serde_json::to_value(record)?}));
    }
    Ok(rows)
}

fn resolve(args: IndexArgs, name: &str) -> Result<Value, Error> {
    let index = open_index(args)?;
    let name = Name::normalize(name)?;
    let resolution = index.registry.resolve(&name);
    Ok(json!({
        "network": index.network,
        "registry": index.registry.genesis().to_string(),
        "genesis_height": index.registry.genesis_height(),
        "height": index.registry.height(),
        "block_hash": index.tip_hash(),
        "name": name.as_str(),
        "resolution": serde_json::to_value(resolution)?,
        "pending": pending_records(&index, name.as_str())?,
        "locally_cached": true,
    }))
}

fn pending(args: IndexArgs) -> Result<Value, Error> {
    let index = open_index(args)?;
    Ok(json!({
        "network": index.network,
        "registry": index.registry.genesis().to_string(),
        "height": index.registry.height(),
        "pending": pending_records(&index, "")?,
    }))
}

fn owner_op(args: &OwnerArgs) -> Result<OwnerOp, Error> {
    Ok(OwnerOp {
        registry: args.registry,
        salt: rand::random(),
        name: Name::normalize(&args.name)?,
        target: args.target,
    })
}

fn name_op(args: &NameArgs) -> Result<NameOp, Error> {
    Ok(NameOp {
        registry: args.registry,
        name: Name::normalize(&args.name)?,
    })
}

fn genesis_payload(
    mode: RegistryMode,
    expiry_blocks: u32,
    reveal_max_blocks: u16,
    threshold: u8,
    mut approvers: Vec<XOnlyPublicKey>,
) -> Payload {
    approvers.sort_by_key(XOnlyPublicKey::serialize);
    let mode = match mode {
        RegistryMode::Open => Mode::Open,
        RegistryMode::Administered => Mode::Administered,
    };
    Payload::Genesis(Genesis {
        mode,
        expiry_blocks,
        reveal_max_blocks,
        threshold,
        approvers,
    })
}

fn encode(command: EncodeCommand) -> Result<Value, Error> {
    let (payload, output) = match command {
        EncodeCommand::Genesis {
            mode,
            expiry_blocks,
            reveal_max_blocks,
            threshold,
            approvers,
            output,
        } => (
            genesis_payload(mode, expiry_blocks, reveal_max_blocks, threshold, approvers),
            output,
        ),
        EncodeCommand::Claim(args) => (Payload::Claim(owner_op(&args)?), args.output),
        EncodeCommand::Update(args) => (Payload::Update(owner_op(&args)?), args.output),
        EncodeCommand::Renew(args) => (Payload::Renew(owner_op(&args)?), args.output),
        EncodeCommand::Approve {
            registry,
            record_txid,
            record,
            output,
        } => {
            let bytes = storage::read_bounded(&record, Urma::MAX_PUBLIC_BYTES)?;
            let referenced = names_record(&bytes)?;
            ensure!(
                matches!(referenced, Payload::Claim(..) | Payload::Update(..)),
                "approvals reference a request or an update record"
            );
            let approval = Approval {
                registry,
                record_txid,
                record_sha256: Sha256::digest(&bytes).into(),
            };
            (Payload::Approve(approval), output)
        }
        EncodeCommand::Suspend(args) => (Payload::Suspend(name_op(&args)?), args.output),
        EncodeCommand::Restore(args) => (Payload::Restore(name_op(&args)?), args.output),
    };
    write_record(&payload, &output)
}

pub(crate) fn write_record(payload: &Payload, output: &Path) -> Result<Value, Error> {
    let bytes = payload.to_record()?.encode()?;
    storage::write_new(output, &bytes)?;
    Ok(json!({
        "status": "encoded",
        "kind": 12,
        "profile": "URMANAM1",
        "op": payload.op(),
        "bytes": bytes.len(),
        "record_sha256": hex::encode(Sha256::digest(&bytes)),
        "output": output,
    }))
}

pub(crate) fn plan_record(
    node: &Node,
    access: &VaultAccess,
    record: &Path,
    output: &Path,
    limits: PlanLimits,
) -> Result<Value, Error> {
    let bytes = storage::read_bounded(record, Urma::MAX_PUBLIC_BYTES)?;
    let payload = names_record(&bytes)?;
    let vault = access.open()?;
    let signer = vault.keyring().active()?;
    let plan =
        urma_runtime::plan::prepare_atomic(node, &signer, &PublicRecord::decode(&bytes)?, limits)?;
    plan.save_new(output)?;
    Ok(json!({
        "status": "prepared",
        "plan": output,
        "plan_id": plan.id()?,
        "author": plan.author,
        "op": payload.op(),
        "record_sha256": hex::encode(Sha256::digest(&bytes)),
        "total_fee": plan.total_fee,
        "maximum_fee": plan.maximum_fee,
        "broadcast": false,
    }))
}

fn plan(args: PlanArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    plan_record(
        &node,
        &args.access,
        &args.record,
        &args.output,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: 1,
        },
    )
}

fn publish(args: PublishArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    names_flow::follow(
        &node,
        Publication {
            plan: &args.plan,
            journal: &args.journal,
            index: args.index,
            label: "Publish names record",
            yes: args.yes,
            watch: args.watch,
        },
    )
}
