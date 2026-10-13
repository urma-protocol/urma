use crate::common_cli::publish_plan;
use crate::{
    config,
    key_cli::{VaultAccess, funding_account},
    node_cli::NodeArgs,
    wire_archive,
};
use bitcoin::{Block, BlockHash, Transaction, Txid, XOnlyPublicKey};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma_core::format::PublicRecord;
use urma_runtime::error::Error;
use urma_runtime::{node::Node, plan::PlanLimits};
use urma_wire::{Error as WireError, SyncError as WireSyncError, index::Index, reader::Reader};

#[derive(Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[arg(help = "Public post text")]
    text: String,
    #[arg(long, default_value = "wire-plan.json")]
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
    #[command(flatten)]
    access: VaultAccess,
    #[arg(long, default_value = "wire-plan.json")]
    plan: PathBuf,
    #[arg(short, long, help = "Approve the displayed exact plan and fee")]
    yes: bool,
    #[arg(long, default_value = "wire-progress.json")]
    journal: PathBuf,
}
#[derive(Args)]
pub(crate) struct IndexArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long, default_value = "wire-index.json")]
    index: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_height: u64,
    #[arg(long, default_value_t = 1000)]
    max_blocks: u64,
}
#[derive(Args)]
pub(crate) struct ReadSource {
    #[arg(long, default_value = "wire-index.json")]
    index: PathBuf,
    #[arg(
        long,
        help = "Read only the local index, even when an operator archive is configured"
    )]
    local: bool,
}
#[derive(Subcommand)]
pub(crate) enum ReadCommand {
    Feed {
        #[command(flatten)]
        source: ReadSource,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Record {
        #[command(flatten)]
        source: ReadSource,
        txid: Txid,
    },
    Identity {
        #[command(flatten)]
        source: ReadSource,
        author: XOnlyPublicKey,
    },
}

pub(crate) fn plan(args: PlanArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let funder = funding_account(&vault, node.chain())?;
    let record = PublicRecord::Post(args.text);
    let plan = urma_runtime::plan::prepare_atomic(
        &node,
        &signer,
        &funder,
        &record,
        PlanLimits {
            fee_rate: args.fee_rate,
            max_fee: args.max_fee,
            max_records: 1,
        },
    )?;
    plan.save_new(&args.output)?;
    Ok(
        json!({"status":"prepared","plan":args.output,"plan_id":plan.id()?,"author":plan.author,"total_fee":plan.total_fee,"maximum_fee":plan.maximum_fee,"records":plan.records.len(),"broadcast":false}),
    )
}
pub(crate) fn publish(args: PublishArgs) -> Result<Value, Error> {
    publish_plan(
        &args.node,
        &args.access,
        &args.plan,
        &args.journal,
        args.yes,
        "Publish public Wire text",
    )
}

pub(crate) fn index(args: IndexArgs) -> Result<Value, Error> {
    let reader = NodeReader(args.node.connect()?);
    let (report, _index) = wire_sync_result(urma_wire::index::sync(
        &reader,
        &args.index,
        args.start_height,
        args.max_blocks,
        |height, tip| tracing::debug!(height, tip, "block indexed"),
    ))?;
    Ok(serde_json::to_value(report)?)
}
/// The operator archive first when configured (unless `--local`), labelled
/// with its coverage; any failure warns and falls back to the local index.
fn open_index(source: &ReadSource) -> Result<(Index, Value), Error> {
    if !source.local {
        if let Some(view) = operator_index() {
            return Ok(view);
        }
    }
    let index = wire_result(Index::load(&source.index))?;
    Ok((index, wire_archive::autonomous_source()))
}

/// The operator archive's view, or nothing: an unreadable configuration, a
/// network mismatch or an unavailable archive all leave the local index.
fn operator_index() -> Option<(Index, Value)> {
    let attempt = || -> Result<Option<(Index, Value)>, Error> {
        let Some(settings) = config::load()?.archive else {
            return Ok(None);
        };
        Ok(Some(wire_archive::read(
            &settings,
            config::explicit_chain()?,
        )?))
    };
    match attempt() {
        Ok(view) => view,
        Err(cause) => {
            tracing::warn!(target: "urma_cli", error = %cause,
                "optional Wire archive unavailable; reading the local index");
            None
        }
    }
}

pub(crate) fn read(command: ReadCommand) -> Result<Value, Error> {
    match command {
        ReadCommand::Feed { source, limit } => {
            let (index, source) = open_index(&source)?;
            Ok(json!({"genesis":index.genesis,
                "records":wire_result(urma_wire::view::records(&index, limit))?,
                "start_height":index.start,"source":source}))
        }
        ReadCommand::Record { source, txid } => {
            let (index, source) = open_index(&source)?;
            let mut value = wire_result(urma_wire::view::record(&index, txid))?;
            value["source"] = source;
            Ok(value)
        }
        ReadCommand::Identity { source, author } => {
            let (index, source) = open_index(&source)?;
            let mut value = wire_result(urma_wire::view::identity(&index, author))?;
            value["source"] = source;
            Ok(value)
        }
    }
}

fn wire_result<T>(result: Result<T, WireError>) -> Result<T, Error> {
    result.map_err(wire_error)
}

fn wire_error(cause: WireError) -> Error {
    match cause {
        WireError::Invalid(message) => Error::Invalid(message),
        WireError::Capacity(message) => Error::Capacity(message),
        WireError::Missing(message) => Error::Missing(message),
        WireError::Protocol(cause) => Error::Protocol(cause),
        WireError::Block(cause) => Error::from(cause),
        WireError::Io(cause) => Error::Io(cause),
        WireError::Json(cause) => Error::Json(cause),
        WireError::Hex(cause) => Error::Hex(cause),
        WireError::Integer(cause) => Error::Integer(cause),
        WireError::Hash(cause) => Error::Hash(cause),
        WireError::Secp256k1(cause) => Error::Secp256k1(cause),
        WireError::Persist(cause) => Error::Persist(cause),
        WireError::Context { message, cause } => Error::Context {
            message,
            cause: Box::new(wire_error(*cause)),
        },
    }
}

fn wire_sync_result<T>(result: Result<T, WireSyncError<Error>>) -> Result<T, Error> {
    match result {
        Ok(value) => Ok(value),
        Err(WireSyncError::Wire(cause)) => wire_result(Err(cause)),
        Err(WireSyncError::Source(cause)) => Err(cause),
    }
}

struct NodeReader(Node);
impl Reader for NodeReader {
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
    fn block(&self, height: u64) -> Result<(Block, BlockHash), Error> {
        self.0.block_at(height)
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        self.0.transaction(txid)
    }
}
