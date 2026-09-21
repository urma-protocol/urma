use crate::common_cli::publish_plan;
use crate::{key_cli::VaultAccess, node_cli::NodeArgs};
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
#[derive(Subcommand)]
pub(crate) enum ReadCommand {
    Feed {
        #[arg(long, default_value = "wire-index.json")]
        index: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Record {
        #[arg(long, default_value = "wire-index.json")]
        index: PathBuf,
        txid: Txid,
    },
    Identity {
        #[arg(long, default_value = "wire-index.json")]
        index: PathBuf,
        author: XOnlyPublicKey,
    },
}

pub(crate) fn plan(args: PlanArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let record = PublicRecord::Post(args.text);
    let plan = urma_runtime::plan::prepare_atomic(
        &node,
        &signer,
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
        &args.plan,
        &args.journal,
        args.yes,
        "Publish public Wire text",
    )
}

pub(crate) fn index(args: IndexArgs) -> Result<Value, Error> {
    let reader = NodeReader(args.node.connect()?);
    Ok(serde_json::to_value(wire_sync_result(
        urma_wire::index::sync(&reader, &args.index, args.start_height, args.max_blocks),
    )?)?)
}
pub(crate) fn read(command: ReadCommand) -> Result<Value, Error> {
    match command {
        ReadCommand::Feed { index, limit } => {
            let index = wire_result(Index::load(&index))?;
            Ok(
                json!({"genesis":index.genesis,"records":wire_result(urma_wire::view::records(&index, limit))?,"start_height":index.start,"locally_cached":true}),
            )
        }
        ReadCommand::Record { index, txid } => wire_result(urma_wire::view::record(
            &wire_result(Index::load(&index))?,
            txid,
        )),
        ReadCommand::Identity { index, author } => wire_result(urma_wire::view::identity(
            &wire_result(Index::load(&index))?,
            author,
        )),
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
    fn block(&self, height: u64) -> Result<Block, Error> {
        self.0.block(height)
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, Error> {
        self.0.transaction(txid)
    }
}
