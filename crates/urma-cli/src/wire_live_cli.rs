use crate::{key_cli::VaultAccess, node_cli::NodeArgs, print_json};
use bitcoin::{Block, BlockHash, Transaction, Txid, XOnlyPublicKey};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;
use urma::error::Error;
use urma_core::format::{PublicRecord, Urma};
use urma_runtime::{
    node::Node,
    plan::{PlanLimits, PublicationPlan},
};
use urma_wire::{index::Index, reader::Reader};

#[derive(Args)]
pub(crate) struct PlanArgs {
    #[command(flatten)]
    access: VaultAccess,
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    record: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    fee_rate: u64,
    #[arg(long)]
    max_fee: u64,
}
#[derive(Args)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    approve: String,
    #[arg(long)]
    journal: PathBuf,
}
#[derive(Args)]
pub(crate) struct IndexArgs {
    #[command(flatten)]
    node: NodeArgs,
    #[arg(long)]
    index: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_height: u64,
    #[arg(long, default_value_t = 1000)]
    max_blocks: u64,
}
#[derive(Subcommand)]
pub(crate) enum ReadCommand {
    Feed {
        #[arg(long)]
        index: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Record {
        #[arg(long)]
        index: PathBuf,
        txid: Txid,
    },
    Identity {
        #[arg(long)]
        index: PathBuf,
        author: XOnlyPublicKey,
    },
}

pub(crate) fn plan(args: PlanArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    let vault = args.access.open()?;
    let signer = vault.keyring().active()?;
    let record = PublicRecord::decode(&urma::storage::read_bounded(
        &args.record,
        Urma::MAX_PUBLIC_BYTES,
    )?)?;
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
    urma_runtime::publish::ensure_journal_distinct(&args.plan, &args.journal)?;
    let plan = PublicationPlan::load(&args.plan)?;
    let node = args.node.connect()?;
    let report = urma_runtime::publish::publish(&node, &plan, &args.approve, &args.journal)?;
    print_json(serde_json::to_value(&report)?)?;
    urma::error::ensure!(
        report.complete,
        "publication paused; inspect report and resume exact plan"
    );
    Ok(Value::Null)
}
pub(crate) fn index(args: IndexArgs) -> Result<Value, Error> {
    let reader = NodeReader(args.node.connect()?);
    Ok(serde_json::to_value(urma_wire::index::sync(
        &reader,
        &args.index,
        args.start_height,
        args.max_blocks,
    )?)?)
}
pub(crate) fn read(command: ReadCommand) -> Result<Value, Error> {
    match command {
        ReadCommand::Feed { index, limit } => {
            let index = Index::load(&index)?;
            Ok(
                json!({"genesis":index.genesis,"records":urma_wire::view::records(&index, limit)?,"start_height":index.start,"locally_cached":true}),
            )
        }
        ReadCommand::Record { index, txid } => urma_wire::view::record(&Index::load(&index)?, txid),
        ReadCommand::Identity { index, author } => {
            urma_wire::view::identity(&Index::load(&index)?, author)
        }
    }
}

struct NodeReader(Node);
impl Reader for NodeReader {
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
