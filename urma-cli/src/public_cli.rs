use crate::key_cli::VaultAccess;
use crate::wire_live_cli;
use bitcoin::{Txid, consensus::deserialize};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::num::NonZeroU64;
use std::path::PathBuf;
use urma_chain::observation::Chain;
use urma_core::format::{PublicRecord, Urma};
use urma_runtime::error::{Context, Error, bail};
use urma_runtime::storage;
use urma_wallet::wallet::{FeeBudget, FeeRate};

#[derive(Clone, Copy, ValueEnum)]
pub enum PublicKind {
    Post,
    Reply,
    Profile,
    Avatar,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PublicChain {
    BitcoinRegtest,
    BitcoinTestnet4,
    LitecoinMainnet,
    LitecoinTestnet,
}

impl From<PublicChain> for Chain {
    fn from(chain: PublicChain) -> Self {
        match chain {
            PublicChain::BitcoinRegtest => Self::BitcoinRegtest,
            PublicChain::BitcoinTestnet4 => Self::BitcoinTestnet4,
            PublicChain::LitecoinMainnet => Self::LitecoinMainnet,
            PublicChain::LitecoinTestnet => Self::LitecoinTestnet,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum PublicCommand {
    #[command(about = "Sync your local confirmed feed and reconcile reorgs")]
    Index(wire_live_cli::IndexArgs),
    #[command(about = "Prepare and quote an atomic public post (no broadcast)")]
    Plan(wire_live_cli::PlanArgs),
    #[command(about = "Approve and publish the prepared post")]
    Publish(wire_live_cli::PublishArgs),
    #[command(about = "Continue the same post publication after confirmation")]
    Resume(wire_live_cli::PublishArgs),
    #[command(about = "Read verified records from your local index")]
    Read {
        #[command(subcommand)]
        command: wire_live_cli::ReadCommand,
    },
    #[command(about = "Low-level atomic record encoding and offline signing")]
    Expert {
        #[command(subcommand)]
        command: PublicTools,
    },
}

#[derive(Subcommand)]
pub(crate) enum PublicTools {
    Encode {
        #[arg(long, value_enum)]
        kind: PublicKind,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        reply_to: Option<Txid>,
    },
    Prepare {
        #[arg(long)]
        record: PathBuf,
        #[command(flatten)]
        access: VaultAccess,
        #[arg(long)]
        max_fee: u64,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long, value_enum)]
        chain: PublicChain,
        #[arg(long)]
        fee_rate: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        commit: PathBuf,
        #[arg(long)]
        reveal: PathBuf,
    },
}

fn encode(
    kind: PublicKind,
    input: PathBuf,
    output: PathBuf,
    target: Option<Txid>,
) -> Result<Value, Error> {
    let bytes = storage::read_bounded(&input, Urma::MAX_PUBLIC_BYTES)?;
    let record = match kind {
        PublicKind::Reply => PublicRecord::Reply {
            target: target.context("reply requires --reply-to")?,
            text: String::from_utf8(bytes)?,
        },
        other => {
            reject_target(target)?;
            match other {
                PublicKind::Post => PublicRecord::Post(String::from_utf8(bytes)?),
                PublicKind::Profile => PublicRecord::Profile(String::from_utf8(bytes)?),
                PublicKind::Avatar => PublicRecord::Avatar(Box::new(bytes.as_slice().try_into()?)),
                PublicKind::Reply => bail!("reply target was not handled"),
            }
        }
    };
    let bytes = record.encode()?;
    storage::write_new(&output, &bytes)?;
    Ok(
        json!({"status":"encoded","version":Urma::VERSION,"kind":record.kind().byte(),"bytes":bytes.len()}),
    )
}

pub(crate) fn run(command: PublicCommand) -> Result<Value, Error> {
    match command {
        PublicCommand::Index(args) => wire_live_cli::index(args),
        PublicCommand::Plan(args) => wire_live_cli::plan(args),
        PublicCommand::Publish(args) | PublicCommand::Resume(args) => wire_live_cli::publish(args),
        PublicCommand::Read { command } => wire_live_cli::read(command),
        PublicCommand::Expert { command } => tools(command),
    }
}

fn tools(command: PublicTools) -> Result<Value, Error> {
    match command {
        PublicTools::Encode {
            kind,
            input,
            output,
            reply_to,
        } => encode(kind, input, output, reply_to),
        PublicTools::Prepare {
            record,
            access,
            max_fee,
            funding,
            chain,
            fee_rate,
            output,
        } => {
            let record =
                PublicRecord::decode(&storage::read_bounded(&record, Urma::MAX_PUBLIC_BYTES)?)?;
            let vault = access.open()?;
            let signer = vault.keyring().active()?;
            let funding = serde_json::from_slice(&storage::read_bounded(&funding, 1_000_000)?)?;
            let chain: Chain = chain.into();
            let budget = FeeBudget {
                chain: chain.genesis()?,
                rate: FeeRate(NonZeroU64::new(fee_rate).context("fee rate must be positive")?),
                maximum_base_units: max_fee,
            };
            let plan = urma_runtime::publication::prepare_signed_bytes(
                &record.encode()?,
                &signer,
                funding,
                chain,
                budget,
            )?
            .plan;
            storage::write_new(&output, &serde_json::to_vec_pretty(&plan)?)?;
            Ok(json!({"status":"prepared","commit_signed":true,"broadcast":false,"plan":plan}))
        }
        PublicTools::Verify { commit, reveal } => {
            let commit = hex::decode(
                std::str::from_utf8(&storage::read_bounded(&commit, 8_000_000)?)?.trim(),
            )?;
            let reveal = hex::decode(
                std::str::from_utf8(&storage::read_bounded(&reveal, 8_000_000)?)?.trim(),
            )?;
            let verified = urma_profiles::wire::verify_bytes(&commit, &reveal)?;
            let transaction: bitcoin::Transaction = deserialize(&reveal)?;
            Ok(
                json!({"status":"valid","author":verified.author().0.to_string(),"txid":transaction.compute_txid().to_string(),
                "kind":verified.record().kind().byte(),"record_hex":hex::encode(verified.raw_record()),"chain_inclusion_checked":false}),
            )
        }
    }
}

fn reject_target(target: Option<Txid>) -> Result<(), Error> {
    let Some(txid) = target else {
        return Ok(());
    };
    bail!("target {txid} requires reply kind")
}
