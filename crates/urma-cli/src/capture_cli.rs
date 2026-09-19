use crate::files_cli::{
    self, IngestArgs, InspectArgs, PlanArgs, PublishArgs, RecoverArgs, RecoverChainArgs,
};
use clap::Subcommand;
use serde_json::Value;
use std::path::PathBuf;
use urma::error::{Error, ensure};
use urma_files::{capture::Capture, safety};

#[derive(Subcommand)]
pub(crate) enum Command {
    #[command(about = "Seal captured originals with explicit session context")]
    Ingest {
        #[command(flatten)]
        files: IngestArgs,
        #[arg(long)]
        session: PathBuf,
    },
    #[command(about = "Authenticate the captured-original catalog")]
    Inspect(InspectArgs),
    #[command(about = "Restore originals from a local encrypted capture")]
    Recover(RecoverArgs),
    #[command(about = "Quote and prepare capture publication (no broadcast)")]
    Plan(PlanArgs),
    #[command(about = "Approve and publish the prepared capture")]
    Publish(PublishArgs),
    #[command(about = "Continue the same capture publication")]
    Resume(PublishArgs),
    #[command(about = "Discover and restore captured originals from the chain")]
    RecoverChain(RecoverChainArgs),
}

pub(crate) fn run(command: Command) -> Result<Value, Error> {
    match command {
        Command::Ingest { files, session } => {
            let bytes = safety::read_regular(&session, 512 * 1024)?;
            let capture: Capture = serde_json::from_slice(&bytes)?;
            ensure!(
                matches!(capture, Capture::Session { .. }),
                "capture session required"
            );
            files_cli::ingest_collection(files, capture)
        }
        Command::Inspect(args) => files_cli::inspect(args, "urma.capture-evidence"),
        Command::Recover(args) => files_cli::recover_collection(args, "urma.capture-evidence"),
        Command::Plan(args) => files_cli::plan(args, "urma.capture-evidence"),
        Command::Publish(args) | Command::Resume(args) => files_cli::publish(args),
        Command::RecoverChain(args) => files_cli::recover_chain(args, "urma.capture-evidence"),
    }
}
