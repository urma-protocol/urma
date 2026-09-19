use crate::files_cli::{self, IngestArgs, InspectArgs, RecoverArgs};
use clap::Subcommand;
use serde_json::Value;
use std::path::PathBuf;
use urma::error::{Error, ensure};
use urma_files::{capture::Capture, safety};

#[derive(Subcommand)]
pub(crate) enum Command {
    Ingest {
        #[command(flatten)]
        files: IngestArgs,
        #[arg(long)]
        session: PathBuf,
    },
    Inspect(InspectArgs),
    Recover(RecoverArgs),
}

pub(crate) fn run(command: Command) -> Result<Value, Error> {
    match command {
        Command::Ingest { files, session } => {
            let bytes = safety::read_regular(&session, 512 * 1024)?;
            let capture: Capture = serde_json::from_slice(&bytes)?;
            ensure!(matches!(capture, Capture::Session { .. }), "capture session required");
            files_cli::ingest_collection(files, capture)
        }
        Command::Inspect(args) => files_cli::inspect(args, "urma.capture-evidence"),
        Command::Recover(args) => files_cli::recover_collection(args, "urma.capture-evidence"),
    }
}
