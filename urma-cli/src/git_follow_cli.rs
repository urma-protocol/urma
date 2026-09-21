use crate::{config, detail, node_cli::NodeArgs, progress};
use clap::{Args, ValueEnum};
use serde_json::Value;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use urma_git::workflows;
use urma_runtime::{
    error::{Error, ensure},
    node::Node,
    publication_progress::{Progress, State, Target},
};

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Completion {
    Mempool,
    Confirmed,
}

impl Completion {
    fn target(self) -> Target {
        match self {
            Self::Mempool => Target::Mempool,
            Self::Confirmed => Target::Confirmed,
        }
    }
}

#[derive(Args)]
pub(crate) struct FollowArgs {
    #[arg(
        long,
        help = "Retry mempool-full congestion at bounded intervals, using exactly the approved bytes and fees"
    )]
    pub(crate) persist: bool,
    #[arg(
        long,
        value_enum,
        default_value = "confirmed",
        help = "Completion for ALL commits and reveals; does not bypass confirmation dependencies"
    )]
    pub(crate) until: Completion,
}

#[derive(Args)]
pub(crate) struct WatchArgs {
    #[arg(long, default_value = ".urma-plan")]
    plan: PathBuf,
    #[arg(
        long,
        value_enum,
        default_value = "confirmed",
        help = "Observe until ALL transactions reach this target"
    )]
    until: Completion,
    #[command(flatten)]
    node: NodeArgs,
}

fn boundary(error: urma_git::error::Error) -> Error {
    Error::Io(std::io::Error::other(error))
}

enum Mode<'a> {
    Watch,
    Publish { approved: &'a str, persist: bool },
}

pub(crate) fn watch(args: WatchArgs) -> Result<Value, Error> {
    let node = args.node.connect()?;
    progress("Read-only watch: no wallet unlock, broadcast or plan writes. Unsubmitted transactions need publish/resume in another process.".into());
    follow(&node, &args.plan, Mode::Watch, args.until)?;
    Ok(Value::Null)
}

pub(crate) fn publish(
    node: &Node,
    directory: &Path,
    approved: &str,
    args: &FollowArgs,
) -> Result<(), Error> {
    progress("Publishing approved bytes; waiting for the selected target. Ctrl-C leaves the exact plan resumable.".into());
    follow(
        node,
        directory,
        Mode::Publish {
            approved,
            persist: args.persist,
        },
        args.until,
    )
}

fn follow(node: &Node, directory: &Path, mode: Mode<'_>, until: Completion) -> Result<(), Error> {
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = stopped.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    let mut display = Display {
        stopped,
        plan_id: String::new(),
        last: String::new(),
        seen: HashMap::new(),
        printed: Instant::now(),
    };
    loop {
        display.check()?;
        let mut notify = |report: &Progress| display.show(report, false);
        let report = match mode {
            Mode::Watch => workflows::watch(node, directory, &mut notify),
            Mode::Publish { approved, .. } => {
                workflows::publish_progress(node, directory, approved, &mut notify)
            }
        }
        .map_err(boundary)?;
        display.show(&report, true)?;
        ensure!(
            report.retryable,
            "publication needs attention: {}; fee floor above the approved rate requires intervention, never an automatic fee increase",
            report.report.blocked_reason
        );
        if report.reached(until.target()) {
            progress(format!(
                "Target {:?} reached for all {} transactions. Root: {}",
                until.target(),
                report.total,
                report.report.root_txid
            ));
            return Ok(());
        }
        if let Mode::Publish { persist: false, .. } = mode {
            ensure!(
                report.report.blocked_reason != "mempool full; approved fees unchanged",
                "mempool full; use --persist to wait/retry or resume later; approved bytes and fees unchanged"
            );
        }
        detail(
            1,
            "Checking again in 30 seconds; approved fees unchanged.".into(),
        );
        let start = Instant::now();
        while start.elapsed() < config::publication_poll_interval() {
            display.check()?;
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

struct Display {
    stopped: Arc<AtomicBool>,
    plan_id: String,
    last: String,
    seen: HashMap<String, State>,
    printed: Instant,
}

impl Display {
    fn check(&self) -> Result<(), Error> {
        ensure!(
            !self.stopped.load(Ordering::Acquire),
            "interrupted; target not reached; exact plan remains resumable"
        );
        Ok(())
    }

    fn show(&mut self, report: &Progress, final_pass: bool) -> Result<(), Error> {
        self.check()?;
        if self.plan_id.is_empty() {
            self.plan_id = report.report.plan_id.clone();
        }
        ensure!(
            self.plan_id == report.report.plan_id,
            "watched plan changed; restart explicitly for the new plan"
        );
        if !final_pass && self.printed.elapsed() < Duration::from_secs(5) {
            return Ok(());
        }
        let mut observed = report.clone();
        for row in &mut observed.observations {
            let previous = self.seen.get(&row.txid);
            if row.state == State::Prepared
                && previous.iter().any(|state| {
                    matches!(state, State::Confirmed | State::Mempool | State::Missing)
                })
            {
                row.state = State::Missing;
            }
            if !previous.iter().any(|state| **state == row.state) {
                detail(3, format!("{} {}: {:?}", row.role, row.txid, row.state));
            }
            self.seen.insert(row.txid.clone(), row.state.clone());
        }
        let summary = format!("{}; {}", observed.summary(), report.report.blocked_reason);
        if summary != self.last || config::verbosity() >= 1 {
            progress(summary.clone());
            for role in ["commit", "data", "leaf", "root"] {
                let rows = observed
                    .observations
                    .iter()
                    .filter(|row| row.role == role)
                    .collect::<Vec<_>>();
                let confirmed = rows
                    .iter()
                    .filter(|row| row.state == State::Confirmed)
                    .count();
                let mempool = rows
                    .iter()
                    .filter(|row| row.state == State::Mempool)
                    .count();
                detail(
                    2,
                    format!(
                        "{role}: {} observed, {confirmed} confirmed, {mempool} mempool",
                        rows.len()
                    ),
                );
            }
            self.last = summary;
        }
        self.printed = Instant::now();
        Ok(())
    }
}
