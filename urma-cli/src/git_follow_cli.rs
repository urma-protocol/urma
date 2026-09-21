use crate::{config, detail, git_terminal, is_terminal, node_cli::NodeArgs, progress};
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
    error::Error,
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
    #[arg(long, action = clap::ArgAction::Set, default_value = "true", help = "Stay in foreground until the target; false performs one reconciliation only")]
    pub(crate) watch: bool,
    #[arg(
        long,
        help = "Retry mempool-full congestion with unchanged bytes/fees while watching; with --watch false, later attempts require resume"
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
    Publish {
        approved: &'a str,
        persist: bool,
        watch: bool,
    },
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
    progress(if args.watch {
        "Publishing approved bytes; waiting for the selected target. Ctrl-C leaves the exact plan resumable."
    } else {
        "Publishing approved bytes in one reconciliation; incomplete publication requires resume."
    }.into());
    follow(
        node,
        directory,
        Mode::Publish {
            approved,
            persist: args.persist,
            watch: args.watch,
        },
        args.until,
    )
}

fn follow(node: &Node, directory: &Path, mode: Mode<'_>, until: Completion) -> Result<(), Error> {
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = stopped.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    let mut display = Display::new(stopped, until);
    loop {
        display.check()?;
        let mut notify = |report: &Progress| display.show(report, false);
        let report = match mode {
            Mode::Watch => workflows::watch(node, directory, &mut notify),
            Mode::Publish { approved, .. } => {
                workflows::publish_progress(node, directory, approved, &mut notify)
            }
        }
        .map_err(|err| {
            display.clear();
            boundary(err)
        })?;
        match display.show(&report, true) {
            Ok(()) => {}
            Err(err) => {
                display.clear();
                return Err(err);
            }
        }
        if !report.retryable {
            display.clear();
            return Err(Error::Invalid(format!(
                "publication needs attention: {}; fee floor above the approved rate requires intervention, never an automatic fee increase",
                report.report.blocked_reason
            )));
        }
        if report.reached(until.target()) {
            display.clear();
            display.complete(&report);
            return Ok(());
        }
        if matches!(mode, Mode::Publish { persist: false, .. })
            && report.report.blocked_reason == "mempool full; approved fees unchanged"
        {
            display.clear();
            return Err(Error::Invalid(
                "mempool full; use --persist to wait/retry or resume later; approved bytes and fees unchanged".into(),
            ));
        }
        if matches!(mode, Mode::Publish { watch: false, .. }) {
            display.clear();
            progress(format!(
                "Pending/incomplete: target not reached; {}. Run git resume for another attempt; no background job is running.",
                report.report.blocked_reason
            ));
            return Ok(());
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

enum TerminalUi {
    Interactive(git_terminal::Publication),
    Plain,
}

struct Display {
    stopped: Arc<AtomicBool>,
    plan_id: String,
    last: String,
    seen: HashMap<String, State>,
    printed: Instant,
    started: Instant,
    ui: TerminalUi,
    until: Completion,
}

impl Display {
    fn new(stopped: Arc<AtomicBool>, until: Completion) -> Self {
        let ui = if is_terminal() && config::verbosity() == 0 {
            TerminalUi::Interactive(git_terminal::Publication::new())
        } else {
            TerminalUi::Plain
        };
        Self {
            stopped,
            plan_id: String::new(),
            last: String::new(),
            seen: HashMap::new(),
            printed: Instant::now(),
            started: Instant::now(),
            ui,
            until,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.stopped.load(Ordering::Acquire) {
            self.clear();
            return Err(Error::Invalid(
                "interrupted; target not reached; exact plan remains resumable".into(),
            ));
        }
        Ok(())
    }

    fn clear(&self) {
        match &self.ui {
            TerminalUi::Interactive(bar) => bar.clear(),
            TerminalUi::Plain => {}
        }
    }

    fn complete(&self, report: &Progress) {
        match self.ui {
            TerminalUi::Interactive(_) => progress(format!(
                "✓ {:?} · {} transactions · {:.1}s\n  Root: {}",
                self.until.target(),
                report.total,
                self.started.elapsed().as_secs_f32(),
                report.report.root_txid
            )),
            TerminalUi::Plain => progress(format!(
                "Target {:?} reached for all {} transactions. Root: {}",
                self.until.target(),
                report.total,
                report.report.root_txid
            )),
        }
    }

    fn update_bar(&self, observed: &Progress) -> Result<(), Error> {
        let bar = match &self.ui {
            TerminalUi::Interactive(bar) => bar,
            TerminalUi::Plain => return Ok(()),
        };
        bar.update(observed, self.until.target())
    }

    fn show(&mut self, report: &Progress, final_pass: bool) -> Result<(), Error> {
        self.check()?;
        if self.plan_id.is_empty() {
            self.plan_id = report.report.plan_id.clone();
        }
        if self.plan_id != report.report.plan_id {
            self.clear();
            return Err(Error::Invalid(
                "watched plan changed; restart explicitly for the new plan".into(),
            ));
        }
        if matches!(self.ui, TerminalUi::Plain)
            && !final_pass
            && self.printed.elapsed() < Duration::from_secs(5)
        {
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
        self.update_bar(&observed)?;
        let summary = format!("{}; {}", observed.summary(), report.report.blocked_reason);
        match &self.ui {
            TerminalUi::Interactive(_) => {}
            TerminalUi::Plain => {
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
            }
        }
        self.printed = Instant::now();
        Ok(())
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        self.clear();
    }
}
