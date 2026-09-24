#[path = "../src/git_progress.rs"]
mod git_progress;
#[path = "../src/git_terminal.rs"]
mod git_terminal;

use std::{io::Write, process::Command, time::Duration};
use tracing_subscriber::{Layer, layer::SubscriberExt};
use urma_runtime::{
    publication_progress::{Observation, Progress, State, Target},
    publish::PublishReport,
};

#[test]
fn confirmation_keeps_exact_line_response_contract() {
    for answer in ["y", "Y", "yes", " yes \n", "\tY\r\n"] {
        assert!(git_terminal::accepted(answer), "{answer:?}");
    }
    for answer in ["", "n", "N", "YES", "Yes", "yesterday", "true", "1"] {
        assert!(!git_terminal::accepted(answer), "{answer:?}");
    }
}

fn report(states: &[State]) -> Progress {
    Progress {
        total: 6,
        retryable: true,
        report: PublishReport {
            plan_id: "offline-fixture".into(),
            root_txid: "fixture-root".into(),
            complete: false,
            confirmed: false,
            blocked_reason: "waiting for confirmations; approved fees unchanged".into(),
            transactions: Vec::new(),
        },
        observations: states
            .iter()
            .enumerate()
            .map(|(index, state)| Observation {
                txid: index.to_string(),
                role: "data".into(),
                state: state.clone(),
            })
            .collect(),
    }
}

#[test]
#[ignore = "offline visual fixture; driven in a PTY by git_ui_demo.py"]
fn ui_fixture() {
    if std::env::var("URMA_UI_FIXTURE").as_deref() == Ok("confirm") {
        let accepted = git_terminal::confirm(&console::Term::stderr()).unwrap();
        eprintln!("accepted={accepted}");
        return;
    }
    let subscriber = tracing_subscriber::registry().with(
        git_progress::ProgressLayer::new(tempfile::tempfile().unwrap(), true).with_filter(
            tracing_subscriber::filter::Targets::new().with_target("urma_ui", tracing::Level::INFO),
        ),
    );
    tracing::subscriber::with_default(subscriber, || {
        let stage = git_terminal::Stage::new("Preparing offline fixture");
        for done in [0u64, 2, 4] {
            tracing::info!(target: "urma_ui", phase = "Signing records", done, total = 4u64);
            std::thread::sleep(Duration::from_millis(140));
        }
        tracing::info!(target: "urma_ui", phase = "Verifying signed bytes");
        std::thread::sleep(Duration::from_millis(140));
        eprintln!("{}", stage.finish("Prepared fixture"));
    });
    let ui = git_terminal::Publication::new();
    let mempool = report(&vec![State::Mempool; 6]);
    assert!(mempool.reached(Target::Mempool));
    assert!(!mempool.reached(Target::Confirmed));
    ui.update(&mempool, Target::Confirmed).unwrap();
    std::thread::sleep(Duration::from_millis(160));
    let mut log = git_terminal::LogWriter(std::io::stderr());
    writeln!(log, "Fixture log: still awaiting confirmation").unwrap();
    log.flush().unwrap();
    let mut changed = report(&[
        State::Confirmed,
        State::Mempool,
        State::Missing,
        State::SourceUnavailable {
            reason: "fixture unavailable".into(),
        },
    ]);
    changed.report.blocked_reason = "source unavailable; retry pending".into();
    ui.update(&changed, Target::Confirmed).unwrap();
    std::thread::sleep(Duration::from_millis(160));
    ui.clear();
    drop(ui);
    let download = git_terminal::Stage::new("Recovering offline fixture");
    for done in [0, 256, 512] {
        git_terminal::stage_progress("Receiving payload bytes", done, 512, true);
        std::thread::sleep(Duration::from_millis(140));
    }
    git_terminal::stage_progress("Verifying complete payload digest", 0, 0, false);
    std::thread::sleep(Duration::from_millis(140));
    drop(download);
    eprintln!("Fixture stopped; no success claimed");
}

#[test]
fn pty_layout_and_confirmation_responses() {
    let result = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/git_ui_demo.py"))
        .arg(std::env::current_exe().unwrap())
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
