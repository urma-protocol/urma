use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{
    io::Write,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use urma_runtime::publication_progress::{Progress, State, Target};

struct Terminal {
    group: MultiProgress,
    active: Mutex<ProgressBar>,
}

fn terminal() -> &'static Terminal {
    static TERMINAL: OnceLock<Terminal> = OnceLock::new();
    TERMINAL.get_or_init(|| Terminal {
        group: MultiProgress::new(),
        active: Mutex::new(ProgressBar::hidden()),
    })
}

pub(crate) fn suspend<T>(operation: impl FnOnce() -> T) -> T {
    terminal().group.suspend(operation)
}

pub(crate) struct LogWriter<W>(pub(crate) W);

impl<W: Write> Write for LogWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        suspend(|| self.0.write(bytes))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn style(template: &str) -> ProgressStyle {
    let style = match ProgressStyle::with_template(template) {
        Ok(style) => style,
        Err(cause) => panic!("invalid terminal template: {cause}"),
    };
    style.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏").progress_chars("━╸─")
}

fn spinner_style() -> ProgressStyle {
    style("{spinner:.cyan} {elapsed_precise} {wide_msg}")
}

pub(crate) struct Stage {
    bar: ProgressBar,
}

impl Stage {
    pub(crate) fn new(label: &str) -> Self {
        let bar = terminal().group.add(ProgressBar::new_spinner());
        bar.set_style(spinner_style());
        bar.set_message(label.to_owned());
        bar.enable_steady_tick(Duration::from_millis(100));
        match terminal().active.lock() {
            Ok(mut active) => *active = bar.clone(),
            Err(cause) => panic!("progress lock poisoned: {cause}"),
        }
        Self { bar }
    }

    pub(crate) fn finish(&self, label: &str) -> String {
        self.bar.finish_and_clear();
        format!(
            "· {} · {:.1}s",
            label.trim_end_matches('.'),
            self.bar.elapsed().as_secs_f32()
        )
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
        terminal().group.remove(&self.bar);
    }
}

pub(crate) fn stage_progress(phase: &str, done: u64, total: u64, counted: bool) {
    let bar = match terminal().active.lock() {
        Ok(bar) => bar,
        Err(cause) => panic!("progress lock poisoned: {cause}"),
    };
    if bar.is_finished() || bar.is_hidden() {
        return;
    }
    if counted && total > 0 {
        if bar.message() != phase || !bar.length().iter().any(|length| *length == total) {
            bar.set_style(style(
                "{spinner:.cyan} {elapsed_precise} {wide_msg}\n  [{wide_bar:.green.bold/white.dim}] {pos}/{len}",
            ));
        }
        bar.update(|state| {
            state.set_len(total);
            state.set_pos(done);
        });
    } else {
        bar.set_style(spinner_style());
    }
    if bar.message() != phase {
        bar.set_message(phase.to_owned());
    }
}

pub(crate) struct Publication {
    network: ProgressBar,
    confirmed: ProgressBar,
    counts: ProgressBar,
    waiting: ProgressBar,
}

impl Publication {
    pub(crate) fn new() -> Self {
        let group = &terminal().group;
        let network = group.add(ProgressBar::new_spinner());
        let confirmed = group.add(ProgressBar::new_spinner());
        let counts = group.add(ProgressBar::new_spinner());
        let waiting = group.add(ProgressBar::new_spinner());
        network.set_style(style("{prefix:9} {wide_msg}"));
        network.set_prefix("Network");
        network.set_message("checking transactions…");
        confirmed.set_style(style("{prefix:9} {wide_msg}"));
        confirmed.set_prefix("Confirmed");
        confirmed.set_message("checking transactions…");
        counts.set_style(style("  {wide_msg}"));
        waiting.set_style(style(
            "{spinner:.cyan} {elapsed_precise} {prefix}\n  {wide_msg}",
        ));
        waiting.set_prefix("Publication");
        waiting.set_message("Observing publication…");
        waiting.enable_steady_tick(Duration::from_millis(100));
        Self {
            network,
            confirmed,
            counts,
            waiting,
        }
    }

    pub(crate) fn update(
        &self,
        report: &Progress,
        target: Target,
    ) -> Result<(), urma_runtime::error::Error> {
        let count = |state| {
            report
                .observations
                .iter()
                .filter(|row| row.state == state)
                .count()
        };
        let confirmed = count(State::Confirmed);
        let mempool = count(State::Mempool);
        for (bar, position) in [
            (&self.network, confirmed + mempool),
            (&self.confirmed, confirmed),
        ] {
            let total = u64::try_from(report.total)?;
            let position = u64::try_from(position)?;
            if !bar.length().iter().any(|length| *length == total) {
                bar.set_style(style(
                    "{prefix:9} [{wide_bar:.green.bold/white.dim}] {pos}/{len}",
                ));
            }
            bar.update(|state| {
                state.set_len(total);
                state.set_pos(position);
            });
        }
        let unavailable = report
            .observations
            .iter()
            .filter(|row| matches!(row.state, State::SourceUnavailable { .. }))
            .count();
        let mut counts = Vec::new();
        for (number, label) in [
            (count(State::Missing), "missing"),
            (unavailable, "unavailable"),
            (count(State::Prepared), "prepared"),
            (mempool, "mempool"),
        ] {
            if number > 0 {
                counts.push(format!("{number} {label}"));
            }
        }
        counts.push(format!(
            "{}/{} checked",
            report.observations.len(),
            report.total
        ));
        self.counts.set_message(counts.join(" · "));
        let target = match target {
            Target::Confirmed => "confirmed",
            Target::Mempool => "mempool",
        };
        let reason = if report.report.blocked_reason.is_empty() {
            "checking transactions"
        } else {
            &report.report.blocked_reason
        };
        self.waiting.set_prefix(format!("Target {target}"));
        self.waiting.set_message(reason.to_owned());
        Ok(())
    }

    pub(crate) fn clear(&self) {
        for bar in [&self.network, &self.confirmed, &self.counts, &self.waiting] {
            bar.finish_and_clear();
        }
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        self.clear();
        for bar in [&self.network, &self.confirmed, &self.counts, &self.waiting] {
            terminal().group.remove(bar);
        }
    }
}

pub(crate) fn accepted(answer: &str) -> bool {
    matches!(answer.trim(), "y" | "Y" | "yes")
}

pub(crate) fn confirm(term: &dialoguer::console::Term) -> Result<bool, dialoguer::Error> {
    let theme = dialoguer::theme::ColorfulTheme {
        prompt_suffix: console::style("›".to_owned()).for_stderr().cyan(),
        ..Default::default()
    };
    let answer: String = dialoguer::Input::with_theme(&theme)
        .with_prompt("Publish this exact plan? [y/N]")
        .allow_empty(true)
        .report(false)
        .interact_on(term)?;
    Ok(accepted(&answer))
}
