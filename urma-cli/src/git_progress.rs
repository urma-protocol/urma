use crate::git_terminal;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Default)]
struct Update {
    phase: String,
    done: u64,
    total: u64,
    counted: bool,
}

impl Visit for Update {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "phase" {
            self.phase = value.to_owned();
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "done" => self.done = value,
            "total" => {
                self.total = value;
                self.counted = true;
            }
            _ => {}
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

struct LoggedProgress {
    phase: String,
    at: Instant,
}

pub(crate) struct ProgressLayer {
    logged: Mutex<LoggedProgress>,
}

impl Default for ProgressLayer {
    fn default() -> Self {
        Self {
            logged: Mutex::new(LoggedProgress {
                phase: String::new(),
                at: Instant::now(),
            }),
        }
    }
}

impl<S: Subscriber> Layer<S> for ProgressLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut update = Update::default();
        event.record(&mut update);
        if !update.phase.is_empty() {
            git_terminal::stage_progress(&update.phase, update.done, update.total, update.counted);
            let mut logged = match self.logged.lock() {
                Ok(logged) => logged,
                Err(cause) => panic!("progress log lock poisoned: {cause}"),
            };
            if logged.phase != update.phase
                || (update.counted && update.done == update.total)
                || logged.at.elapsed() >= Duration::from_secs(5)
            {
                tracing::info!(target: "urma_activity", phase = %update.phase, done = update.done, total = update.total, counted = update.counted, "Progress");
                logged.phase = update.phase;
                logged.at = Instant::now();
            }
        }
    }
}
