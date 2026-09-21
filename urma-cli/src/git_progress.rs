use crate::git_terminal;
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

pub(crate) struct ProgressLayer;

impl<S: Subscriber> Layer<S> for ProgressLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut update = Update::default();
        event.record(&mut update);
        if !update.phase.is_empty() {
            git_terminal::stage_progress(&update.phase, update.done, update.total, update.counted);
        }
    }
}
