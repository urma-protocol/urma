use crate::git_terminal;
use std::{
    fs::File,
    io::Write,
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    Layer,
    fmt::{
        format::Writer,
        time::{FormatTime, SystemTime},
    },
    layer::Context,
};

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
    file: File,
    phase: String,
    at: Instant,
}

pub(crate) struct ProgressLayer {
    logged: Mutex<LoggedProgress>,
    enabled: bool,
}

impl ProgressLayer {
    pub(crate) fn new(file: File, enabled: bool) -> Self {
        Self {
            logged: Mutex::new(LoggedProgress {
                file,
                phase: String::new(),
                at: Instant::now(),
            }),
            enabled,
        }
    }
}

impl LoggedProgress {
    fn record(&mut self, update: &Update) {
        let mut timestamp = String::new();
        match SystemTime.format_time(&mut Writer::new(&mut timestamp)) {
            Ok(()) => (),
            Err(cause) => panic!("cannot format progress timestamp: {cause}"),
        }
        let line = format!(
            "{timestamp} INFO urma_activity: Progress phase={:?} done={} total={} counted={}\n",
            update.phase, update.done, update.total, update.counted
        );
        match self.file.write_all(line.as_bytes()) {
            Ok(()) => (),
            Err(cause) => panic!("cannot write progress log: {cause}"),
        }
    }
}

impl<S: Subscriber> Layer<S> for ProgressLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut update = Update::default();
        event.record(&mut update);
        if !update.phase.is_empty() {
            git_terminal::stage_progress(&update.phase, update.done, update.total, update.counted);
            if !self.enabled {
                return;
            }
            let mut logged = match self.logged.lock() {
                Ok(logged) => logged,
                Err(cause) => panic!("progress log lock poisoned: {cause}"),
            };
            if logged.phase != update.phase
                || (update.counted && update.done == update.total)
                || logged.at.elapsed() >= Duration::from_secs(5)
            {
                logged.record(&update);
                logged.phase = update.phase;
                logged.at = Instant::now();
            }
        }
    }
}
