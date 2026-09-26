use std::{
    collections::HashMap,
    io::Write,
    num::Saturating,
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::{Event, Metadata, Subscriber, callsite::Identifier, subscriber::Interest};
use tracing_subscriber::{
    fmt::MakeWriter,
    layer::{Context, Filter},
};

pub(crate) struct ProviderWarnings<W> {
    last: Mutex<HashMap<Identifier, WarningWindow>>,
    writer: W,
    interval: Duration,
}

impl<W: for<'a> MakeWriter<'a>> ProviderWarnings<W> {
    pub(crate) fn new(writer: W, interval: Duration) -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
            writer,
            interval,
        }
    }

    fn permit(&self, metadata: &Metadata<'_>, now: Instant) -> bool {
        if metadata.target() != "urma_runtime::transport"
            || *metadata.level() != tracing::Level::WARN
        {
            return true;
        }
        let mut last = match self.last.lock() {
            Ok(last) => last,
            Err(cause) => panic!("provider warning state lock poisoned: {cause}"),
        };
        let window = last
            .entry(metadata.callsite())
            .or_insert(WarningWindow::Fresh);
        let decision = window.admit(now, self.interval);
        drop(last);
        match decision {
            Admission::Suppress => false,
            Admission::Permit(count) => {
                if count > 0 {
                    match writeln!(
                        self.writer.make_writer(),
                        "WARN urma_runtime::transport: suppressed {count} repetitive warnings at {:?}:{:?} in the previous window",
                        metadata.file(),
                        metadata.line()
                    ) {
                        Ok(()) => {}
                        Err(cause) => panic!("cannot write provider suppression summary: {cause}"),
                    }
                }
                true
            }
        }
    }
}

enum Admission {
    Suppress,
    Permit(u64),
}

enum WarningWindow {
    Fresh,
    Active {
        at: Instant,
        suppressed: Saturating<u64>,
    },
}
impl WarningWindow {
    fn admit(&mut self, now: Instant, interval: Duration) -> Admission {
        match self {
            Self::Fresh => {
                *self = Self::Active {
                    at: now,
                    suppressed: Saturating(0),
                };
                Admission::Permit(0)
            }
            Self::Active { at, suppressed } => {
                if now.duration_since(*at) < interval {
                    *suppressed += Saturating(1);
                    Admission::Suppress
                } else {
                    *at = now;
                    Admission::Permit(std::mem::take(suppressed).0)
                }
            }
        }
    }
}

impl<S: Subscriber, W: for<'a> MakeWriter<'a>> Filter<S> for ProviderWarnings<W> {
    fn enabled(&self, _metadata: &Metadata<'_>, _context: &Context<'_, S>) -> bool {
        true
    }
    fn callsite_enabled(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }
    fn event_enabled(&self, event: &Event<'_>, _context: &Context<'_, S>) -> bool {
        self.permit(event.metadata(), Instant::now())
    }
}
