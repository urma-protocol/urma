use crate::{config, git_progress};
use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    fmt::MakeWriter,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use urma_runtime::error::Error;

pub(crate) fn install(
    verbosity: u8,
    writer: impl for<'a> MakeWriter<'a> + Send + Sync + 'static,
) -> Result<Option<PathBuf>, Error> {
    let level = config::load()?.log_level.filter();
    match std::env::var("URMA_LOG_OUTPUT").as_deref() {
        Ok("stderr") => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(std::io::stderr)
                        .with_filter(
                            Targets::new()
                                .with_target("urma", level)
                                .with_target("urma_timer", LevelFilter::OFF)
                                .with_target("urma_ui", LevelFilter::OFF),
                        )
                        .with_filter(ProviderWarnings::default()),
                )
                .try_init()
                .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
            return Ok(None);
        }
        Ok("file") | Err(std::env::VarError::NotPresent) => {}
        _ => {
            return Err(Error::Invalid(
                "URMA_LOG_OUTPUT must be file or stderr".into(),
            ));
        }
    }
    let directory = config::log_directory()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    let (file, path) = tempfile::Builder::new()
        .prefix(&format!("urma-{}-", timestamp.as_secs()))
        .suffix(".log")
        .tempfile_in(directory)?
        .keep()
        .map_err(|cause| Error::Io(cause.error))?;
    let console_level = match verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    tracing_subscriber::registry()
        .with(
            git_progress::ProgressLayer::new(file.try_clone()?, level >= LevelFilter::INFO)
                .with_filter(Targets::new().with_target("urma_ui", LevelFilter::INFO)),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(false)
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(
                    Targets::new()
                        .with_target("urma_progress", console_level)
                        .with_target("urma_stage", LevelFilter::INFO),
                ),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Mutex::new(file))
                .with_filter(
                    Targets::new()
                        .with_target("urma", level)
                        .with_target("urma_timer", LevelFilter::OFF)
                        .with_target("urma_ui", LevelFilter::OFF),
                ),
        )
        .try_init()
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    Ok(Some(path))
}

/// Only repetitive transport warnings are limited; errors and gateway failures remain visible.
#[derive(Default)]
struct ProviderWarnings {
    last: Mutex<std::collections::HashMap<tracing::callsite::Identifier, WarningWindow>>,
}

impl ProviderWarnings {
    fn permit(&self, metadata: &tracing::Metadata<'_>, now: std::time::Instant) -> bool {
        if metadata.target() != "urma_runtime::transport"
            || *metadata.level() != tracing::Level::WARN
        {
            return true;
        }
        let Ok(mut last) = self.last.lock() else {
            return true;
        };
        let key = metadata.callsite();
        let window = last.entry(key).or_insert(WarningWindow {
            at: None,
            suppressed: 0,
        });
        let Some(suppressed) = window.admit(now) else {
            return false;
        };
        drop(last);
        if suppressed > 0 {
            eprintln!(
                "WARN urma_runtime::transport: suppressed {suppressed} repetitive warnings at {}:{} in the previous window",
                metadata.file().unwrap_or("transport"),
                metadata.line().unwrap_or(0)
            );
        }
        true
    }
}

struct WarningWindow {
    at: Option<std::time::Instant>,
    suppressed: u64,
}
impl WarningWindow {
    fn admit(&mut self, now: std::time::Instant) -> Option<u64> {
        if self
            .at
            .is_some_and(|at| now.duration_since(at) < std::time::Duration::from_secs(60))
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.at = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::layer::Filter<S> for ProviderWarnings {
    fn enabled(
        &self,
        _: &tracing::Metadata<'_>,
        _: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        true
    }
    fn callsite_enabled(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn event_enabled(
        &self,
        event: &tracing::Event<'_>,
        _: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        self.permit(event.metadata(), std::time::Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::Arc};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn warning_window_reports_suppression_and_resumes() {
        let now = std::time::Instant::now();
        let mut window = WarningWindow {
            at: None,
            suppressed: 0,
        };
        assert_eq!(window.admit(now), Some(0));
        for _ in 0..99 {
            assert_eq!(window.admit(now), None);
        }
        assert_eq!(
            window.admit(now + std::time::Duration::from_secs(60)),
            Some(99)
        );
        assert_eq!(
            window.admit(now + std::time::Duration::from_secs(120)),
            Some(0)
        );
    }

    #[test]
    fn provider_warning_limit_preserves_distinct_callsites_and_errors() {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(ProviderWarnings::default()),
        );
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..100 {
                tracing::warn!(target: "urma_runtime::transport", "provider unavailable");
            }
            tracing::warn!(target: "urma_runtime::transport", "provider stopped");
            tracing::error!(target: "urma_runtime::transport", "fatal error");
            tracing::warn!(target: "urma_gateway", "rescan failed");
        });
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.matches("provider unavailable").count(), 1);
        assert!(
            text.contains("provider stopped")
                && text.contains("fatal error")
                && text.contains("rescan failed")
        );
    }
}
