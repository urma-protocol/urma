use crate::{config, git_progress, provider_warnings::ProviderWarnings};
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
    writer: impl for<'a> MakeWriter<'a> + Clone + Send + Sync + 'static,
) -> Result<Destination, Error> {
    let level = config::load()?.log_level.filter();
    match config::log_output()? {
        config::LogOutput::Console => install_stderr(writer, level),
        config::LogOutput::File => install_file(verbosity, writer, level),
    }
}

pub(crate) enum Destination {
    File(PathBuf),
    Console,
}

fn install_stderr(
    writer: impl for<'a> MakeWriter<'a> + Clone + Send + Sync + 'static,
    level: LevelFilter,
) -> Result<Destination, Error> {
    let warnings = ProviderWarnings::new(writer.clone(), config::provider_warning_window());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(
                    Targets::new()
                        .with_target("urma", level)
                        .with_target("urma_timer", LevelFilter::OFF)
                        .with_target("urma_ui", LevelFilter::OFF),
                )
                .with_filter(warnings),
        )
        .try_init()
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    Ok(Destination::Console)
}

fn install_file(
    verbosity: u8,
    writer: impl for<'a> MakeWriter<'a> + Send + Sync + 'static,
    level: LevelFilter,
) -> Result<Destination, Error> {
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
    Ok(Destination::File(path))
}
