use crate::Error;
use std::{
    fmt::Display,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// A worker failure with the Unix second it was recorded, as reported in status.
#[derive(Clone, Debug)]
pub(crate) struct RecordedError {
    pub(crate) message: String,
    pub(crate) at: u64,
}

impl RecordedError {
    pub(crate) fn now(error: impl Display) -> Self {
        let at = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs(),
            Err(_clock_before_epoch) => 0,
        };
        Self {
            message: error.to_string(),
            at,
        }
    }

    pub(crate) fn from_result<T, E: Display>(result: &Result<T, E>) -> Option<Self> {
        match result {
            Ok(_) => None,
            Err(error) => Some(Self::now(error)),
        }
    }

    pub(crate) fn split(recorded: Option<Self>) -> (Option<String>, Option<u64>) {
        match recorded {
            Some(Self { message, at }) => (Some(message), Some(at)),
            None => (None, None),
        }
    }
}

/// The current Unix second; a clock before 1970 is an error.
pub(crate) fn unix_seconds() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| Error::Invalid(format!("system clock before 1970: {error}")))
}

/// Replace the latest outcome of one worker. A poisoned slot keeps its value.
pub(crate) fn record<T>(slot: &Mutex<Option<RecordedError>>, result: &Result<T, Error>) {
    if let Ok(mut latest) = slot.lock() {
        *latest = RecordedError::from_result(result);
    }
}

pub(crate) fn read(
    slot: &Mutex<Option<RecordedError>>,
    what: &str,
) -> Result<Option<RecordedError>, Error> {
    Ok(slot
        .lock()
        .map_err(|_| Error::Invalid(format!("{what} status poisoned")))?
        .clone())
}
