#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Json(serde_json::Error),
    Source(Box<dyn std::error::Error + Send + Sync>),
    Invalid(String),
    Busy(String),
    Stale,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "archive I/O: {e}"),
            Self::Database(e) => write!(f, "archive database: {e}"),
            Self::Json(e) => write!(f, "archive encoding: {e}"),
            Self::Source(e) => write!(f, "chain source: {e}"),
            Self::Invalid(e) => f.write_str(e),
            Self::Busy(e) => write!(f, "archive busy: {e}"),
            Self::Stale => f.write_str("result belongs to a superseded chain view"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Database(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Source(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
