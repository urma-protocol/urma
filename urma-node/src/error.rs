#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Json(serde_json::Error),
    Source(Box<dyn std::error::Error + Send + Sync>),
    CommitSource(String),
    Invalid(String),
    Busy(String),
    /// A remote peer answered Busy: its capacity, not ours.
    PeerBusy,
    /// A peer request failed in transport (dial, timeout, closed connection,
    /// I/O, unsupported protocol): no statement about the peer's honesty.
    Transport(String),
    /// Our own connection admission refused a dial, before reaching the peer.
    DialDenied(DialLimit),
    Stale,
}

/// Which local admission limit refused a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialLimit {
    /// Too many connections still handshaking in that direction.
    Pending,
    /// Every established slot in that direction (or in total) is taken.
    Established,
    /// The peer already holds an established connection.
    Duplicate,
}

impl std::fmt::Display for DialLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending connection limit",
            Self::Established => "established connection limit",
            Self::Duplicate => "peer already connected",
        })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "archive I/O: {e}"),
            Self::Database(e) => write!(f, "archive database: {e}"),
            Self::Json(e) => write!(f, "archive encoding: {e}"),
            Self::Source(e) => write!(f, "chain source: {e}"),
            Self::CommitSource(e) => write!(f, "commit source: {e}"),
            Self::Invalid(e) => f.write_str(e),
            Self::Busy(e) => write!(f, "archive busy: {e}"),
            Self::PeerBusy => f.write_str("remote peer busy"),
            Self::Transport(e) => write!(f, "peer transport: {e}"),
            Self::DialDenied(limit) => write!(f, "dial denied by local connection limit ({limit})"),
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

impl From<urma_node_client::Error> for Error {
    fn from(error: urma_node_client::Error) -> Self {
        match error {
            urma_node_client::Error::Io(error) => Self::Io(error),
            urma_node_client::Error::Json(error) => Self::Json(error),
            urma_node_client::Error::Invalid(message) => Self::Invalid(message),
            urma_node_client::Error::Busy(message) => Self::Busy(message),
        }
    }
}
