use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Integer(std::num::TryFromIntError),
    LimitOverflow,
    PrivatePermissions,
    TooLarge { limit: usize },
    Persist(tempfile::PersistError),
    Context { message: String, cause: Box<Error> },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(cause) => Display::fmt(cause, f),
            Self::Integer(cause) => Display::fmt(cause, f),
            Self::PrivatePermissions => f.write_str("file must have private permissions"),
            Self::LimitOverflow => f.write_str("file read limit overflow"),
            Self::TooLarge { limit } => write!(f, "file exceeds {limit} byte capacity"),
            Self::Persist(cause) => Display::fmt(cause, f),
            Self::Context { message, cause } => write!(f, "{message}: {cause}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::Persist(cause) => Some(cause),
            Self::Context { cause, .. } => Some(cause),
            Self::PrivatePermissions | Self::LimitOverflow | Self::TooLarge { .. } => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(cause: std::io::Error) -> Self {
        Self::Io(cause)
    }
}
