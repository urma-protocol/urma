use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Capacity(String),
    Missing(String),
    Context { message: String, cause: Box<Error> },
    Protocol(urma_core::error::Error),
    Block(urma_chain::validation::BlockValidationError),
    Io(std::io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Integer(std::num::TryFromIntError),
    Hash(bitcoin::hex::HexToArrayError),
    Secp256k1(bitcoin::secp256k1::Error),
    Persist(tempfile::PersistError),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Capacity(message) | Self::Missing(message) => {
                formatter.write_str(message)
            }
            Self::Context { message, cause } => write!(formatter, "{message}: {cause}"),
            Self::Protocol(cause) => Display::fmt(cause, formatter),
            Self::Block(cause) => Display::fmt(cause, formatter),
            Self::Io(cause) => Display::fmt(cause, formatter),
            Self::Json(cause) => Display::fmt(cause, formatter),
            Self::Hex(cause) => Display::fmt(cause, formatter),
            Self::Integer(cause) => Display::fmt(cause, formatter),
            Self::Hash(cause) => Display::fmt(cause, formatter),
            Self::Secp256k1(cause) => Display::fmt(cause, formatter),
            Self::Persist(cause) => Display::fmt(cause, formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) | Self::Capacity(_) | Self::Missing(_) => None,
            Self::Context { cause, .. } => Some(cause),
            Self::Protocol(cause) => Some(cause),
            Self::Block(cause) => Some(cause),
            Self::Io(cause) => Some(cause),
            Self::Json(cause) => Some(cause),
            Self::Hex(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::Hash(cause) => Some(cause),
            Self::Secp256k1(cause) => Some(cause),
            Self::Persist(cause) => Some(cause),
        }
    }
}

#[derive(Debug)]
pub enum SyncError<E> {
    Wire(Error),
    Source(E),
}

impl<E: Display> Display for SyncError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(cause) => Display::fmt(cause, formatter),
            Self::Source(cause) => write!(formatter, "Wire source: {cause}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SyncError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(cause) => Some(cause),
            Self::Source(cause) => Some(cause),
        }
    }
}

impl<E> From<Error> for SyncError<E> {
    fn from(cause: Error) -> Self {
        Self::Wire(cause)
    }
}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for Error {
            fn from(cause: $source) -> Self {
                Self::$variant(cause)
            }
        }
    };
}

from_error!(urma_core::error::Error, Protocol);
from_error!(urma_chain::validation::BlockValidationError, Block);
from_error!(std::io::Error, Io);
from_error!(serde_json::Error, Json);
from_error!(hex::FromHexError, Hex);
from_error!(std::num::TryFromIntError, Integer);
from_error!(bitcoin::hex::HexToArrayError, Hash);
from_error!(bitcoin::secp256k1::Error, Secp256k1);
from_error!(tempfile::PersistError, Persist);

macro_rules! ensure {
    ($condition:expr, $($argument:tt)*) => {
        if !$condition {
            return Err(crate::Error::Invalid(format!($($argument)*)));
        }
    };
}

pub(crate) use ensure;

impl From<urma_io::Error> for Error {
    fn from(cause: urma_io::Error) -> Self {
        match cause {
            urma_io::Error::Io(cause) => Self::Io(cause),
            urma_io::Error::PrivatePermissions => {
                Self::Invalid("file must have private permissions".into())
            }
            urma_io::Error::Integer(cause) => Self::Integer(cause),
            urma_io::Error::LimitOverflow => Self::Capacity("file read limit overflow".into()),
            urma_io::Error::TooLarge { limit } => {
                Self::Capacity(format!("file exceeds {limit} byte Wire capacity"))
            }
            urma_io::Error::Persist(cause) => Self::Persist(cause),
            urma_io::Error::Context { message, cause } => Self::Context {
                message,
                cause: Box::new((*cause).into()),
            },
        }
    }
}
