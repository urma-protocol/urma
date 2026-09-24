use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum NamesError {
    Protocol(urma_core::error::Error),
    Block(urma_chain::validation::BlockValidationError),
    Io(urma_io::Error),
    Json(serde_json::Error),
    Integer(std::num::TryFromIntError),
    Hash(bitcoin::hex::HexToArrayError),
    Invalid(String),
    Missing(String),
}

impl Display for NamesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(cause) => Display::fmt(cause, formatter),
            Self::Block(cause) => Display::fmt(cause, formatter),
            Self::Io(cause) => Display::fmt(cause, formatter),
            Self::Json(cause) => Display::fmt(cause, formatter),
            Self::Integer(cause) => Display::fmt(cause, formatter),
            Self::Hash(cause) => Display::fmt(cause, formatter),
            Self::Invalid(message) | Self::Missing(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for NamesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(cause) => Some(cause),
            Self::Block(cause) => Some(cause),
            Self::Io(cause) => Some(cause),
            Self::Json(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::Hash(cause) => Some(cause),
            Self::Invalid(..) | Self::Missing(..) => None,
        }
    }
}

impl From<urma_core::error::Error> for NamesError {
    fn from(cause: urma_core::error::Error) -> Self {
        Self::Protocol(cause)
    }
}

impl From<urma_chain::validation::BlockValidationError> for NamesError {
    fn from(cause: urma_chain::validation::BlockValidationError) -> Self {
        Self::Block(cause)
    }
}

impl From<urma_io::Error> for NamesError {
    fn from(cause: urma_io::Error) -> Self {
        Self::Io(cause)
    }
}

impl From<serde_json::Error> for NamesError {
    fn from(cause: serde_json::Error) -> Self {
        Self::Json(cause)
    }
}

impl From<std::num::TryFromIntError> for NamesError {
    fn from(cause: std::num::TryFromIntError) -> Self {
        Self::Integer(cause)
    }
}

impl From<bitcoin::hex::HexToArrayError> for NamesError {
    fn from(cause: bitcoin::hex::HexToArrayError) -> Self {
        Self::Hash(cause)
    }
}

#[derive(Debug)]
pub enum ScanError<S> {
    Source(S),
    Names(NamesError),
}

impl<S: Display> Display for ScanError<S> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(cause) => write!(formatter, "chain source: {cause}"),
            Self::Names(cause) => Display::fmt(cause, formatter),
        }
    }
}

impl<S: std::error::Error + 'static> std::error::Error for ScanError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(cause) => Some(cause),
            Self::Names(cause) => Some(cause),
        }
    }
}

impl<S> From<NamesError> for ScanError<S> {
    fn from(cause: NamesError) -> Self {
        Self::Names(cause)
    }
}

impl<S> From<urma_core::error::Error> for ScanError<S> {
    fn from(cause: urma_core::error::Error) -> Self {
        Self::Names(NamesError::Protocol(cause))
    }
}

impl<S> From<urma_chain::validation::BlockValidationError> for ScanError<S> {
    fn from(cause: urma_chain::validation::BlockValidationError) -> Self {
        Self::Names(NamesError::Block(cause))
    }
}

impl<S> From<urma_io::Error> for ScanError<S> {
    fn from(cause: urma_io::Error) -> Self {
        Self::Names(NamesError::Io(cause))
    }
}

impl<S> From<serde_json::Error> for ScanError<S> {
    fn from(cause: serde_json::Error) -> Self {
        Self::Names(NamesError::Json(cause))
    }
}

impl<S> From<std::num::TryFromIntError> for ScanError<S> {
    fn from(cause: std::num::TryFromIntError) -> Self {
        Self::Names(NamesError::Integer(cause))
    }
}

impl<S> From<bitcoin::hex::HexToArrayError> for ScanError<S> {
    fn from(cause: bitcoin::hex::HexToArrayError) -> Self {
        Self::Names(NamesError::Hash(cause))
    }
}

#[macro_export]
macro_rules! ensure_names {
    ($condition:expr, $($message:tt)*) => {
        if !$condition {
            return Err($crate::error::NamesError::Invalid(format!($($message)*)).into());
        }
    };
}
pub use ensure_names;
