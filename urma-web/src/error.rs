use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum WebError {
    Protocol(urma_core::error::Error),
    Io(std::io::Error),
    Files(urma_io::Error),
    Json(serde_json::Error),
    Integer(std::num::TryFromIntError),
    Hex(hex::FromHexError),
    Hash(bitcoin::hex::HexToArrayError),
    Transaction(bitcoin::consensus::encode::Error),
    Invalid(String),
    Missing(String),
}

impl Display for WebError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(cause) => Display::fmt(cause, formatter),
            Self::Io(cause) => Display::fmt(cause, formatter),
            Self::Files(cause) => Display::fmt(cause, formatter),
            Self::Json(cause) => Display::fmt(cause, formatter),
            Self::Integer(cause) => Display::fmt(cause, formatter),
            Self::Hex(cause) => Display::fmt(cause, formatter),
            Self::Hash(cause) => Display::fmt(cause, formatter),
            Self::Transaction(cause) => Display::fmt(cause, formatter),
            Self::Invalid(message) | Self::Missing(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for WebError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(cause) => Some(cause),
            Self::Io(cause) => Some(cause),
            Self::Files(cause) => Some(cause),
            Self::Json(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::Hex(cause) => Some(cause),
            Self::Hash(cause) => Some(cause),
            Self::Transaction(cause) => Some(cause),
            Self::Invalid(..) | Self::Missing(..) => None,
        }
    }
}

impl From<urma_core::error::Error> for WebError {
    fn from(cause: urma_core::error::Error) -> Self {
        Self::Protocol(cause)
    }
}

impl From<std::io::Error> for WebError {
    fn from(cause: std::io::Error) -> Self {
        Self::Io(cause)
    }
}

impl From<urma_io::Error> for WebError {
    fn from(cause: urma_io::Error) -> Self {
        Self::Files(cause)
    }
}

impl From<serde_json::Error> for WebError {
    fn from(cause: serde_json::Error) -> Self {
        Self::Json(cause)
    }
}

impl From<std::num::TryFromIntError> for WebError {
    fn from(cause: std::num::TryFromIntError) -> Self {
        Self::Integer(cause)
    }
}

impl From<hex::FromHexError> for WebError {
    fn from(cause: hex::FromHexError) -> Self {
        Self::Hex(cause)
    }
}

impl From<bitcoin::hex::HexToArrayError> for WebError {
    fn from(cause: bitcoin::hex::HexToArrayError) -> Self {
        Self::Hash(cause)
    }
}

impl From<bitcoin::consensus::encode::Error> for WebError {
    fn from(cause: bitcoin::consensus::encode::Error) -> Self {
        Self::Transaction(cause)
    }
}

#[macro_export]
macro_rules! ensure_web {
    ($condition:expr, $($message:tt)*) => {
        if !$condition {
            return Err($crate::error::WebError::Invalid(format!($($message)*)));
        }
    };
}
pub use ensure_web;
