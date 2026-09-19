use std::{fmt, io, num::ParseIntError, string::FromUtf8Error};

#[derive(Debug)]
pub enum Error {
    Native(urma::error::Error),
    Protocol(urma_core::error::Error),
    Io(io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Integer(ParseIntError),
    Conversion(std::num::TryFromIntError),
    Utf8(FromUtf8Error),
    Regex(regex::Error),
    Git(String),
    Invalid(String),
    Capacity(String),
    ReviewRequired(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => write!(f, "{error}"),
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "Git artifact I/O: {error}"),
            Self::Json(error) => write!(f, "Git artifact JSON: {error}"),
            Self::Hex(error) => write!(f, "Git artifact hex: {error}"),
            Self::Conversion(error) => write!(f, "Git size conversion: {error}"),
            Self::Integer(error) => write!(f, "Git artifact integer: {error}"),
            Self::Utf8(error) => write!(f, "Git metadata encoding: {error}"),
            Self::Regex(error) => write!(f, "Git scanner rule: {error}"),
            Self::Git(message) => write!(f, "Git worker failed: {message}"),
            Self::Invalid(message) => write!(f, "git_profile_invalid: {message}"),
            Self::Capacity(message) => write!(f, "capacity_refusal: {message}"),
            Self::ReviewRequired(message) => write!(f, "review_required: {message}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<hex::FromHexError> for Error {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}
impl From<ParseIntError> for Error {
    fn from(error: ParseIntError) -> Self {
        Self::Integer(error)
    }
}
impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Self::Utf8(error)
    }
}
impl From<regex::Error> for Error {
    fn from(error: regex::Error) -> Self {
        Self::Regex(error)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(error: std::num::TryFromIntError) -> Self {
        Self::Conversion(error)
    }
}

impl From<urma::error::Error> for Error {
    fn from(error: urma::error::Error) -> Self {
        Self::Native(error)
    }
}
impl From<urma_core::error::Error> for Error {
    fn from(error: urma_core::error::Error) -> Self {
        Self::Protocol(error)
    }
}
