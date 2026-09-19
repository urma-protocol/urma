use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Amount(bitcoin::amount::ParseAmountError),
    Script(bitcoin::script::Error),
    Invalid(String),
    Unsupported(String),
    Capacity(String),
    Missing(String),
    Context { message: String, cause: Box<Error> },
    Hex(hex::FromHexError),
    Integer(std::num::TryFromIntError),
    IntegerText(std::num::ParseIntError),
    Slice(std::array::TryFromSliceError),
    Utf8(std::str::Utf8Error),
    Text(std::string::FromUtf8Error),
    Allocation(std::collections::TryReserveError),
    Random(rand::Error),
    CipherKey(hmac::digest::InvalidLength),
    Mac(hmac::digest::MacError),
    Secp256k1(bitcoin::secp256k1::Error),
    Transaction(bitcoin::consensus::encode::Error),
    Push(bitcoin::script::PushBytesError),
    TaprootBuilder(bitcoin::taproot::TaprootBuilderError),
    Taproot(bitcoin::taproot::TaprootError),
    TaprootSighash(bitcoin::sighash::TaprootError),
    SegwitSighash(bitcoin::sighash::P2wpkhError),
    AddressScript(bitcoin::address::FromScriptError),
    AddressParse(bitcoin::address::ParseError),
    AddressNetwork(bitcoin::address::NetworkValidationError),
    PublicKey(bitcoin::key::FromSliceError),
    UncompressedKey(bitcoin::key::UncompressedPublicKeyError),
    Ecdsa(bitcoin::ecdsa::Error),
    Hash(bitcoin::hex::HexToArrayError),
    ProofOfWork(bitcoin::block::ValidationError),
}
impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Amount(cause) => Display::fmt(cause, formatter),
            Self::Script(cause) => Display::fmt(cause, formatter),
            Self::Invalid(message)
            | Self::Missing(message)
            | Self::Unsupported(message)
            | Self::Capacity(message) => formatter.write_str(message),
            Self::Context { message, cause } => write!(formatter, "{message}: {cause}"),
            Self::Hex(cause) => Display::fmt(cause, formatter),
            Self::Integer(cause) => Display::fmt(cause, formatter),
            Self::IntegerText(cause) => Display::fmt(cause, formatter),
            Self::Slice(cause) => Display::fmt(cause, formatter),
            Self::Utf8(cause) => Display::fmt(cause, formatter),
            Self::Text(cause) => Display::fmt(cause, formatter),
            Self::Allocation(cause) => Display::fmt(cause, formatter),
            Self::Random(cause) => Display::fmt(cause, formatter),
            Self::CipherKey(cause) => Display::fmt(cause, formatter),
            Self::Mac(cause) => Display::fmt(cause, formatter),
            Self::Secp256k1(cause) => Display::fmt(cause, formatter),
            Self::Transaction(cause) => Display::fmt(cause, formatter),
            Self::Push(cause) => Display::fmt(cause, formatter),
            Self::TaprootBuilder(cause) => Display::fmt(cause, formatter),
            Self::Taproot(cause) => Display::fmt(cause, formatter),
            Self::TaprootSighash(cause) => Display::fmt(cause, formatter),
            Self::SegwitSighash(cause) => Display::fmt(cause, formatter),
            Self::AddressScript(cause) => Display::fmt(cause, formatter),
            Self::AddressParse(cause) => Display::fmt(cause, formatter),
            Self::AddressNetwork(cause) => Display::fmt(cause, formatter),
            Self::PublicKey(cause) => Display::fmt(cause, formatter),
            Self::UncompressedKey(cause) => Display::fmt(cause, formatter),
            Self::Ecdsa(cause) => Display::fmt(cause, formatter),
            Self::Hash(cause) => Display::fmt(cause, formatter),
            Self::ProofOfWork(cause) => Display::fmt(cause, formatter),
        }
    }
}
impl std::error::Error for Error {}
impl From<hex::FromHexError> for Error {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}
impl From<std::num::TryFromIntError> for Error {
    fn from(error: std::num::TryFromIntError) -> Self {
        Self::Integer(error)
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::IntegerText(error)
    }
}
impl From<std::array::TryFromSliceError> for Error {
    fn from(error: std::array::TryFromSliceError) -> Self {
        Self::Slice(error)
    }
}
impl From<std::str::Utf8Error> for Error {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::Utf8(error)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::Text(error)
    }
}
impl From<std::collections::TryReserveError> for Error {
    fn from(error: std::collections::TryReserveError) -> Self {
        Self::Allocation(error)
    }
}
impl From<rand::Error> for Error {
    fn from(error: rand::Error) -> Self {
        Self::Random(error)
    }
}
impl From<hmac::digest::InvalidLength> for Error {
    fn from(error: hmac::digest::InvalidLength) -> Self {
        Self::CipherKey(error)
    }
}
impl From<hmac::digest::MacError> for Error {
    fn from(error: hmac::digest::MacError) -> Self {
        Self::Mac(error)
    }
}
impl From<bitcoin::secp256k1::Error> for Error {
    fn from(error: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(error)
    }
}
impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(error: bitcoin::consensus::encode::Error) -> Self {
        Self::Transaction(error)
    }
}
impl From<bitcoin::script::PushBytesError> for Error {
    fn from(error: bitcoin::script::PushBytesError) -> Self {
        Self::Push(error)
    }
}
impl From<bitcoin::taproot::TaprootBuilderError> for Error {
    fn from(error: bitcoin::taproot::TaprootBuilderError) -> Self {
        Self::TaprootBuilder(error)
    }
}
impl From<bitcoin::taproot::TaprootError> for Error {
    fn from(error: bitcoin::taproot::TaprootError) -> Self {
        Self::Taproot(error)
    }
}
impl From<bitcoin::sighash::TaprootError> for Error {
    fn from(error: bitcoin::sighash::TaprootError) -> Self {
        Self::TaprootSighash(error)
    }
}
impl From<bitcoin::sighash::P2wpkhError> for Error {
    fn from(error: bitcoin::sighash::P2wpkhError) -> Self {
        Self::SegwitSighash(error)
    }
}
impl From<bitcoin::address::FromScriptError> for Error {
    fn from(error: bitcoin::address::FromScriptError) -> Self {
        Self::AddressScript(error)
    }
}
impl From<bitcoin::address::ParseError> for Error {
    fn from(error: bitcoin::address::ParseError) -> Self {
        Self::AddressParse(error)
    }
}
impl From<bitcoin::address::NetworkValidationError> for Error {
    fn from(error: bitcoin::address::NetworkValidationError) -> Self {
        Self::AddressNetwork(error)
    }
}
impl From<bitcoin::key::FromSliceError> for Error {
    fn from(error: bitcoin::key::FromSliceError) -> Self {
        Self::PublicKey(error)
    }
}
impl From<bitcoin::key::UncompressedPublicKeyError> for Error {
    fn from(error: bitcoin::key::UncompressedPublicKeyError) -> Self {
        Self::UncompressedKey(error)
    }
}
impl From<bitcoin::ecdsa::Error> for Error {
    fn from(error: bitcoin::ecdsa::Error) -> Self {
        Self::Ecdsa(error)
    }
}
impl From<bitcoin::hex::HexToArrayError> for Error {
    fn from(error: bitcoin::hex::HexToArrayError) -> Self {
        Self::Hash(error)
    }
}
impl From<bitcoin::block::ValidationError> for Error {
    fn from(error: bitcoin::block::ValidationError) -> Self {
        Self::ProofOfWork(error)
    }
}

pub trait Context<T> {
    fn context(self, message: impl Into<String>) -> Result<T, Error>;
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T, Error>;
}
impl<T> Context<T> for Option<T> {
    fn context(self, message: impl Into<String>) -> Result<T, Error> {
        match self {
            Some(value) => Ok(value),
            None => Err(Error::Missing(message.into())),
        }
    }
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T, Error> {
        match self {
            Some(value) => Ok(value),
            None => Err(Error::Missing(message())),
        }
    }
}
impl<T, E: Into<Error>> Context<T> for Result<T, E> {
    fn context(self, message: impl Into<String>) -> Result<T, Error> {
        self.map_err(|cause| Error::Context {
            message: message.into(),
            cause: Box::new(cause.into()),
        })
    }
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T, Error> {
        self.map_err(|cause| Error::Context {
            message: message(),
            cause: Box::new(cause.into()),
        })
    }
}
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $($message:tt)*) => {
        if !$condition { return Err($crate::error::Error::Invalid(format!($($message)*))); }
    };
}
#[macro_export]
macro_rules! bail {
    ($($message:tt)*) => { return Err($crate::error::Error::Invalid(format!($($message)*))) };
}
pub use {bail, ensure};
impl From<bitcoin::script::Error> for Error {
    fn from(error: bitcoin::script::Error) -> Self {
        Self::Script(error)
    }
}
impl From<bitcoin::amount::ParseAmountError> for Error {
    fn from(error: bitcoin::amount::ParseAmountError) -> Self {
        Self::Amount(error)
    }
}
