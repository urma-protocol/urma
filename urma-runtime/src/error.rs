use std::fmt::{Display, Formatter};
use urma_chain::validation::BlockValidationError;

#[derive(Debug)]
pub enum Error {
    Identity(urma_identity::error::IdentityError),
    Wallet(urma_wallet::wallet::WalletError),
    Protocol(urma_core::error::Error),
    Amount(bitcoin::amount::ParseAmountError),
    Script(bitcoin::script::Error),
    Invalid(String),
    Unsupported(String),
    Capacity(String),
    Missing(String),
    Context { message: String, cause: Box<Error> },
    Io(std::io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Url(url::ParseError),
    Integer(std::num::TryFromIntError),
    IntegerText(std::num::ParseIntError),
    Slice(std::array::TryFromSliceError),
    Utf8(std::str::Utf8Error),
    Text(std::string::FromUtf8Error),
    Allocation(std::collections::TryReserveError),
    Random(rand::Error),
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
    Rpc(bitcoincore_rpc::Error),
    Http(minreq::Error),
    Persist(tempfile::PersistError),
    Ip(std::net::AddrParseError),
}
impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(cause) => Display::fmt(cause, formatter),
            Self::Wallet(cause) => Display::fmt(cause, formatter),
            Self::Protocol(cause) => Display::fmt(cause, formatter),
            Self::Amount(cause) => Display::fmt(cause, formatter),
            Self::Script(cause) => Display::fmt(cause, formatter),
            Self::Invalid(message)
            | Self::Missing(message)
            | Self::Unsupported(message)
            | Self::Capacity(message) => formatter.write_str(message),
            Self::Context { message, cause } => write!(formatter, "{message}: {cause}"),
            Self::Io(cause) => Display::fmt(cause, formatter),
            Self::Json(cause) => Display::fmt(cause, formatter),
            Self::Hex(cause) => Display::fmt(cause, formatter),
            Self::Url(cause) => Display::fmt(cause, formatter),
            Self::Integer(cause) => Display::fmt(cause, formatter),
            Self::IntegerText(cause) => Display::fmt(cause, formatter),
            Self::Slice(cause) => Display::fmt(cause, formatter),
            Self::Utf8(cause) => Display::fmt(cause, formatter),
            Self::Text(cause) => Display::fmt(cause, formatter),
            Self::Allocation(cause) => Display::fmt(cause, formatter),
            Self::Random(cause) => Display::fmt(cause, formatter),
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
            Self::Rpc(cause) => Display::fmt(cause, formatter),
            Self::Http(cause) => Display::fmt(cause, formatter),
            Self::Persist(cause) => Display::fmt(cause, formatter),
            Self::Ip(cause) => Display::fmt(cause, formatter),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(cause) => Some(cause),
            Self::Wallet(cause) => Some(cause),
            Self::Protocol(cause) => Some(cause),
            Self::Amount(cause) => Some(cause),
            Self::Script(cause) => Some(cause),
            Self::Io(cause) => Some(cause),
            Self::Json(cause) => Some(cause),
            Self::Hex(cause) => Some(cause),
            Self::Url(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::IntegerText(cause) => Some(cause),
            Self::Slice(cause) => Some(cause),
            Self::Utf8(cause) => Some(cause),
            Self::Text(cause) => Some(cause),
            Self::Allocation(cause) => Some(cause),
            Self::Random(cause) => Some(cause),
            Self::Secp256k1(cause) => Some(cause),
            Self::Transaction(cause) => Some(cause),
            Self::Push(cause) => Some(cause),
            Self::TaprootBuilder(cause) => Some(cause),
            Self::Taproot(cause) => Some(cause),
            Self::TaprootSighash(cause) => Some(cause),
            Self::SegwitSighash(cause) => Some(cause),
            Self::AddressScript(cause) => Some(cause),
            Self::AddressParse(cause) => Some(cause),
            Self::AddressNetwork(cause) => Some(cause),
            Self::PublicKey(cause) => Some(cause),
            Self::UncompressedKey(cause) => Some(cause),
            Self::Ecdsa(cause) => Some(cause),
            Self::Hash(cause) => Some(cause),
            Self::ProofOfWork(cause) => Some(cause),
            Self::Rpc(cause) => Some(cause),
            Self::Http(cause) => Some(cause),
            Self::Persist(cause) => Some(cause),
            Self::Ip(cause) => Some(cause),
            Self::Context { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
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
impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Self::Url(error)
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
impl From<bitcoincore_rpc::Error> for Error {
    fn from(error: bitcoincore_rpc::Error) -> Self {
        Self::Rpc(error)
    }
}
impl From<minreq::Error> for Error {
    fn from(error: minreq::Error) -> Self {
        Self::Http(error)
    }
}
impl From<tempfile::PersistError> for Error {
    fn from(error: tempfile::PersistError) -> Self {
        Self::Persist(error)
    }
}
impl From<std::net::AddrParseError> for Error {
    fn from(error: std::net::AddrParseError) -> Self {
        Self::Ip(error)
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

impl From<urma_core::error::Error> for Error {
    fn from(cause: urma_core::error::Error) -> Self {
        Self::Protocol(cause)
    }
}

impl From<urma_wallet::wallet::WalletError> for Error {
    fn from(cause: urma_wallet::wallet::WalletError) -> Self {
        Self::Wallet(cause)
    }
}

impl From<urma_identity::error::IdentityError> for Error {
    fn from(cause: urma_identity::error::IdentityError) -> Self {
        Self::Identity(cause)
    }
}

impl From<urma_io::Error> for Error {
    fn from(cause: urma_io::Error) -> Self {
        match cause {
            urma_io::Error::Io(cause) => Self::Io(cause),
            urma_io::Error::PrivatePermissions => {
                Self::Invalid("file must have private permissions".into())
            }
            urma_io::Error::Integer(cause) => Self::Integer(cause),
            urma_io::Error::LimitOverflow => Self::Missing("file read limit overflow".into()),
            urma_io::Error::TooLarge { limit } => {
                Self::Capacity(format!("file exceeds {limit} byte client capacity"))
            }
            urma_io::Error::Persist(cause) => Self::Persist(cause),
            urma_io::Error::Context { message, cause } => Self::Context {
                message,
                cause: Box::new((*cause).into()),
            },
        }
    }
}

impl From<BlockValidationError> for Error {
    fn from(error: BlockValidationError) -> Self {
        match error {
            BlockValidationError::ProofOfWork(cause) => Self::Context {
                message: "block proof of work".into(),
                cause: Box::new(Self::ProofOfWork(cause)),
            },
            cause => Self::Invalid(cause.to_string()),
        }
    }
}

impl From<urma_chain::transaction::TransactionDecodeError> for Error {
    fn from(cause: urma_chain::transaction::TransactionDecodeError) -> Self {
        use urma_chain::transaction::TransactionDecodeError;
        match cause {
            TransactionDecodeError::LimitExceeded => Self::Invalid(cause.to_string()),
            TransactionDecodeError::Hex(cause) => Self::Hex(cause),
            TransactionDecodeError::Consensus(cause) => Self::Context {
                message: "decode transaction".into(),
                cause: Box::new(Self::Transaction(cause)),
            },
        }
    }
}
