use crate::identity::IdentitySlot;
use bitcoin::{
    bech32::{primitives::hrp, segwit},
    bip32,
};
use std::fmt;

#[derive(Debug)]
pub enum IdentityError {
    Phrase(bip39::Error),
    Kdf(argon2::Error),
    Hkdf(hkdf::InvalidLength),
    CipherKey(aes::cipher::InvalidLength),
    Aead(aes_gcm::Error),
    Integer(std::num::TryFromIntError),
    Slice(std::array::TryFromSliceError),
    Utf8(std::str::Utf8Error),
    Bip32(bip32::Error),
    AddressPrefix(hrp::Error),
    AddressEncoding(segwit::EncodeError),

    InvalidPhrase,
    InvalidSlot(IdentitySlot),
    Descriptor,
    InvalidPassword,
    InvalidName,
    DuplicateName,
    MissingIdentity,
    Capacity,
    InvalidVault,
    UnsupportedVersion,
    Authentication,
    Derivation,
    Random(rand::Error),
    Signing(bitcoin::secp256k1::Error),
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Phrase(_) | Self::InvalidPhrase => {
                "invalid URMA recovery phrase: expected 12 English BIP39 words"
            }
            Self::InvalidSlot(_) => "identity slot has no valid key; choose another slot",
            Self::Bip32(_) => "wallet key derivation failed",
            Self::AddressPrefix(_) | Self::AddressEncoding(_) => "wallet address encoding failed",
            Self::Descriptor => "output descriptor contains an unsupported character",
            Self::InvalidPassword => "vault password must contain 12..1024 UTF-8 bytes",
            Self::InvalidName => {
                "identity name must be 1..64 UTF-8 bytes without control or edge whitespace"
            }
            Self::DuplicateName => "identity name already exists",
            Self::MissingIdentity => "identity slot is not present",
            Self::Capacity => "identity vault capacity exceeded",
            Self::Integer(_) | Self::Slice(_) | Self::Utf8(_) | Self::InvalidVault => {
                "invalid identity vault"
            }
            Self::UnsupportedVersion => "unsupported identity vault version or suite",
            Self::Aead(_) | Self::Authentication => "vault authentication failed",
            Self::Kdf(_) | Self::Hkdf(_) | Self::CipherKey(_) | Self::Derivation => {
                "identity key derivation failed"
            }
            Self::Random(_) => "identity entropy source failed",
            Self::Signing(_) => "identity signing failed",
        };
        f.write_str(message)
    }
}
impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Phrase(cause) => Some(cause),
            Self::CipherKey(cause) => Some(cause),
            Self::Integer(cause) => Some(cause),
            Self::Slice(cause) => Some(cause),
            Self::Utf8(cause) => Some(cause),
            Self::Random(cause) => Some(cause),
            Self::Signing(cause) => Some(cause),
            Self::Bip32(cause) => Some(cause),
            Self::AddressPrefix(cause) => Some(cause),
            Self::AddressEncoding(cause) => Some(cause),
            _ => None,
        }
    }
}
impl From<rand::Error> for IdentityError {
    fn from(error: rand::Error) -> Self {
        Self::Random(error)
    }
}
impl From<bitcoin::secp256k1::Error> for IdentityError {
    fn from(error: bitcoin::secp256k1::Error) -> Self {
        Self::Signing(error)
    }
}

impl From<bip32::Error> for IdentityError {
    fn from(cause: bip32::Error) -> Self {
        Self::Bip32(cause)
    }
}

impl From<hrp::Error> for IdentityError {
    fn from(cause: hrp::Error) -> Self {
        Self::AddressPrefix(cause)
    }
}

impl From<segwit::EncodeError> for IdentityError {
    fn from(cause: segwit::EncodeError) -> Self {
        Self::AddressEncoding(cause)
    }
}

impl From<bip39::Error> for IdentityError {
    fn from(cause: bip39::Error) -> Self {
        Self::Phrase(cause)
    }
}

impl From<argon2::Error> for IdentityError {
    fn from(cause: argon2::Error) -> Self {
        Self::Kdf(cause)
    }
}

impl From<hkdf::InvalidLength> for IdentityError {
    fn from(cause: hkdf::InvalidLength) -> Self {
        Self::Hkdf(cause)
    }
}

impl From<aes::cipher::InvalidLength> for IdentityError {
    fn from(cause: aes::cipher::InvalidLength) -> Self {
        Self::CipherKey(cause)
    }
}

impl From<aes_gcm::Error> for IdentityError {
    fn from(cause: aes_gcm::Error) -> Self {
        Self::Aead(cause)
    }
}

impl From<std::num::TryFromIntError> for IdentityError {
    fn from(cause: std::num::TryFromIntError) -> Self {
        Self::Integer(cause)
    }
}

impl From<std::array::TryFromSliceError> for IdentityError {
    fn from(cause: std::array::TryFromSliceError) -> Self {
        Self::Slice(cause)
    }
}

impl From<std::str::Utf8Error> for IdentityError {
    fn from(cause: std::str::Utf8Error) -> Self {
        Self::Utf8(cause)
    }
}
