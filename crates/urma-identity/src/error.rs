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

    InvalidPhrase,
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
            Self::Phrase(_) | Self::InvalidPhrase => "invalid URMA identity recovery phrase",
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
impl std::error::Error for IdentityError {}
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
