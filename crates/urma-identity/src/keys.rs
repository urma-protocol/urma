use bitcoin::XOnlyPublicKey;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecoverySecretId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorIdentity(pub XOnlyPublicKey);

pub struct RecoverySecret(Zeroizing<[u8; 32]>);
impl RecoverySecret {
    pub fn import(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    pub fn with_bytes<T>(&self, use_secret: impl FnOnce(&[u8; 32]) -> T) -> T {
        use_secret(&self.0)
    }
}

#[derive(Debug)]
pub enum KeyStoreError {
    MissingRecovery(RecoverySecretId),
    Locked,
    Unsupported,
    Storage(std::io::Error),
    Signing(bitcoin::secp256k1::Error),
}
impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key store: {self:?}")
    }
}
impl std::error::Error for KeyStoreError {}

pub trait RecoveryKeyStore {
    fn load_recovery(&self, key: RecoverySecretId) -> Result<RecoverySecret, KeyStoreError>;
}
