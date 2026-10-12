use crate::{bip85, error::IdentityError, keys::AuthorIdentity};
use bitcoin::{
    PublicKey,
    bip32::Xpriv,
    secp256k1::{Keypair, Message, Secp256k1, ecdsa, schnorr},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentitySlot(u16);
impl IdentitySlot {
    pub const CAPACITY: u16 = 64;
    pub fn new(value: u16) -> Result<Self, IdentityError> {
        if value >= Self::CAPACITY {
            return Err(IdentityError::Capacity);
        }
        Ok(Self(value))
    }
    pub fn index(self) -> u16 {
        self.0
    }
}

pub trait IdentitySigner {
    fn public_key(&self) -> PublicKey;
    fn sign_author(&self, message: Message) -> Result<schnorr::Signature, IdentityError>;
    fn sign_funding(&self, message: Message) -> Result<ecdsa::Signature, IdentityError>;
}

pub struct IdentityKey(Zeroizing<[u8; 32]>);
struct TemporaryKeypair(Keypair);
impl Drop for TemporaryKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl IdentityKey {
    pub(crate) fn derive(master: &Xpriv, slot: IdentitySlot) -> Result<Self, IdentityError> {
        let entropy = match bip85::hex(master, 32, u32::from(slot.index())) {
            Ok(entropy) => entropy,
            Err(IdentityError::Derivation) => return Err(IdentityError::InvalidSlot(slot)),
            Err(other) => return Err(other),
        };
        let key = Zeroizing::new(<[u8; 32]>::try_from(entropy.as_slice())?);
        match Keypair::from_seckey_slice(&Secp256k1::new(), key.as_ref()) {
            Ok(pair) => {
                let temporary = TemporaryKeypair(pair);
                drop(temporary);
                Ok(Self(key))
            }
            Err(bitcoin::secp256k1::Error::InvalidSecretKey) => {
                Err(IdentityError::InvalidSlot(slot))
            }
            Err(other) => Err(other.into()),
        }
    }
    fn keypair(&self) -> TemporaryKeypair {
        match Keypair::from_seckey_slice(&Secp256k1::new(), self.0.as_ref()) {
            Ok(key) => TemporaryKeypair(key),
            Err(error) => panic!("validated identity scalar became invalid: {error}"),
        }
    }
    pub fn author(&self) -> AuthorIdentity {
        AuthorIdentity(self.keypair().0.x_only_public_key().0)
    }
    pub fn sign_author_with_aux_rand(
        &self,
        message: Message,
        aux: &[u8; 32],
    ) -> schnorr::Signature {
        Secp256k1::new().sign_schnorr_with_aux_rand(&message, &self.keypair().0, aux)
    }
}
impl IdentitySigner for IdentityKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::new(self.keypair().0.public_key())
    }
    fn sign_author(&self, message: Message) -> Result<schnorr::Signature, IdentityError> {
        Ok(Secp256k1::new().sign_schnorr_no_aux_rand(&message, &self.keypair().0))
    }
    fn sign_funding(&self, message: Message) -> Result<ecdsa::Signature, IdentityError> {
        let pair = self.keypair();
        let mut secret = pair.0.secret_key();
        let signature = Secp256k1::new().sign_ecdsa(&message, &secret);
        secret.non_secure_erase();
        Ok(signature)
    }
}

impl IdentitySigner for Keypair {
    fn public_key(&self) -> PublicKey {
        PublicKey::new(Keypair::public_key(self))
    }
    fn sign_author(&self, message: Message) -> Result<schnorr::Signature, IdentityError> {
        Ok(Secp256k1::new().sign_schnorr_no_aux_rand(&message, self))
    }
    fn sign_funding(&self, message: Message) -> Result<ecdsa::Signature, IdentityError> {
        let mut secret = self.secret_key();
        let signature = Secp256k1::new().sign_ecdsa(&message, &secret);
        secret.non_secure_erase();
        Ok(signature)
    }
}
