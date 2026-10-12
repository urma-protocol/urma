use crate::error::IdentityError;
use bip39::{Language, Mnemonic};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub struct IdentityPhrase(Zeroizing<[u8; 16]>);
impl IdentityPhrase {
    pub const WORDS: usize = 12;
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, IdentityError> {
        let mut entropy = Zeroizing::new([0; 16]);
        rng.try_fill_bytes(entropy.as_mut())?;
        Ok(Self(entropy))
    }
    pub fn parse(words: &str) -> Result<Self, IdentityError> {
        if words.len() > 512 {
            return Err(IdentityError::InvalidPhrase);
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)?;
        if mnemonic.word_count() != Self::WORDS {
            return Err(IdentityError::InvalidPhrase);
        }
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let bytes: [u8; 16] = entropy.as_slice().try_into()?;
        Ok(Self(Zeroizing::new(bytes)))
    }
    pub fn export_words(&self) -> Result<Zeroizing<String>, IdentityError> {
        Ok(Zeroizing::new(self.mnemonic()?.to_string()))
    }
    pub(crate) fn from_entropy(entropy: Zeroizing<[u8; 16]>) -> Self {
        Self(entropy)
    }
    pub(crate) fn entropy(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn seed(&self) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
        Ok(Zeroizing::new(self.mnemonic()?.to_seed_normalized("")))
    }
    fn mnemonic(&self) -> Result<Mnemonic, IdentityError> {
        Ok(Mnemonic::from_entropy_in(
            Language::English,
            self.0.as_ref(),
        )?)
    }
}
