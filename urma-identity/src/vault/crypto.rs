use crate::error::IdentityError;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub(super) fn password_key(
    password: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(IdentityError::InvalidPassword);
    }
    let params = Params::new(65536, 3, 4, Some(32))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); 65536]);
    kdf.hash_password_into_with_memory(password.as_bytes(), salt, key.as_mut(), &mut memory)?;
    Ok(key)
}

pub(super) fn recovery_key(
    entropy: &[u8; 32],
    id: &[u8],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(id), entropy).expand(b"URMA/vault/v1/recovery-wrap", key.as_mut())?;
    Ok(key)
}

pub(super) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut bytes = Zeroizing::new(plaintext.to_vec());
    cipher.encrypt_in_place(Nonce::from_slice(nonce), aad, &mut *bytes)?;
    Ok(bytes.to_vec())
}
pub(super) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut bytes = Zeroizing::new(ciphertext.to_vec());
    cipher.decrypt_in_place(Nonce::from_slice(nonce), aad, &mut *bytes)?;
    Ok(bytes)
}
