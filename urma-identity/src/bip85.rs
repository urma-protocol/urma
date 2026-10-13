use crate::{ckd, error::IdentityError};
use bitcoin::{
    bip32::Xpriv,
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha512},
};
use zeroize::Zeroizing;

pub const PURPOSE: u32 = 83696968;
pub const APPLICATION_HEX: u32 = 128169;

pub fn entropy(master: &Xpriv, path: &[u32]) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
    let mut node = ckd::derive_hardened(master, path)?;
    let key = Zeroizing::new(node.private_key.secret_bytes());
    node.private_key.non_secure_erase();
    let mut engine = HmacEngine::<sha512::Hash>::new(b"bip-entropy-from-k");
    engine.input(key.as_ref());
    Ok(Zeroizing::new(
        Hmac::<sha512::Hash>::from_engine(engine).to_byte_array(),
    ))
}

pub fn hex(master: &Xpriv, length: u32, index: u32) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    if !(16..=64).contains(&length) {
        return Err(IdentityError::Derivation);
    }
    let full = entropy(master, &[PURPOSE, APPLICATION_HEX, length, index])?;
    Ok(Zeroizing::new(full[..usize::try_from(length)?].to_vec()))
}
