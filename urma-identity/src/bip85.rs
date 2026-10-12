use crate::error::IdentityError;
use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha512},
    secp256k1::Scalar,
};
use zeroize::Zeroizing;

pub const PURPOSE: u32 = 83696968;
pub const APPLICATION_HEX: u32 = 128169;

pub fn entropy(master: &Xpriv, path: &[u32]) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
    let key = derive_hardened(master, path)?;
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

fn derive_hardened(master: &Xpriv, path: &[u32]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut key = master.private_key;
    let mut chain = Zeroizing::new(master.chain_code.to_bytes());
    for index in path {
        let child = ChildNumber::from_hardened_idx(*index)?;
        let mut engine = HmacEngine::<sha512::Hash>::new(chain.as_ref());
        engine.input(&[0]);
        engine.input(Zeroizing::new(key.secret_bytes()).as_ref());
        engine.input(&u32::from(child).to_be_bytes());
        let mac = Zeroizing::new(Hmac::<sha512::Hash>::from_engine(engine).to_byte_array());
        let left = Zeroizing::new(<[u8; 32]>::try_from(&mac[..32])?);
        let tweak = Scalar::from_be_bytes(*left).map_err(|_| IdentityError::Derivation)?;
        let next = key
            .add_tweak(&tweak)
            .map_err(|_| IdentityError::Derivation)?;
        key.non_secure_erase();
        key = next;
        chain.copy_from_slice(&mac[32..]);
    }
    let bytes = Zeroizing::new(key.secret_bytes());
    key.non_secure_erase();
    Ok(bytes)
}
