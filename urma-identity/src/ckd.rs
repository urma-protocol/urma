use crate::error::IdentityError;
use bitcoin::{
    bip32::{ChainCode, ChildNumber, Xpriv},
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha512},
    secp256k1::{Scalar, Secp256k1, SignOnly},
};
use zeroize::Zeroizing;

pub(crate) fn derive_hardened(parent: &Xpriv, path: &[u32]) -> Result<Xpriv, IdentityError> {
    let secp = Secp256k1::signing_only();
    let mut node = *parent;
    for index in path {
        let next = hardened_child(&secp, &node, *index);
        node.private_key.non_secure_erase();
        node = next?;
    }
    Ok(node)
}

fn hardened_child(
    secp: &Secp256k1<SignOnly>,
    parent: &Xpriv,
    index: u32,
) -> Result<Xpriv, IdentityError> {
    let child_number = ChildNumber::from_hardened_idx(index)?;
    let mut engine = HmacEngine::<sha512::Hash>::new(&parent.chain_code[..]);
    engine.input(&[0]);
    engine.input(Zeroizing::new(parent.private_key.secret_bytes()).as_ref());
    engine.input(&u32::from(child_number).to_be_bytes());
    let mac = Zeroizing::new(Hmac::<sha512::Hash>::from_engine(engine).to_byte_array());
    let left = Zeroizing::new(<[u8; 32]>::try_from(&mac[..32])?);
    let tweak = Scalar::from_be_bytes(*left).map_err(|_| IdentityError::Derivation)?;
    let private_key = parent
        .private_key
        .add_tweak(&tweak)
        .map_err(|_| IdentityError::Derivation)?;
    Ok(Xpriv {
        network: parent.network,
        depth: parent
            .depth
            .checked_add(1)
            .ok_or(IdentityError::Derivation)?,
        parent_fingerprint: parent.fingerprint(secp),
        child_number,
        private_key,
        chain_code: ChainCode::from(<[u8; 32]>::try_from(&mac[32..])?),
    })
}
