use crate::{
    error::IdentityError, identity::IdentitySlot, keyring::Keyring, phrase::IdentityPhrase,
};
use zeroize::Zeroizing;

pub(super) fn encode(keyring: &Keyring) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let count = u16::try_from(keyring.entries.len())?;
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&keyring.active.index().to_le_bytes());
    bytes.extend_from_slice(keyring.entropy.as_ref());
    for entry in &keyring.entries {
        bytes.extend_from_slice(&entry.slot.index().to_le_bytes());
        bytes.push(u8::try_from(entry.name.len())?);
        bytes.extend_from_slice(entry.name.as_bytes());
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Keyring, IdentityError> {
    if bytes.len() < 40 {
        return Err(IdentityError::InvalidVault);
    }
    let count = u16::from_le_bytes([bytes[0], bytes[1]]);
    let active = IdentitySlot::new(u16::from_le_bytes([bytes[2], bytes[3]]))?;
    if count == 0 || count > IdentitySlot::CAPACITY || active.index() >= count {
        return Err(IdentityError::InvalidVault);
    }
    let entropy = bytes[4..36].try_into()?;
    let phrase = IdentityPhrase::from_entropy(Zeroizing::new(entropy));
    let mut keyring = Keyring::create(&phrase, "pending")?;
    keyring.entries.clear();
    let mut offset = 36;
    for index in 0..count {
        let prefix = bytes
            .get(offset..offset + 3)
            .ok_or(IdentityError::InvalidVault)?;
        let slot = u16::from_le_bytes([prefix[0], prefix[1]]);
        if slot != index {
            return Err(IdentityError::InvalidVault);
        }
        offset += 3;
        let length = usize::from(prefix[2]);
        let name = std::str::from_utf8(
            bytes
                .get(offset..offset + length)
                .ok_or(IdentityError::InvalidVault)?,
        )?;
        keyring.add(name)?;
        offset += length;
    }
    if offset != bytes.len() {
        return Err(IdentityError::InvalidVault);
    }
    keyring.select(active)?;
    Ok(keyring)
}
