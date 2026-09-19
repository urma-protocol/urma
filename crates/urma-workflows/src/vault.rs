use rand::rngs::OsRng;
use std::{fs::File, io::Read, os::unix::fs::PermissionsExt, path::Path};
use urma::{error::Error, storage};
use urma_identity::{
    error::IdentityError,
    identity::IdentitySlot,
    keyring::Keyring,
    phrase::IdentityPhrase,
    vault::{EncryptedVault, UnlockCredential, UnlockedVault},
};
use zeroize::Zeroizing;

pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    let file = File::open(path)?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(Error::Invalid(
            "credential file must have private permissions".into(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(IdentityError::Capacity.into());
    }
    let text = std::str::from_utf8(&bytes).map_err(IdentityError::from)?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn load(path: &Path, credential: UnlockCredential<'_>) -> Result<UnlockedVault, Error> {
    let bytes = storage::read_bounded(path, EncryptedVault::MAX_BYTES)?;
    Ok(EncryptedVault::from_bytes(&bytes)?.unlock(credential)?)
}

pub fn save_new(path: &Path, vault: &UnlockedVault) -> Result<(), Error> {
    let encrypted = vault.seal(&mut OsRng)?;
    storage::write_new(path, encrypted.as_bytes())
}

pub fn create(
    path: &Path,
    password: &str,
    name: &str,
    recovery_output: &Path,
) -> Result<(), Error> {
    if new_location(path)? == new_location(recovery_output)?
        || path.try_exists()?
        || recovery_output.try_exists()?
    {
        return Err(Error::Invalid(
            "vault and recovery backup require distinct new paths".into(),
        ));
    }
    let phrase = IdentityPhrase::generate(&mut OsRng)?;
    let keyring = Keyring::create(&phrase, name)?;
    let vault = UnlockedVault::create(keyring, password, &mut OsRng)?;
    let encrypted = vault.seal(&mut OsRng)?;
    let words = phrase.export_words()?;
    storage::write_new(recovery_output, words.as_bytes())?;
    storage::write_new(path, encrypted.as_bytes())
}

fn new_location(path: &Path) -> Result<std::path::PathBuf, Error> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Invalid("output requires a filename".into()))?;
    Ok(urma::config::output_parent(path).canonicalize()?.join(name))
}

pub fn recover(path: &Path, phrase: &IdentityPhrase, password: &str) -> Result<(), Error> {
    let keys = Keyring::recover(phrase)?;
    let vault = UnlockedVault::create(keys, password, &mut OsRng)?;
    save_new(path, &vault)
}

pub enum VaultChange<'a> {
    Add(&'a str),
    Select(IdentitySlot),
    Rename { slot: IdentitySlot, name: &'a str },
}

pub fn change(vault: &mut UnlockedVault, change: VaultChange<'_>) -> Result<(), Error> {
    match change {
        VaultChange::Add(name) => {
            vault.keyring_mut().add(name)?;
        }
        VaultChange::Select(slot) => vault.keyring_mut().select(slot)?,
        VaultChange::Rename { slot, name } => vault.keyring_mut().rename(slot, name)?,
    }
    Ok(())
}
