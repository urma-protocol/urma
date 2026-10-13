use crate::{
    error::IdentityError,
    identity::{IdentityKey, IdentitySlot},
    phrase::IdentityPhrase,
    root::Root,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedIdentity {
    pub slot: IdentitySlot,
    pub name: String,
}

pub struct Keyring {
    pub(crate) phrase: IdentityPhrase,
    pub(crate) root: Root,
    pub(crate) entries: Vec<NamedIdentity>,
    pub(crate) active: IdentitySlot,
}
impl Keyring {
    pub fn create(phrase: &IdentityPhrase, name: &str) -> Result<Self, IdentityError> {
        let mut keyring = Self::empty(phrase)?;
        keyring.add(name)?;
        Ok(keyring)
    }
    pub fn recover(phrase: &IdentityPhrase) -> Result<Self, IdentityError> {
        let mut keyring = Self::empty(phrase)?;
        for index in 0..IdentitySlot::CAPACITY {
            keyring.push(&format!("identity-{index}"))?;
        }
        Ok(keyring)
    }
    pub(crate) fn empty(phrase: &IdentityPhrase) -> Result<Self, IdentityError> {
        Ok(Self {
            phrase: IdentityPhrase::from_entropy(Zeroizing::new(*phrase.entropy())),
            root: Root::from_phrase(phrase)?,
            entries: Vec::new(),
            active: IdentitySlot::new(0)?,
        })
    }
    pub(crate) fn push(&mut self, name: &str) -> Result<IdentitySlot, IdentityError> {
        validate_name(name)?;
        if self.entries.iter().any(|entry| entry.name == name) {
            return Err(IdentityError::DuplicateName);
        }
        let slot = self.next_slot()?;
        self.entries.push(NamedIdentity {
            slot,
            name: name.into(),
        });
        Ok(slot)
    }
    fn next_slot(&self) -> Result<IdentitySlot, IdentityError> {
        IdentitySlot::new(u16::try_from(self.entries.len())?)
    }
    pub fn root(&self) -> &Root {
        &self.root
    }
    pub fn identities(&self) -> &[NamedIdentity] {
        &self.entries
    }
    pub fn active_slot(&self) -> IdentitySlot {
        self.active
    }
    pub fn active(&self) -> Result<IdentityKey, IdentityError> {
        self.identity(self.active)
    }
    pub fn identity(&self, slot: IdentitySlot) -> Result<IdentityKey, IdentityError> {
        if !self.entries.iter().any(|entry| entry.slot == slot) {
            return Err(IdentityError::MissingIdentity);
        }
        self.root.identity(slot)
    }
    pub fn select(&mut self, slot: IdentitySlot) -> Result<(), IdentityError> {
        self.identity(slot)?;
        self.active = slot;
        Ok(())
    }
    pub fn add(&mut self, name: &str) -> Result<IdentitySlot, IdentityError> {
        validate_name(name)?;
        self.root.identity(self.next_slot()?)?;
        self.push(name)
    }
    pub fn rename(&mut self, slot: IdentitySlot, name: &str) -> Result<(), IdentityError> {
        validate_name(name)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.slot != slot && entry.name == name)
        {
            return Err(IdentityError::DuplicateName);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.slot == slot)
            .ok_or(IdentityError::MissingIdentity)?;
        entry.name = name.into();
        Ok(())
    }
}
fn validate_name(name: &str) -> Result<(), IdentityError> {
    if name.is_empty()
        || name.len() > 64
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(IdentityError::InvalidName);
    }
    Ok(())
}
