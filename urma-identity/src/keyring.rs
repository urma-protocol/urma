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
        let slot = IdentitySlot::new(0)?;
        validate_name(name)?;
        let root = Root::from_phrase(phrase)?;
        root.identity(slot)?;
        Ok(Self {
            phrase: IdentityPhrase::from_entropy(Zeroizing::new(*phrase.entropy())),
            root,
            entries: vec![NamedIdentity {
                slot,
                name: name.into(),
            }],
            active: slot,
        })
    }
    pub fn recover(phrase: &IdentityPhrase) -> Result<Self, IdentityError> {
        let mut keyring = Self::create(phrase, "identity-0")?;
        for index in 1..IdentitySlot::CAPACITY {
            keyring.add(&format!("identity-{index}"))?;
        }
        Ok(keyring)
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
        if self.entries.iter().any(|entry| entry.name == name) {
            return Err(IdentityError::DuplicateName);
        }
        let index = u16::try_from(self.entries.len())?;
        let slot = IdentitySlot::new(index)?;
        self.root.identity(slot)?;
        self.entries.push(NamedIdentity {
            slot,
            name: name.into(),
        });
        Ok(slot)
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
