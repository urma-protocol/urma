use crate::{error::IdentityError, keyring::Keyring, phrase::IdentityPhrase};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;
mod crypto;
mod payload;

pub enum UnlockCredential<'a> {
    Password(&'a str),
    RecoveryPhrase(&'a IdentityPhrase),
}

pub struct EncryptedVault {
    bytes: Vec<u8>,
}
pub struct UnlockedVault {
    keyring: Keyring,
    header: Vec<u8>,
    data_key: Zeroizing<[u8; 32]>,
}

impl EncryptedVault {
    pub const HEADER_BYTES: usize = 192;
    pub const MAX_BYTES: usize = 4532;
    pub const MAGIC: [u8; 8] = *b"URMAVLT\0";
    pub const VERSION: u16 = 1;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if !(248..=Self::MAX_BYTES).contains(&bytes.len()) {
            return Err(IdentityError::InvalidVault);
        }
        if bytes[..8] != Self::MAGIC
            || bytes[8..12] != [1, 0, 0, 0]
            || bytes[12..24] != [0, 0, 1, 0, 3, 0, 0, 0, 4, 0, 0, 0]
        {
            return Err(IdentityError::UnsupportedVersion);
        }
        let size = u32::from_le_bytes(bytes[188..192].try_into()?);
        if usize::try_from(size)? != bytes.len() - Self::HEADER_BYTES {
            return Err(IdentityError::InvalidVault);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn unlock(&self, credential: UnlockCredential<'_>) -> Result<UnlockedVault, IdentityError> {
        let bytes = &self.bytes;
        let (key, nonce, wrapped, label) = match credential {
            UnlockCredential::Password(password) => (
                crypto::password_key(password, &bytes[40..56])?,
                &bytes[56..68],
                &bytes[68..116],
                "password",
            ),
            UnlockCredential::RecoveryPhrase(phrase) => (
                crypto::recovery_key(phrase.entropy(), &bytes[24..40])?,
                &bytes[116..128],
                &bytes[128..176],
                "recovery",
            ),
        };
        let aad = slot_aad(&bytes[..56], label);
        let raw_key = crypto::decrypt(&key, nonce, &aad, wrapped)?;
        let data_key = Zeroizing::new(raw_key.as_slice().try_into()?);
        let plaintext = crypto::decrypt(&data_key, &bytes[176..188], &bytes[..192], &bytes[192..])?;
        let keyring = payload::decode(&plaintext)?;
        let recovery_key = crypto::recovery_key(&keyring.entropy, &bytes[24..40])?;
        let expected = crypto::encrypt(
            &recovery_key,
            &bytes[116..128],
            &slot_aad(&bytes[..56], "recovery"),
            data_key.as_ref(),
        )?;
        if expected != bytes[128..176] {
            return Err(IdentityError::Authentication);
        }
        Ok(UnlockedVault {
            keyring,
            header: bytes[..176].to_vec(),
            data_key,
        })
    }
}

impl UnlockedVault {
    pub fn create<R: RngCore + CryptoRng>(
        keyring: Keyring,
        password: &str,
        rng: &mut R,
    ) -> Result<Self, IdentityError> {
        let mut header = Vec::from(EncryptedVault::MAGIC);
        header.extend_from_slice(&[1, 0, 0, 0]);
        header.extend_from_slice(&65536u32.to_le_bytes());
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&4u32.to_le_bytes());
        header.resize(56, 0);
        rng.try_fill_bytes(&mut header[24..56])?;
        let mut data_key = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(data_key.as_mut())?;
        let password_key = crypto::password_key(password, &header[40..56])?;
        let recovery_key = crypto::recovery_key(&keyring.entropy, &header[24..40])?;
        for (key, label) in [(&password_key, "password"), (&recovery_key, "recovery")] {
            let mut nonce = [0; 12];
            rng.try_fill_bytes(&mut nonce)?;
            let wrapped = crypto::encrypt(
                key,
                &nonce,
                &slot_aad(&header[..56], label),
                data_key.as_ref(),
            )?;
            header.extend_from_slice(&nonce);
            header.extend_from_slice(&wrapped);
        }
        Ok(Self {
            keyring,
            header,
            data_key,
        })
    }
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }
    pub fn keyring_mut(&mut self) -> &mut Keyring {
        &mut self.keyring
    }
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<EncryptedVault, IdentityError> {
        let plaintext = payload::encode(&self.keyring)?;
        let mut header = self.header.clone();
        let mut nonce = [0; 12];
        rng.try_fill_bytes(&mut nonce)?;
        header.extend_from_slice(&nonce);
        let size = u32::try_from(plaintext.len() + 16)?;
        header.extend_from_slice(&size.to_le_bytes());
        let ciphertext = crypto::encrypt(&self.data_key, &nonce, &header, &plaintext)?;
        header.extend_from_slice(&ciphertext);
        EncryptedVault::from_bytes(&header)
    }
    pub fn reset_password<R: RngCore + CryptoRng>(
        self,
        password: &str,
        rng: &mut R,
    ) -> Result<Self, IdentityError> {
        Self::create(self.keyring, password, rng)
    }
}
fn slot_aad(base: &[u8], label: &str) -> Vec<u8> {
    let mut aad = base.to_vec();
    aad.extend_from_slice(b"URMA/vault/v1/");
    aad.extend_from_slice(label.as_bytes());
    aad
}
