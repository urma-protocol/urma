use crate::{
    descriptor,
    error::IdentityError,
    identity::{IdentityKey, IdentitySlot},
    phrase::IdentityPhrase,
};
use bitcoin::{
    CompressedPublicKey, NetworkKind,
    bech32::{Hrp, segwit},
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::Secp256k1,
};
use urma_chain::observation::Chain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    External,
    Internal,
}
impl Branch {
    pub fn index(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }
}

pub struct Root {
    master: Xpriv,
}
impl Root {
    pub const PURPOSE: u32 = 84;

    pub fn from_phrase(phrase: &IdentityPhrase) -> Result<Self, IdentityError> {
        let seed = phrase.seed()?;
        Ok(Self {
            master: Xpriv::new_master(NetworkKind::Main, seed.as_ref())?,
        })
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.master.fingerprint(&Secp256k1::signing_only())
    }
    pub fn coin_type(chain: Chain) -> u32 {
        match chain {
            Chain::BitcoinMainnet => 0,
            Chain::LitecoinMainnet => 2,
            Chain::BitcoinTestnet4 | Chain::BitcoinRegtest | Chain::LitecoinTestnet => 1,
        }
    }
    pub fn account(&self, chain: Chain) -> Result<Xpriv, IdentityError> {
        let path = [
            ChildNumber::from_hardened_idx(Self::PURPOSE)?,
            ChildNumber::from_hardened_idx(Self::coin_type(chain))?,
            ChildNumber::from_hardened_idx(0)?,
        ];
        let mut account = self.master.derive_priv(&Secp256k1::signing_only(), &path)?;
        account.network = match chain {
            Chain::BitcoinMainnet | Chain::LitecoinMainnet => NetworkKind::Main,
            Chain::BitcoinTestnet4 | Chain::BitcoinRegtest | Chain::LitecoinTestnet => {
                NetworkKind::Test
            }
        };
        Ok(account)
    }
    pub fn account_xpub(&self, chain: Chain) -> Result<Xpub, IdentityError> {
        let mut account = self.account(chain)?;
        let xpub = Xpub::from_priv(&Secp256k1::signing_only(), &account);
        account.private_key.non_secure_erase();
        Ok(xpub)
    }
    pub fn descriptors(&self, chain: Chain) -> Result<[String; 2], IdentityError> {
        let origin = format!(
            "[{}/{}h/{}h/0h]{}",
            self.fingerprint(),
            Self::PURPOSE,
            Self::coin_type(chain),
            self.account_xpub(chain)?
        );
        Ok([
            descriptor::with_checksum(&format!("wpkh({origin}/0/*)"))?,
            descriptor::with_checksum(&format!("wpkh({origin}/1/*)"))?,
        ])
    }
    pub fn address(
        &self,
        chain: Chain,
        branch: Branch,
        index: u32,
    ) -> Result<String, IdentityError> {
        let path = [
            ChildNumber::from_normal_idx(branch.index())?,
            ChildNumber::from_normal_idx(index)?,
        ];
        let child = self
            .account_xpub(chain)?
            .derive_pub(&Secp256k1::verification_only(), &path)?;
        let hash = CompressedPublicKey(child.public_key).wpubkey_hash();
        Ok(segwit::encode(
            Hrp::parse(chain.address_hrp())?,
            segwit::VERSION_0,
            hash.as_byte_array(),
        )?)
    }
    pub fn identity(&self, slot: IdentitySlot) -> Result<IdentityKey, IdentityError> {
        IdentityKey::derive(&self.master, slot)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        self.master.private_key.non_secure_erase();
        self.master.chain_code = ChainCode::from([0; 32]);
    }
}
