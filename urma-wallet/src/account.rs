use crate::wallet::{SpendRequest, WalletError};
use bitcoin::{
    CompressedPublicKey, NetworkKind, ScriptBuf, Transaction, Witness,
    bech32::{Hrp, segwit},
    bip32::{ChildNumber, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
};
use std::collections::HashSet;
use urma_chain::observation::Chain;
pub use urma_identity::root::Branch;
use urma_identity::{ckd::derive_normal, root::Root};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPath {
    pub branch: Branch,
    pub index: u32,
}

impl KeyPath {
    pub const RECEIVE: KeyPath = KeyPath {
        branch: Branch::External,
        index: 0,
    };

    pub fn new(branch: Branch, index: u32) -> Self {
        Self { branch, index }
    }

    fn children(self) -> Result<[ChildNumber; 2], WalletError> {
        Ok([
            ChildNumber::from_normal_idx(self.branch.index()).map_err(WalletError::Derivation)?,
            ChildNumber::from_normal_idx(self.index).map_err(WalletError::Derivation)?,
        ])
    }
}

pub struct Account {
    chain: Chain,
    key: Xpriv,
    xpub: Xpub,
}

impl Account {
    pub fn from_root(chain: Chain, root: &Root) -> Result<Self, WalletError> {
        Self::new(chain, root.account(chain).map_err(WalletError::Identity)?)
    }

    fn new(chain: Chain, key: Xpriv) -> Result<Self, WalletError> {
        let expected = match chain {
            Chain::BitcoinMainnet | Chain::LitecoinMainnet => NetworkKind::Main,
            Chain::BitcoinTestnet4 | Chain::BitcoinRegtest | Chain::LitecoinTestnet => {
                NetworkKind::Test
            }
        };
        if key.network != expected || key.depth != 3 {
            return Err(WalletError::WrongNetwork);
        }
        let xpub = Xpub::from_priv(&Secp256k1::signing_only(), &key);
        Ok(Self { chain, key, xpub })
    }

    pub fn chain(&self) -> Chain {
        self.chain
    }

    pub fn xpub(&self) -> Xpub {
        self.xpub
    }

    fn public(&self, path: KeyPath) -> Result<CompressedPublicKey, WalletError> {
        let child = self
            .xpub
            .derive_pub(&Secp256k1::verification_only(), &path.children()?)
            .map_err(WalletError::Derivation)?;
        Ok(CompressedPublicKey(child.public_key))
    }

    pub fn script(&self, path: KeyPath) -> Result<ScriptBuf, WalletError> {
        Ok(ScriptBuf::new_p2wpkh(&self.public(path)?.wpubkey_hash()))
    }

    pub fn address(&self, path: KeyPath) -> Result<String, WalletError> {
        segwit::encode(
            Hrp::parse(self.chain.address_hrp()).map_err(WalletError::AddressPrefix)?,
            segwit::VERSION_0,
            self.public(path)?.wpubkey_hash().as_byte_array(),
        )
        .map_err(WalletError::AddressEncoding)
    }

    pub fn receive_script(&self) -> Result<ScriptBuf, WalletError> {
        self.script(KeyPath::RECEIVE)
    }

    pub fn receive_address(&self) -> Result<String, WalletError> {
        self.address(KeyPath::RECEIVE)
    }

    pub fn sign(
        &self,
        request: &SpendRequest<'_>,
        paths: &[KeyPath],
    ) -> Result<Transaction, WalletError> {
        let tx = request.transaction;
        if tx.input.is_empty()
            || tx.input.len() != request.prevouts.len()
            || tx.input.len() != paths.len()
        {
            return Err(WalletError::InvalidFunding);
        }
        let mut seen = HashSet::new();
        if tx
            .input
            .iter()
            .any(|input| !seen.insert(input.previous_output) || !input.script_sig.is_empty())
        {
            return Err(WalletError::InvalidFunding);
        }
        budget(request)?;
        let secp = Secp256k1::new();
        let mut signed = tx.clone();
        let mut cache = SighashCache::new(tx);
        for (index, (previous, path)) in request.prevouts.iter().zip(paths).enumerate() {
            let expected = self.script(*path)?;
            if previous.script_pubkey != expected {
                return Err(WalletError::WrongIdentity);
            }
            let digest = cache
                .p2wpkh_signature_hash(index, &expected, previous.value, EcdsaSighashType::All)
                .map_err(|cause| WalletError::Protocol(cause.into()))?;
            let message = Message::from_digest(digest.to_byte_array());
            let mut child = derive_normal(&self.key, &[path.branch.index(), path.index])
                .map_err(WalletError::Identity)?;
            let signature = secp.sign_ecdsa(&message, &child.private_key);
            let public = child.private_key.public_key(&secp);
            child.private_key.non_secure_erase();
            secp.verify_ecdsa(&message, &signature, &public)
                .map_err(|cause| WalletError::Protocol(cause.into()))?;
            signed.input[index].witness =
                Witness::p2wpkh(&bitcoin::ecdsa::Signature::sighash_all(signature), &public);
        }
        Ok(signed)
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.key.private_key.non_secure_erase();
    }
}

fn budget(request: &SpendRequest<'_>) -> Result<(), WalletError> {
    let mut inputs = 0u64;
    for output in request.prevouts {
        inputs = inputs
            .checked_add(output.value.to_sat())
            .ok_or(WalletError::Overflow)?;
    }
    let mut outputs = 0u64;
    for output in &request.transaction.output {
        outputs = outputs
            .checked_add(output.value.to_sat())
            .ok_or(WalletError::Overflow)?;
    }
    let fee = inputs
        .checked_sub(outputs)
        .ok_or(WalletError::InsufficientFunds)?;
    if fee > request.budget.maximum_base_units {
        return Err(WalletError::BudgetExceeded);
    }
    Ok(())
}
