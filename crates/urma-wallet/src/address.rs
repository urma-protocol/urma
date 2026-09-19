use crate::wallet::WalletError;
use bech32::{Hrp, segwit};
use bitcoin::{Address, CompressedPublicKey, Network, hashes::Hash};
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;

pub fn receive_address(signer: &impl IdentitySigner, chain: Chain) -> Result<String, WalletError> {
    let public = CompressedPublicKey::try_from(signer.public_key())
        .map_err(|cause| WalletError::Protocol(cause.into()))?;
    match chain {
        Chain::BitcoinRegtest => Ok(Address::p2wpkh(&public, Network::Regtest).to_string()),
        Chain::BitcoinTestnet4 => Ok(Address::p2wpkh(&public, Network::Testnet4).to_string()),
        Chain::LitecoinMainnet => segwit::encode(
            Hrp::parse("ltc").map_err(WalletError::AddressPrefix)?,
            segwit::VERSION_0,
            public.wpubkey_hash().as_byte_array(),
        )
        .map_err(WalletError::AddressEncoding),
        Chain::LitecoinTestnet => segwit::encode(
            Hrp::parse("tltc").map_err(WalletError::AddressPrefix)?,
            segwit::VERSION_0,
            public.wpubkey_hash().as_byte_array(),
        )
        .map_err(WalletError::AddressEncoding),
    }
}
