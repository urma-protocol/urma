use crate::wallet::WalletError;
use bech32::{Hrp, segwit};
use bitcoin::{
    Address, CompressedPublicKey, Network, ScriptBuf, WitnessProgram, WitnessVersion,
    hashes::Hash,
};
use std::str::FromStr;
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;

pub fn destination_script(address: &str, chain: Chain) -> Result<ScriptBuf, WalletError> {
    match chain {
        Chain::BitcoinRegtest => bitcoin_script(address, Network::Regtest),
        Chain::BitcoinTestnet4 => bitcoin_script(address, Network::Testnet4),
        Chain::LitecoinMainnet => litecoin_script(address, "ltc"),
        Chain::LitecoinTestnet => litecoin_script(address, "tltc"),
    }
}

fn bitcoin_script(address: &str, network: Network) -> Result<ScriptBuf, WalletError> {
    Ok(Address::from_str(address)
        .map_err(WalletError::AddressParse)?
        .require_network(network)
        .map_err(WalletError::AddressParse)?
        .script_pubkey())
}

fn litecoin_script(address: &str, prefix: &str) -> Result<ScriptBuf, WalletError> {
    let (hrp, version, program) =
        segwit::decode(address).map_err(WalletError::AddressDecoding)?;
    if hrp != Hrp::parse(prefix).map_err(WalletError::AddressPrefix)? {
        return Err(WalletError::WrongNetwork);
    }
    let version = WitnessVersion::try_from(version).map_err(WalletError::WitnessVersion)?;
    let program = WitnessProgram::new(version, &program).map_err(WalletError::WitnessProgram)?;
    Ok(ScriptBuf::new_witness_program(&program))
}

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
