use crate::wallet::WalletError;
use bech32::{Hrp, segwit};
use bitcoin::{
    Address, CompressedPublicKey, Network, PubkeyHash, ScriptBuf, ScriptHash, WitnessProgram,
    WitnessVersion, base58, hashes::Hash,
};
use std::str::FromStr;
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;

pub fn destination_script(address: &str, chain: Chain) -> Result<ScriptBuf, WalletError> {
    match chain {
        Chain::BitcoinMainnet => bitcoin_script(address, Network::Bitcoin),
        Chain::BitcoinRegtest => bitcoin_script(address, Network::Regtest),
        Chain::BitcoinTestnet4 => bitcoin_script(address, Network::Testnet4),
        Chain::LitecoinMainnet => litecoin_script(address, "ltc", &Legacy::MAINNET),
        Chain::LitecoinTestnet => litecoin_script(address, "tltc", &Legacy::TESTNET),
    }
}

struct Legacy {
    key_hash: u8,
    script_hash: [u8; 2],
}

impl Legacy {
    const MAINNET: Legacy = Legacy {
        key_hash: 0x30,
        script_hash: [0x32, 0x05],
    };
    const TESTNET: Legacy = Legacy {
        key_hash: 0x6f,
        script_hash: [0x3a, 0xc4],
    };
}

fn legacy_script(payload: &[u8], versions: &Legacy) -> Result<ScriptBuf, WalletError> {
    if payload.len() != 21 {
        return Err(WalletError::WrongNetwork);
    }
    let Some(&[version, ref hash @ ..]) = payload.first_chunk::<21>() else {
        return Err(WalletError::WrongNetwork);
    };
    if version == versions.key_hash {
        return Ok(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(*hash)));
    }
    if versions.script_hash.contains(&version) {
        return Ok(ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(*hash)));
    }
    Err(WalletError::WrongNetwork)
}

fn bitcoin_script(address: &str, network: Network) -> Result<ScriptBuf, WalletError> {
    Ok(Address::from_str(address)
        .map_err(WalletError::AddressParse)?
        .require_network(network)
        .map_err(WalletError::AddressParse)?
        .script_pubkey())
}

fn litecoin_script(address: &str, prefix: &str, legacy: &Legacy) -> Result<ScriptBuf, WalletError> {
    let (hrp, version, program) = match segwit::decode(address) {
        Ok(decoded) => decoded,
        Err(segwit_cause) => {
            return match base58::decode_check(address) {
                Ok(payload) => legacy_script(&payload, legacy),
                Err(base58_cause) => Err(WalletError::LitecoinAddress {
                    bech32: segwit_cause,
                    legacy: base58_cause,
                }),
            };
        }
    };
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
        Chain::BitcoinMainnet => Ok(Address::p2wpkh(&public, Network::Bitcoin).to_string()),
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
