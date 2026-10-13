use bitcoin::{PubkeyHash, ScriptBuf, ScriptHash, base58, hashes::Hash, hex::FromHex};
use urma_chain::observation::Chain;
use urma_wallet::{address::destination_script, wallet::WalletError};

const GENESIS_HASH: &str = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18";

fn hash() -> [u8; 20] {
    <[u8; 20]>::from_hex(GENESIS_HASH).unwrap()
}

fn legacy(version: u8, payload: &[u8]) -> String {
    base58::encode_check(&[&[version][..], payload].concat())
}

fn p2pkh() -> ScriptBuf {
    ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash()))
}

fn p2sh() -> ScriptBuf {
    ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash()))
}

#[test]
fn bitcoin_legacy_destinations_are_unchanged() {
    assert_eq!(legacy(0x00, &hash()), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    assert_eq!(
        destination_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Chain::BitcoinMainnet).unwrap(),
        p2pkh()
    );
    assert_eq!(
        destination_script(&legacy(0x05, &hash()), Chain::BitcoinMainnet).unwrap(),
        p2sh()
    );
    for chain in [Chain::BitcoinTestnet4, Chain::BitcoinRegtest] {
        assert_eq!(
            destination_script(&legacy(0x6f, &hash()), chain).unwrap(),
            p2pkh()
        );
        assert_eq!(
            destination_script(&legacy(0xc4, &hash()), chain).unwrap(),
            p2sh()
        );
    }
}

#[test]
fn bitcoin_refuses_litecoin_only_versions_and_prefixes() {
    for version in [0x30, 0x32] {
        assert!(matches!(
            destination_script(&legacy(version, &hash()), Chain::BitcoinMainnet),
            Err(WalletError::AddressParse(_))
        ));
    }
    assert!(matches!(
        destination_script(&legacy(0x3a, &hash()), Chain::BitcoinTestnet4),
        Err(WalletError::AddressParse(_))
    ));
    assert!(matches!(
        destination_script(
            "ltc1q6hku5at2sfjdv3444y4r4a8slaa0q8zcpm0u5n",
            Chain::BitcoinMainnet
        ),
        Err(WalletError::AddressParse(_))
    ));
    assert!(matches!(
        destination_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Chain::BitcoinRegtest),
        Err(WalletError::AddressParse(_))
    ));
}

#[test]
fn litecoin_refuses_foreign_legacy_versions() {
    for version in [0x00, 0x6f, 0x3a, 0xc4] {
        assert!(matches!(
            destination_script(&legacy(version, &hash()), Chain::LitecoinMainnet),
            Err(WalletError::WrongNetwork)
        ));
    }
    for version in [0x00, 0x30, 0x32, 0x05] {
        assert!(matches!(
            destination_script(&legacy(version, &hash()), Chain::LitecoinTestnet),
            Err(WalletError::WrongNetwork)
        ));
    }
}

#[test]
fn litecoin_refuses_malformed_legacy_payloads() {
    let chain = Chain::LitecoinMainnet;
    let long = legacy(0x30, &[hash().as_slice(), &[0]].concat());
    assert!(matches!(
        destination_script(&long, chain),
        Err(WalletError::WrongNetwork)
    ));
    let short = legacy(0x30, &hash()[..19]);
    assert!(matches!(
        destination_script(&short, chain),
        Err(WalletError::WrongNetwork)
    ));
    let mut corrupted = legacy(0x30, &hash());
    let last = corrupted.pop().unwrap();
    corrupted.push(if last == '1' { '2' } else { '1' });
    assert!(matches!(
        destination_script(&corrupted, chain),
        Err(WalletError::LitecoinAddress { .. })
    ));
    assert!(matches!(
        destination_script("bc1qdsdxmlnu5phmwaw9fy88vm57n552l9ztcg4rev", chain),
        Err(WalletError::WrongNetwork)
    ));
}
