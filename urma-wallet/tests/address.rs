use bitcoin::{PubkeyHash, ScriptBuf, ScriptHash, base58, hashes::Hash};
use urma_chain::observation::Chain;
use urma_wallet::{address::destination_script, wallet::WalletError};

#[test]
fn litecoin_testnet_address_becomes_its_witness_script() {
    let expected = ScriptBuf::from_hex("0014de00894a2a77e2742acc397109b4d84f30e4c351").unwrap();
    let script = destination_script(
        "tltc1qmcqgjj32wl38g2kv89csndxcfucwfs63l7ywld",
        Chain::LitecoinTestnet,
    )
    .unwrap();
    assert_eq!(script, expected);
}

#[test]
fn litecoin_address_of_another_network_is_refused() {
    let refused = destination_script(
        "tltc1qmcqgjj32wl38g2kv89csndxcfucwfs63l7ywld",
        Chain::LitecoinMainnet,
    );
    assert!(matches!(refused, Err(WalletError::WrongNetwork)));
}

#[test]
fn corrupted_litecoin_address_is_refused() {
    let refused = destination_script(
        "tltc1qmcqgjj32wl38g2kv89csndxcfucwfs63l7ywle",
        Chain::LitecoinTestnet,
    );
    assert!(matches!(refused, Err(WalletError::LitecoinAddress { .. })));
}

#[test]
fn litecoin_legacy_addresses_map_to_their_scripts() {
    let hash = [9; 20];
    let cases = [
        (
            Chain::LitecoinMainnet,
            0x30,
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)),
        ),
        (
            Chain::LitecoinMainnet,
            0x32,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)),
        ),
        (
            Chain::LitecoinMainnet,
            0x05,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)),
        ),
        (
            Chain::LitecoinTestnet,
            0x6f,
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)),
        ),
        (
            Chain::LitecoinTestnet,
            0x3a,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)),
        ),
        (
            Chain::LitecoinTestnet,
            0xc4,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)),
        ),
    ];
    for (chain, version, expected) in cases {
        let address = base58::encode_check(&[&[version][..], &hash].concat());
        assert_eq!(destination_script(&address, chain).unwrap(), expected);
    }
    let foreign = base58::encode_check(&[&[0x6f][..], &hash].concat());
    assert!(matches!(
        destination_script(&foreign, Chain::LitecoinMainnet),
        Err(WalletError::WrongNetwork)
    ));
}

#[test]
fn bitcoin_address_must_match_the_selected_network() {
    let address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    assert!(destination_script(address, Chain::BitcoinRegtest).is_ok());
    assert!(matches!(
        destination_script(address, Chain::BitcoinTestnet4),
        Err(WalletError::AddressParse(..))
    ));
}
