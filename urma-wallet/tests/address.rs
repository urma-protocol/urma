use bitcoin::ScriptBuf;
use urma_chain::observation::Chain;
use urma_wallet::{address::destination_script, wallet::WalletError};

#[test]
fn litecoin_testnet_address_becomes_its_witness_script() {
    let expected =
        ScriptBuf::from_hex("0014de00894a2a77e2742acc397109b4d84f30e4c351").unwrap();
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
    assert!(matches!(refused, Err(WalletError::AddressDecoding(..))));
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
