use bitcoin::{Network, blockdata::constants::genesis_block, consensus::serialize};
use urma_chain::transaction::{TransactionDecodeError as Error, decode_bounded};

#[test]
fn transaction_hex_limit_is_inclusive_and_checked_before_decoding() {
    let transaction = genesis_block(Network::Regtest).txdata.remove(0);
    let raw = hex::encode(serialize(&transaction));
    assert_eq!(decode_bounded(&raw, raw.len()).unwrap(), transaction);
    assert!(matches!(
        decode_bounded(&raw, raw.len() - 1),
        Err(Error::LimitExceeded)
    ));
    assert!(matches!(
        decode_bounded("not hex", 2),
        Err(Error::LimitExceeded)
    ));
}

#[test]
fn malformed_hex_and_consensus_encoding_keep_distinct_causes() {
    assert!(matches!(decode_bounded("xyz", 3), Err(Error::Hex(_))));
    assert!(matches!(decode_bounded("0", 1), Err(Error::Hex(_))));
    assert!(matches!(decode_bounded("", 0), Err(Error::Consensus(_))));
    let transaction = genesis_block(Network::Regtest).txdata.remove(0);
    let mut raw = hex::encode(serialize(&transaction));
    raw.push_str("00");
    assert!(matches!(
        decode_bounded(&raw, raw.len()),
        Err(Error::Consensus(_))
    ));
}
