use bitcoin::{ScriptBuf, WPubkeyHash, hashes::Hash};
use urma_core::envelope::{validate_reveal_scripts, validate_reveal_shape};

#[test]
fn reveal_shape_and_scripts_have_one_chain_independent_policy() {
    validate_reveal_shape(2, 1, 1).unwrap();
    for (version, inputs, outputs) in [(1, 1, 1), (2, 0, 1), (2, 2, 1), (2, 1, 0), (2, 1, 2)] {
        assert!(validate_reveal_shape(version, inputs, outputs).is_err());
    }
    let empty = ScriptBuf::new();
    let payout = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0; 20]));
    validate_reveal_scripts(&empty, &payout).unwrap();
    let taproot = ScriptBuf::from_bytes([vec![0x51, 0x20], vec![0; 32]].concat());
    validate_reveal_scripts(&empty, &taproot).unwrap();
    assert!(validate_reveal_scripts(&payout, &payout).is_err());
    assert!(validate_reveal_scripts(&empty, &empty).is_err());
}
