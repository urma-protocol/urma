use crate::error::Error;
use bitcoin::{
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    transaction::Version,
};
use urma_chain::transaction::decode_bounded;

pub(crate) fn transaction(outpoint: OutPoint, output: TxOut) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![output],
    }
}

pub(crate) fn decode(raw: &str, max_hex_bytes: usize) -> Result<Transaction, Error> {
    decode_bounded(raw, max_hex_bytes).map_err(Error::from)
}
