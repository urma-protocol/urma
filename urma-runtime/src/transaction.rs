use crate::error::Error;
use bitcoin::{
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    transaction::Version,
};
use urma_chain::transaction::decode_bounded;

pub(crate) fn transaction(outpoint: OutPoint, output: TxOut) -> Transaction {
    spending(&[outpoint], output)
}

pub(crate) fn spending(outpoints: &[OutPoint], output: TxOut) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: outpoints
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![output],
    }
}

pub(crate) fn signed_vsize(unsigned: &Transaction) -> Result<u64, Error> {
    let mut draft = unsigned.clone();
    for input in &mut draft.input {
        input.witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
    }
    Ok(u64::try_from(draft.vsize())?)
}

pub(crate) fn decode(raw: &str, max_hex_bytes: usize) -> Result<Transaction, Error> {
    decode_bounded(raw, max_hex_bytes).map_err(Error::from)
}
