use bitcoin::{OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use urma_chain::transaction::{TransactionDecodeError, decode_bounded};
use urma_core::error::{Context, Error, ensure};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Funding {
    pub raw_transaction: String,
    pub vout: u32,
}

impl Funding {
    pub fn prevout(&self) -> Result<(OutPoint, TxOut), Error> {
        let transaction = decode_bounded(&self.raw_transaction, 8_000_000).map_err(decode_error)?;
        let output = transaction
            .output
            .get(usize::try_from(self.vout)?)
            .context("funding vout is absent")?
            .clone();
        ensure!(
            output.script_pubkey.is_p2wpkh(),
            "funding requires a native P2WPKH output"
        );
        ensure!(
            output.value.to_sat() <= 21_000_000 * 100_000_000,
            "invalid funding amount"
        );
        Ok((
            OutPoint {
                txid: transaction.compute_txid(),
                vout: self.vout,
            },
            output,
        ))
    }
}

fn decode_error(cause: TransactionDecodeError) -> Error {
    match cause {
        TransactionDecodeError::LimitExceeded => Error::Invalid(cause.to_string()),
        TransactionDecodeError::Hex(cause) => Error::Hex(cause),
        TransactionDecodeError::Consensus(cause) => Error::Context {
            message: "decode transaction".into(),
            cause: Box::new(Error::Transaction(cause)),
        },
    }
}
