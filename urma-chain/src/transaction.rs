use bitcoin::{Transaction, consensus::deserialize};

#[derive(Debug)]
pub enum TransactionDecodeError {
    LimitExceeded,
    Hex(hex::FromHexError),
    Consensus(bitcoin::consensus::encode::Error),
}

impl std::fmt::Display for TransactionDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded => f.write_str("raw transaction exceeds byte limit"),
            Self::Hex(cause) => std::fmt::Display::fmt(cause, f),
            Self::Consensus(cause) => write!(f, "decode transaction: {cause}"),
        }
    }
}

impl std::error::Error for TransactionDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LimitExceeded => None,
            Self::Hex(cause) => Some(cause),
            Self::Consensus(cause) => Some(cause),
        }
    }
}

pub fn decode_bounded(
    raw: &str,
    max_hex_bytes: usize,
) -> Result<Transaction, TransactionDecodeError> {
    if raw.len() > max_hex_bytes {
        return Err(TransactionDecodeError::LimitExceeded);
    }
    let bytes = hex::decode(raw).map_err(TransactionDecodeError::Hex)?;
    deserialize(&bytes).map_err(TransactionDecodeError::Consensus)
}
