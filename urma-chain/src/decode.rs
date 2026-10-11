use crate::observation::Chain;
use crate::validation::{BlockValidationError, validate_block_integrity};
use bitcoin::{
    Block, BlockHash, Transaction,
    consensus::{deserialize, deserialize_partial},
};
use litecoin::block::MwebBlock;
use litecoin::consensus::{Decodable, Encodable, serialize};

#[derive(Clone, Copy)]
enum Encoding {
    Core,
    Esplora,
}

/// An integrity-checked transparent block projection with its original
/// transaction encodings, in the same order as `Block::txdata`.
///
/// Litecoin HogEx metadata is retained in the raw transactions, even though it
/// is stripped from the transparent projection. The block extension suffix is
/// not part of any transaction. Extension parsing does not validate MWEB consensus.
#[derive(Debug)]
pub struct DecodedBlock {
    block: Block,
    raw_transactions: Vec<Vec<u8>>,
}

impl DecodedBlock {
    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn raw_transactions(&self) -> &[Vec<u8>] {
        &self.raw_transactions
    }

    pub fn into_parts(self) -> (Block, Vec<Vec<u8>>) {
        (self.block, self.raw_transactions)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    LimitExceeded,
    Bitcoin(bitcoin::consensus::encode::Error),
    Litecoin(litecoin::consensus::encode::Error),
    Integrity(BlockValidationError),
    NonCanonical,
    UnsupportedMwebTransaction,
    InvalidHogEx,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded => {
                f.write_str("raw chain data exceeds 8,000,000 byte client limit")
            }
            Self::Bitcoin(cause) => write!(f, "decode Bitcoin data: {cause}"),
            Self::Litecoin(cause) => write!(f, "decode Litecoin data: {cause}"),
            Self::Integrity(cause) => std::fmt::Display::fmt(cause, f),
            Self::NonCanonical => f.write_str("noncanonical or trailing chain data"),
            Self::UnsupportedMwebTransaction => {
                f.write_str("embedded confidential MWEB transactions are unsupported")
            }
            Self::InvalidHogEx => f.write_str("invalid HogEx placement"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bitcoin(cause) => Some(cause),
            Self::Litecoin(cause) => Some(cause),
            Self::Integrity(cause) => Some(cause),
            _ => None,
        }
    }
}

pub fn block(raw: &[u8], chain: Chain, expected_hash: BlockHash) -> Result<Block, DecodeError> {
    block_with_transactions(raw, chain, expected_hash).map(|decoded| decoded.block)
}

pub fn esplora_block(
    raw: &[u8],
    chain: Chain,
    expected_hash: BlockHash,
) -> Result<Block, DecodeError> {
    esplora_block_with_transactions(raw, chain, expected_hash).map(|decoded| decoded.block)
}

/// Decodes strict Core block encoding and retains each original transaction.
pub fn block_with_transactions(
    raw: &[u8],
    chain: Chain,
    expected_hash: BlockHash,
) -> Result<DecodedBlock, DecodeError> {
    decode_block(raw, chain, expected_hash, Encoding::Core)
}

/// Decodes Esplora block encoding and retains each original transaction.
pub fn esplora_block_with_transactions(
    raw: &[u8],
    chain: Chain,
    expected_hash: BlockHash,
) -> Result<DecodedBlock, DecodeError> {
    decode_block(raw, chain, expected_hash, Encoding::Esplora)
}

fn decode_block(
    raw: &[u8],
    chain: Chain,
    expected_hash: BlockHash,
    encoding: Encoding,
) -> Result<DecodedBlock, DecodeError> {
    bounded(raw)?;
    let block = match chain {
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => bitcoin_decoded_block(raw)?,
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => litecoin_block(raw, encoding)?,
    };
    validate_block_integrity(block.block(), expected_hash).map_err(DecodeError::Integrity)?;
    Ok(block)
}

fn bitcoin_decoded_block(raw: &[u8]) -> Result<DecodedBlock, DecodeError> {
    // Keep the existing whole-block decoder and its EOF/error semantics. The
    // second pass measures consumed spans rather than serializing the projection.
    let block: Block = deserialize(raw).map_err(DecodeError::Bitcoin)?;
    let mut remaining = &raw[bitcoin::block::Header::SIZE..];
    let (_, prefix_bytes) = deserialize_partial::<bitcoin::consensus::encode::VarInt>(remaining)
        .map_err(DecodeError::Bitcoin)?;
    remaining = &remaining[prefix_bytes..];
    let mut raw_transactions = Vec::new();
    for _tx in &block.txdata {
        let (_, consumed) =
            deserialize_partial::<Transaction>(remaining).map_err(DecodeError::Bitcoin)?;
        raw_transactions.push(remaining[..consumed].to_vec());
        remaining = &remaining[consumed..];
    }
    Ok(DecodedBlock {
        block,
        raw_transactions,
    })
}

pub fn bitcoin_block(raw: &[u8], expected_hash: BlockHash) -> Result<Block, DecodeError> {
    block(raw, Chain::BitcoinRegtest, expected_hash)
}

pub fn transaction(raw: &[u8], chain: Chain) -> Result<Transaction, DecodeError> {
    bounded(raw)?;
    match chain {
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => {
            deserialize(raw).map_err(DecodeError::Bitcoin)
        }
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => {
            let mut remaining = raw;
            let tx = canonical::<litecoin::Transaction>(&mut remaining)?;
            finished(remaining)?;
            transparent(tx)
        }
    }
}

fn bounded(raw: &[u8]) -> Result<(), DecodeError> {
    if raw.len() > 8_000_000 {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(())
}

fn canonical<T: Decodable + Encodable>(remaining: &mut &[u8]) -> Result<T, DecodeError> {
    let before = *remaining;
    let value = T::consensus_decode_from_finite_reader(remaining).map_err(DecodeError::Litecoin)?;
    if serialize(&value) != before[..before.len() - remaining.len()] {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn finished(remaining: &[u8]) -> Result<(), DecodeError> {
    if !remaining.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn transparent(mut tx: litecoin::Transaction) -> Result<Transaction, DecodeError> {
    if tx.mw_tx.iter().count() != 0 || tx.input.is_empty() {
        return Err(DecodeError::UnsupportedMwebTransaction);
    }
    tx.is_hog_ex = false;
    deserialize(&serialize(&tx)).map_err(DecodeError::Bitcoin)
}

fn litecoin_block(raw: &[u8], encoding: Encoding) -> Result<DecodedBlock, DecodeError> {
    let mut remaining = raw;
    let header = canonical::<litecoin::block::Header>(&mut remaining)?;
    let transactions_start = remaining;
    let transactions = canonical::<Vec<litecoin::Transaction>>(&mut remaining)?;
    let mut transaction_bytes = &transactions_start[..transactions_start.len() - remaining.len()];
    canonical::<litecoin::consensus::encode::VarInt>(&mut transaction_bytes)?;
    let count = transactions.len();
    let mut txdata = Vec::new();
    let mut raw_transactions = Vec::new();
    for (index, tx) in transactions.into_iter().enumerate() {
        // The canonical vector check already proved these original Litecoin
        // encodings byte-identical to the consumed span. Use their lengths only
        // to split the original bytes, before `transparent` strips HogEx metadata.
        let length = serialize(&tx).len();
        raw_transactions.push(transaction_bytes[..length].to_vec());
        transaction_bytes = &transaction_bytes[length..];
        if tx.is_hog_ex {
            if index == 0 || index + 1 != count {
                return Err(DecodeError::InvalidHogEx);
            }
            if !remaining.is_empty() || matches!(encoding, Encoding::Core) {
                match canonical::<u8>(&mut remaining)? {
                    0 => (),
                    1 => {
                        canonical::<MwebBlock>(&mut remaining)?;
                    }
                    _ => return Err(DecodeError::NonCanonical),
                }
            }
        }
        txdata.push(transparent(tx)?);
    }
    finished(remaining)?;
    Ok(DecodedBlock {
        block: Block {
            header: deserialize(&serialize(&header)).map_err(DecodeError::Bitcoin)?,
            txdata,
        },
        raw_transactions,
    })
}
