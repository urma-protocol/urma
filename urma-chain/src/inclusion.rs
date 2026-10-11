//! Selective transparent transaction inclusion against an externally selected header.
//!
//! These proofs do not verify proof of work, difficulty, scripts, UTXOs or MWEB
//! consensus. The supplied transaction count describes the proof geometry; it is
//! not independently committed by the header and does not prove completeness.

use crate::{
    decode::{self, DecodeError},
    observation::Chain,
    validation::{BlockValidationError, validate_block_integrity},
};
use bitcoin::{
    Block, BlockHash, Transaction, WitnessMerkleNode,
    block::Header,
    hashes::{Hash, sha256d},
};
use serde::{Deserialize, Serialize};

const MAX_TRANSACTIONS: u32 = 1_000_000;
const MAX_PATH_LEVELS: usize = 20;

/// Hashes are consensus-order byte arrays, not display-order hexadecimal IDs.
/// Every level includes a sibling, including an explicit duplicate for odd padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    pub index: u32,
    pub tx_count: u32,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionProof {
    pub transaction: Vec<u8>,
    pub txid_path: MerklePath,
    pub coinbase: Vec<u8>,
    pub coinbase_path: MerklePath,
    pub witness_path: MerklePath,
    pub coinbase_witness_path: MerklePath,
}

/// Verified inclusion, relative to the header supplied by the caller.
#[derive(Clone, Debug)]
pub struct IncludedTransaction {
    transaction: Transaction,
    raw: Vec<u8>,
    block_hash: BlockHash,
    position: u32,
}

impl IncludedTransaction {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }
    pub fn position(&self) -> u32 {
        self.position
    }
}

#[derive(Debug)]
pub enum InclusionError {
    Decode(DecodeError),
    Integrity(BlockValidationError),
    LimitExceeded,
    InvalidPath,
    InconsistentPaths,
    InvalidPadding,
    MerkleRootMismatch,
    InvalidCoinbase,
    CoinbaseTarget,
    InvalidReservedValue,
    MissingWitnessCommitment,
    WitnessRootMismatch,
    WitnessCommitmentMismatch,
}

impl std::fmt::Display for InclusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(cause) => write!(f, "decode inclusion transaction: {cause}"),
            Self::Integrity(cause) => write!(f, "proof source block integrity: {cause}"),
            Self::LimitExceeded => f.write_str("inclusion proof exceeds resource limits"),
            Self::InvalidPath => f.write_str("invalid Merkle path index, count or length"),
            Self::InconsistentPaths => {
                f.write_str("inconsistent inclusion proof positions or counts")
            }
            Self::InvalidPadding => f.write_str("odd Merkle padding must duplicate the last hash"),
            Self::MerkleRootMismatch => f.write_str("inclusion transaction Merkle root mismatch"),
            Self::InvalidCoinbase => f.write_str("inclusion proof requires a real coinbase"),
            Self::CoinbaseTarget => {
                f.write_str("inclusion target must be a noncoinbase transaction")
            }
            Self::InvalidReservedValue => {
                f.write_str("coinbase witness must contain one 32-byte reserved value")
            }
            Self::MissingWitnessCommitment => f.write_str("coinbase witness commitment absent"),
            Self::WitnessRootMismatch => {
                f.write_str("transaction and zero coinbase witness roots differ")
            }
            Self::WitnessCommitmentMismatch => f.write_str("inclusion witness commitment mismatch"),
        }
    }
}

impl std::error::Error for InclusionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(cause) => Some(cause),
            Self::Integrity(cause) => Some(cause),
            _ => None,
        }
    }
}

impl MerklePath {
    fn check(&self) -> Result<(), InclusionError> {
        if self.tx_count > MAX_TRANSACTIONS || self.siblings.len() > MAX_PATH_LEVELS {
            return Err(InclusionError::LimitExceeded);
        }
        if self.tx_count == 0 || self.index >= self.tx_count {
            return Err(InclusionError::InvalidPath);
        }
        let mut width = self.tx_count;
        let mut levels = 0;
        while width > 1 {
            width = width.div_ceil(2);
            levels += 1;
        }
        if self.siblings.len() != levels {
            return Err(InclusionError::InvalidPath);
        }
        Ok(())
    }

    fn root(&self, mut hash: [u8; 32]) -> Result<[u8; 32], InclusionError> {
        self.check()?;
        let mut index = self.index;
        let mut width = self.tx_count;
        for sibling in &self.siblings {
            if index % 2 == 0 {
                if index + 1 == width && *sibling != hash {
                    return Err(InclusionError::InvalidPadding);
                }
                hash = parent(hash, *sibling);
            } else {
                hash = parent(*sibling, hash);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        Ok(hash)
    }
}

impl TransactionProof {
    /// Verify inclusion only. The engine must select and validate `expected` externally.
    pub fn verify(
        &self,
        chain: Chain,
        expected: &Header,
    ) -> Result<IncludedTransaction, InclusionError> {
        let paths = [
            &self.txid_path,
            &self.coinbase_path,
            &self.witness_path,
            &self.coinbase_witness_path,
        ];
        for path in paths {
            path.check()?;
        }
        if paths
            .iter()
            .any(|path| path.tx_count != self.txid_path.tx_count)
            || self.txid_path.index != self.witness_path.index
            || self.coinbase_path.index != 0
            || self.coinbase_witness_path.index != 0
        {
            return Err(InclusionError::InconsistentPaths);
        }
        if self.txid_path.index == 0 {
            return Err(InclusionError::CoinbaseTarget);
        }
        let transaction =
            decode::transaction(&self.transaction, chain).map_err(InclusionError::Decode)?;
        let coinbase =
            decode::transaction(&self.coinbase, chain).map_err(InclusionError::Decode)?;
        if transaction.is_coinbase() {
            return Err(InclusionError::CoinbaseTarget);
        }
        if !coinbase.is_coinbase() {
            return Err(InclusionError::InvalidCoinbase);
        }
        let expected_root = expected.merkle_root.to_byte_array();
        if self
            .txid_path
            .root(transaction.compute_txid().to_byte_array())?
            != expected_root
            || self
                .coinbase_path
                .root(coinbase.compute_txid().to_byte_array())?
                != expected_root
        {
            return Err(InclusionError::MerkleRootMismatch);
        }
        let mut witness = coinbase.input[0].witness.iter();
        let reserved = witness.next().ok_or(InclusionError::InvalidReservedValue)?;
        if reserved.len() != 32 || witness.next().is_some() {
            return Err(InclusionError::InvalidReservedValue);
        }
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let commitment = coinbase
            .output
            .iter()
            .rev()
            .find_map(|output| {
                let script = output.script_pubkey.as_bytes();
                (script.len() >= 38 && script[..6] == MAGIC).then(|| &script[6..38])
            })
            .ok_or(InclusionError::MissingWitnessCommitment)?;
        let witness_root = self
            .witness_path
            .root(transaction.compute_wtxid().to_byte_array())?;
        if self.coinbase_witness_path.root([0; 32])? != witness_root {
            return Err(InclusionError::WitnessRootMismatch);
        }
        let computed = Block::compute_witness_commitment(
            &WitnessMerkleNode::from_byte_array(witness_root),
            reserved,
        );
        if computed.as_byte_array().as_slice() != commitment {
            return Err(InclusionError::WitnessCommitmentMismatch);
        }
        Ok(IncludedTransaction {
            transaction,
            raw: self.transaction.clone(),
            block_hash: expected.block_hash(),
            position: self.txid_path.index,
        })
    }

    /// Build paths from a complete transparent projection, preserving supplied raw bytes.
    ///
    /// Raw/projection binding is established only by `verify(chain, header)`. This
    /// builder never serializes a projection to fabricate original Litecoin bytes.
    pub fn from_block(
        block: &Block,
        position: u32,
        raw_transaction: Vec<u8>,
        raw_coinbase: Vec<u8>,
    ) -> Result<Self, InclusionError> {
        if block.txdata.len() > MAX_TRANSACTIONS as usize {
            return Err(InclusionError::LimitExceeded);
        }
        if position == 0 {
            return Err(InclusionError::CoinbaseTarget);
        }
        let target = block
            .txdata
            .get(position as usize)
            .ok_or(InclusionError::InvalidPath)?;
        if target.is_coinbase() {
            return Err(InclusionError::CoinbaseTarget);
        }
        validate_block_integrity(block, block.block_hash()).map_err(InclusionError::Integrity)?;
        let txids = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array())
            .collect::<Vec<_>>();
        let witnesses = block
            .txdata
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                if index == 0 {
                    [0; 32]
                } else {
                    tx.compute_wtxid().to_byte_array()
                }
            })
            .collect::<Vec<_>>();
        Ok(Self {
            transaction: raw_transaction,
            txid_path: build_path(txids.clone(), position),
            coinbase: raw_coinbase,
            coinbase_path: build_path(txids, 0),
            witness_path: build_path(witnesses.clone(), position),
            coinbase_witness_path: build_path(witnesses, 0),
        })
    }
}

fn parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    sha256d::Hash::hash(&bytes).to_byte_array()
}

fn build_path(mut hashes: Vec<[u8; 32]>, position: u32) -> MerklePath {
    let tx_count = hashes.len() as u32;
    let mut index = position as usize;
    let mut siblings = Vec::new();
    while hashes.len() > 1 {
        siblings.push(hashes.get(index ^ 1).copied().unwrap_or(hashes[index]));
        hashes = hashes
            .chunks(2)
            .map(|pair| parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
        index /= 2;
    }
    MerklePath {
        index: position,
        tx_count,
        siblings,
    }
}
