use bitcoin::{Block, BlockHash, Network, hashes::Hash};

#[derive(Debug)]
pub enum BlockValidationError {
    HashMismatch,
    MerkleRootMismatch,
    WitnessCommitmentMismatch,
    ProofOfWork(bitcoin::block::ValidationError),
    UnsupportedNetwork,
    TargetLimit,
}

impl std::fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch => f.write_str("block hash mismatch"),
            Self::MerkleRootMismatch => f.write_str("transaction Merkle root mismatch"),
            Self::WitnessCommitmentMismatch => f.write_str("witness commitment mismatch"),
            Self::ProofOfWork(cause) => write!(f, "block proof of work: {cause}"),
            Self::UnsupportedNetwork => f.write_str("only regtest and testnet4 are supported"),
            Self::TargetLimit => f.write_str("block target exceeds network proof-of-work limit"),
        }
    }
}

impl std::error::Error for BlockValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProofOfWork(cause) => Some(cause),
            _ => None,
        }
    }
}

pub fn validate_block_integrity(
    block: &Block,
    expected_hash: BlockHash,
) -> Result<(), BlockValidationError> {
    if block.block_hash() != expected_hash {
        return Err(BlockValidationError::HashMismatch);
    }
    if !block.check_merkle_root() {
        return Err(BlockValidationError::MerkleRootMismatch);
    }
    if !check_witness_commitment(block) {
        return Err(BlockValidationError::WitnessCommitmentMismatch);
    }
    Ok(())
}

fn check_witness_commitment(block: &Block) -> bool {
    let Some(coinbase) = block.txdata.first() else {
        return false;
    };
    let commitment = coinbase.output.iter().rfind(|output| {
        let script = output.script_pubkey.as_bytes();
        script.len() >= 38 && script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
    });
    match commitment {
        Some(output) => {
            if !coinbase.is_coinbase() {
                return false;
            }
            let witness = &coinbase.input[0].witness;
            if witness.len() != 1 {
                return false;
            }
            let Some(reserved) = witness.iter().next() else {
                return false;
            };
            if reserved.len() != 32 {
                return false;
            }
            let Some(root) = block.witness_root() else {
                return false;
            };
            let expected = Block::compute_witness_commitment(&root, reserved);
            output.script_pubkey.as_bytes()[6..38] == expected.as_byte_array()[..]
        }
        None => block
            .txdata
            .iter()
            .all(|tx| tx.input.iter().all(|input| input.witness.is_empty())),
    }
}

pub fn validate_block(block: &Block, expected_hash: BlockHash) -> Result<(), BlockValidationError> {
    validate_block_integrity(block, expected_hash)?;
    block
        .header
        .validate_pow(block.header.target())
        .map_err(BlockValidationError::ProofOfWork)?;
    Ok(())
}

pub fn validate_block_for_network(
    block: &Block,
    expected_hash: BlockHash,
    network: Network,
) -> Result<(), BlockValidationError> {
    if !matches!(network, Network::Regtest | Network::Testnet4) {
        return Err(BlockValidationError::UnsupportedNetwork);
    }
    if block.header.target() > network.params().max_attainable_target {
        return Err(BlockValidationError::TargetLimit);
    }
    validate_block(block, expected_hash)
}
