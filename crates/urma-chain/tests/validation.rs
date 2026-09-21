use bitcoin::{
    Amount, BlockHash, CompactTarget, Network, Witness, blockdata::constants::genesis_block,
    hashes::Hash,
};
use urma_chain::validation::{
    BlockValidationError, validate_block, validate_block_for_network, validate_block_integrity,
};

#[test]
fn genesis_blocks_validate_on_supported_networks() {
    for network in [Network::Regtest, Network::Testnet4] {
        let block = genesis_block(network);
        validate_block(&block, block.block_hash()).unwrap();
        validate_block_for_network(&block, block.block_hash(), network).unwrap();
    }
}

#[test]
fn network_policy_precedes_bitcoin_block_validation() {
    let block = genesis_block(Network::Regtest);
    for network in [Network::Bitcoin, Network::Testnet, Network::Signet] {
        assert!(matches!(
            validate_block_for_network(&block, block.block_hash(), network),
            Err(BlockValidationError::UnsupportedNetwork)
        ));
    }
    assert!(matches!(
        validate_block_for_network(&block, block.block_hash(), Network::Testnet4),
        Err(BlockValidationError::TargetLimit)
    ));
}

#[test]
fn hash_merkle_witness_and_proof_of_work_fail_independently() {
    let original = genesis_block(Network::Regtest);
    assert!(matches!(
        validate_block(&original, BlockHash::all_zeros()),
        Err(BlockValidationError::HashMismatch)
    ));
    let mut block = original.clone();
    block.txdata[0].output[0].value = Amount::from_sat(1);
    assert!(matches!(
        validate_block(&block, block.block_hash()),
        Err(BlockValidationError::MerkleRootMismatch)
    ));
    let mut block = original.clone();
    block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
    assert!(matches!(
        validate_block(&block, block.block_hash()),
        Err(BlockValidationError::WitnessCommitmentMismatch)
    ));
    let mut block = original;
    block.header.bits = CompactTarget::from_consensus(0);
    assert!(matches!(
        validate_block(&block, block.block_hash()),
        Err(BlockValidationError::ProofOfWork(_))
    ));
}

#[test]
fn integrity_does_not_apply_bitcoin_proof_of_work_policy() {
    let mut block = genesis_block(Network::Regtest);
    block.header.bits = CompactTarget::from_consensus(0);
    validate_block_integrity(&block, block.block_hash()).unwrap();
    assert!(matches!(
        validate_block(&block, block.block_hash()),
        Err(BlockValidationError::ProofOfWork(_))
    ));
    block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
    assert!(matches!(
        validate_block_integrity(&block, block.block_hash()),
        Err(BlockValidationError::WitnessCommitmentMismatch)
    ));
}

#[test]
fn witness_mutation_is_detected_even_when_transaction_merkle_root_matches() {
    let mut block = genesis_block(Network::Regtest);
    block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
    let commitment =
        bitcoin::Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block.txdata[0].input[0].witness = Witness::from_slice(&[vec![1; 32]]);
    assert!(block.check_merkle_root());
    assert!(matches!(
        validate_block_integrity(&block, block.block_hash()),
        Err(BlockValidationError::WitnessCommitmentMismatch)
    ));
}
