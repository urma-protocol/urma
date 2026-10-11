use bitcoin::{
    Amount, BlockHash, CompactTarget, Network, Witness, blockdata::constants::genesis_block,
    hashes::Hash,
};
use urma_chain::validation::{
    BlockValidationError, validate_block, validate_block_for_network, validate_block_integrity,
};

fn block_with_witness_commitment() -> bitcoin::Block {
    let mut block = genesis_block(Network::Regtest);
    let mut spend = block.txdata[0].clone();
    spend.input[0].previous_output = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
    spend.input[0].script_sig = bitcoin::ScriptBuf::new();
    spend.input[0].witness = Witness::from_slice(&[vec![42; 64]]);
    block.txdata.push(spend);
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
    block
}

#[test]
fn stripping_every_witness_is_rejected_without_changing_txids_or_header() {
    let original = block_with_witness_commitment();
    let expected_hash = original.block_hash();
    validate_block_integrity(&original, expected_hash).unwrap();
    let txids: Vec<_> = original.txdata.iter().map(|tx| tx.compute_txid()).collect();
    let mut stripped = original.clone();
    for transaction in &mut stripped.txdata {
        for input in &mut transaction.input {
            input.witness = Witness::new();
        }
    }
    assert_eq!(stripped.header, original.header);
    assert_eq!(stripped.block_hash(), expected_hash);
    assert_eq!(
        stripped
            .txdata
            .iter()
            .map(|tx| tx.compute_txid())
            .collect::<Vec<_>>(),
        txids
    );
    assert!(stripped.check_merkle_root());
    let result = validate_block_integrity(&stripped, expected_hash);
    assert!(
        matches!(result, Err(BlockValidationError::WitnessCommitmentMismatch)),
        "stripped witness result: {result:?}"
    );
}

#[test]
fn commitment_requires_exactly_one_32_byte_coinbase_reserved_value() {
    let original = block_with_witness_commitment();
    for values in [
        vec![],
        vec![vec![]],
        vec![vec![0; 31]],
        vec![vec![0; 33]],
        vec![vec![0; 32], vec![0; 32]],
        vec![vec![0; 32], vec![]],
        vec![vec![1; 32]],
    ] {
        let mut block = original.clone();
        block.txdata[0].input[0].witness = Witness::from_slice(&values);
        assert!(block.check_merkle_root());
        assert!(matches!(
            validate_block_integrity(&block, original.block_hash()),
            Err(BlockValidationError::WitnessCommitmentMismatch)
        ));
    }
}

#[test]
fn commitment_checks_the_root_even_without_non_coinbase_witness() {
    let mut block = block_with_witness_commitment();
    block.txdata[1].input[0].witness = Witness::new();
    assert!(block.check_merkle_root());
    assert!(matches!(
        validate_block_integrity(&block, block.block_hash()),
        Err(BlockValidationError::WitnessCommitmentMismatch)
    ));
    let commitment =
        bitcoin::Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.last_mut().unwrap().script_pubkey =
        bitcoin::ScriptBuf::from_bytes(script);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
}

#[test]
fn highest_matching_commitment_output_wins_and_allows_trailing_bytes() {
    let mut block = block_with_witness_commitment();
    let mut valid = block.txdata[0].output.last().unwrap().clone();
    let mut invalid_script = valid.script_pubkey.as_bytes().to_vec();
    invalid_script[6] ^= 1;
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(invalid_script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert!(matches!(
        validate_block_integrity(&block, block.block_hash()),
        Err(BlockValidationError::WitnessCommitmentMismatch)
    ));
    let mut valid_script = valid.script_pubkey.as_bytes().to_vec();
    valid_script.extend_from_slice(&[0x51, 0x00]);
    valid.script_pubkey = bitcoin::ScriptBuf::from_bytes(valid_script);
    let short_script = valid.script_pubkey.as_bytes()[..37].to_vec();
    block.txdata[0].output.push(valid);
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(short_script),
    });
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
}

#[test]
fn no_commitment_requires_every_witness_to_be_empty() {
    let mut block = block_with_witness_commitment();
    block.txdata[0].output.pop();
    for transaction in &mut block.txdata {
        for input in &mut transaction.input {
            input.witness = Witness::new();
        }
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    for transaction in 0..block.txdata.len() {
        let mut with_witness = block.clone();
        with_witness.txdata[transaction].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
        assert!(with_witness.check_merkle_root());
        assert!(matches!(
            validate_block_integrity(&with_witness, block.block_hash()),
            Err(BlockValidationError::WitnessCommitmentMismatch)
        ));
    }
}

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
