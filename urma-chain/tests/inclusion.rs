use bitcoin::{
    Amount, Block, Network, OutPoint, ScriptBuf, Transaction, Txid, Witness,
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use urma_chain::{
    decode,
    inclusion::{InclusionError, TransactionProof},
    observation::Chain,
};

fn commitment_script(block: &Block) -> ScriptBuf {
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut bytes = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    bytes.extend_from_slice(commitment.as_byte_array());
    ScriptBuf::from_bytes(bytes)
}

fn block(count: usize) -> Block {
    let mut block = genesis_block(Network::Regtest);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    for index in 1..count {
        let mut transaction = block.txdata[0].clone();
        transaction.input[0].previous_output = OutPoint {
            txid: Txid::from_byte_array([index as u8; 32]),
            vout: 0,
        };
        transaction.input[0].witness = Witness::from_slice(&[vec![index as u8; 3]]);
        block.txdata.push(transaction);
    }
    let script_pubkey = commitment_script(&block);
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey,
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    // Inclusion deliberately does not apply proof-of-work or consensus policy.
    block.header.bits = bitcoin::CompactTarget::from_consensus(0);
    block
}

fn proof(block: &Block, position: u32) -> TransactionProof {
    TransactionProof::from_block(
        block,
        position,
        serialize(&block.txdata[position as usize]),
        serialize(&block.txdata[0]),
    )
    .unwrap()
}

// The two-transaction tree permits changing coinbase non-witness bytes while
// updating its authenticated TXID, without a second implementation of path building.
fn replace_coinbase(block: &mut Block, proof: &mut TransactionProof, coinbase: Transaction) {
    assert_eq!(block.txdata.len(), 2);
    proof.txid_path.siblings[0] = coinbase.compute_txid().to_byte_array();
    proof.coinbase = serialize(&coinbase);
    block.txdata[0] = coinbase;
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

#[test]
fn bitcoin_inclusion_preserves_bytes_and_handles_odd_padding_at_multiple_levels() {
    for count in [2, 3, 5, 7, 9] {
        let block = block(count);
        for position in 1..count as u32 {
            let proof = proof(&block, position);
            let included = proof.verify(Chain::BitcoinRegtest, &block.header).unwrap();
            assert_eq!(included.transaction(), &block.txdata[position as usize]);
            assert_eq!(included.raw(), serialize(included.transaction()));
            assert_eq!(included.block_hash(), block.block_hash());
            assert_eq!(included.position(), position);
        }
    }
}

#[test]
fn witness_mutation_with_same_txid_and_builder_raw_mismatch_are_rejected() {
    let block = block(3);
    let mut altered = block.txdata[1].clone();
    altered.input[0].witness = Witness::from_slice(&[b"changed witness"]);
    assert_eq!(altered.compute_txid(), block.txdata[1].compute_txid());
    assert_ne!(altered.compute_wtxid(), block.txdata[1].compute_wtxid());
    let proof =
        TransactionProof::from_block(&block, 1, serialize(&altered), serialize(&block.txdata[0]))
            .unwrap();
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::WitnessRootMismatch)
    ));
    let proof = TransactionProof::from_block(
        &block,
        1,
        serialize(&block.txdata[2]),
        serialize(&block.txdata[0]),
    )
    .unwrap();
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::MerkleRootMismatch)
    ));
    let proof =
        TransactionProof::from_block(&block, 1, vec![1], serialize(&block.txdata[0])).unwrap();
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::Decode(_))
    ));
}

#[test]
fn coinbase_and_expected_header_must_be_authenticated() {
    let block = block(3);
    let mut proof = proof(&block, 1);
    let mut coinbase: Transaction = deserialize(&proof.coinbase).unwrap();
    coinbase.output[0].value = Amount::from_sat(1);
    proof.coinbase = serialize(&coinbase);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::MerkleRootMismatch)
    ));
    proof.coinbase = serialize(&block.txdata[1]);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::InvalidCoinbase)
    ));
    proof.coinbase = serialize(&block.txdata[0]);
    let mut header = block.header;
    header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &header),
        Err(InclusionError::MerkleRootMismatch)
    ));
}

#[test]
fn positions_counts_lengths_and_hashes_are_checked() {
    let block = block(5);
    let original = proof(&block, 4);
    let mut changed = original.clone();
    changed.witness_path.index = 3;
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::InconsistentPaths)
    ));
    for witness in [false, true] {
        let mut changed = original.clone();
        let path = if witness {
            &mut changed.coinbase_witness_path
        } else {
            &mut changed.coinbase_path
        };
        path.index = 1;
        assert!(matches!(
            changed.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::InconsistentPaths)
        ));
    }
    let mut changed = original.clone();
    changed.coinbase_witness_path.tx_count = 6;
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::InconsistentPaths)
    ));
    for count in [0, 4] {
        let mut changed = original.clone();
        changed.txid_path.tx_count = count;
        assert!(matches!(
            changed.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::InvalidPath)
        ));
    }
    for extra in [false, true] {
        let mut changed = original.clone();
        if extra {
            changed.witness_path.siblings.push([0; 32]);
        } else {
            changed.witness_path.siblings.pop().unwrap();
        }
        assert!(matches!(
            changed.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::InvalidPath)
        ));
    }
    for level in [0, 1] {
        let mut changed = original.clone();
        changed.txid_path.siblings[level][0] ^= 1;
        assert!(matches!(
            changed.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::InvalidPadding)
        ));
    }
    let mut changed = original.clone();
    changed.coinbase_witness_path.siblings[0][0] ^= 1;
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::WitnessRootMismatch)
    ));
    let mut changed = proof(&block, 1);
    changed.txid_path.index = 2;
    changed.witness_path.index = 2;
    assert!(
        changed
            .verify(Chain::BitcoinRegtest, &block.header)
            .is_err()
    );
}

#[test]
fn coinbase_zero_witness_leaf_is_proved_explicitly() {
    let block = block(2);
    let mut proof = proof(&block, 1);
    // This makes the target path claim a real coinbase WTXID instead of zero.
    proof.witness_path.siblings[0] = block.txdata[0].compute_wtxid().to_byte_array();
    assert_ne!(proof.witness_path.siblings[0], [0; 32]);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::WitnessRootMismatch)
    ));
}

#[test]
fn reserved_value_must_be_one_item_of_32_bytes_and_match_commitment() {
    let block = block(2);
    for items in [
        vec![],
        vec![vec![0; 31]],
        vec![vec![0; 33]],
        vec![vec![0; 32], vec![]],
    ] {
        let mut proof = proof(&block, 1);
        let mut coinbase = block.txdata[0].clone();
        coinbase.input[0].witness = Witness::from_slice(&items);
        proof.coinbase = serialize(&coinbase);
        assert!(matches!(
            proof.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::InvalidReservedValue)
        ));
    }
    let mut proof = proof(&block, 1);
    let mut coinbase = block.txdata[0].clone();
    coinbase.input[0].witness = Witness::from_slice(&[[1; 32]]);
    proof.coinbase = serialize(&coinbase);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::WitnessCommitmentMismatch)
    ));
}

#[test]
fn last_matching_commitment_wins_and_trailing_script_bytes_are_allowed() {
    let mut block = block(2);
    let valid = block.txdata[0].output.last().unwrap().clone();
    let mut incorrect = valid.clone();
    let mut bytes = incorrect.script_pubkey.clone().into_bytes();
    bytes[6] ^= 1;
    incorrect.script_pubkey = ScriptBuf::from_bytes(bytes);
    block.txdata[0].output.insert(0, incorrect.clone());
    let mut bytes = valid.script_pubkey.into_bytes();
    bytes.extend_from_slice(&[0x51, 0x52]);
    block.txdata[0].output.last_mut().unwrap().script_pubkey = ScriptBuf::from_bytes(bytes);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let mut proof = proof(&block, 1);
    proof.verify(Chain::BitcoinRegtest, &block.header).unwrap();
    let mut coinbase = block.txdata[0].clone();
    coinbase.output.push(incorrect);
    replace_coinbase(&mut block, &mut proof, coinbase);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::WitnessCommitmentMismatch)
    ));
    assert!(matches!(
        TransactionProof::from_block(&block, 1, proof.transaction.clone(), proof.coinbase.clone()),
        Err(InclusionError::Integrity(_))
    ));
    let mut coinbase = block.txdata[0].clone();
    coinbase.output.clear();
    replace_coinbase(&mut block, &mut proof, coinbase);
    assert!(matches!(
        proof.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::MissingWitnessCommitment)
    ));
}

#[test]
fn resource_limits_and_coinbase_target_are_rejected() {
    let block = block(2);
    let original = proof(&block, 1);
    let mut changed = original.clone();
    changed.txid_path.tx_count = 1_000_001;
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::LimitExceeded)
    ));
    let mut changed = original.clone();
    changed.coinbase_witness_path.siblings = vec![[0; 32]; 21];
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::LimitExceeded)
    ));
    for target in [false, true] {
        let mut changed = original.clone();
        if target {
            changed.transaction = vec![0; 8_000_001];
        } else {
            changed.coinbase = vec![0; 8_000_001];
        }
        assert!(matches!(
            changed.verify(Chain::BitcoinRegtest, &block.header),
            Err(InclusionError::Decode(decode::DecodeError::LimitExceeded))
        ));
    }
    let mut changed = original.clone();
    changed.txid_path.index = 0;
    changed.witness_path.index = 0;
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::CoinbaseTarget)
    ));
    let mut changed = original.clone();
    changed.transaction = changed.coinbase.clone();
    assert!(matches!(
        changed.verify(Chain::BitcoinRegtest, &block.header),
        Err(InclusionError::CoinbaseTarget)
    ));
    assert!(matches!(
        TransactionProof::from_block(&block, 0, vec![], vec![]),
        Err(InclusionError::CoinbaseTarget)
    ));
    assert!(matches!(
        TransactionProof::from_block(&block, 2, vec![], vec![]),
        Err(InclusionError::InvalidPath)
    ));
}

#[test]
fn builder_refuses_invalid_complete_block_integrity() {
    let original = block(2);
    for witness in [false, true] {
        let mut block = original.clone();
        if witness {
            block.txdata[1].input[0].witness = Witness::from_slice(&[[8; 32]]);
        } else {
            block.txdata[1].output[0].value = Amount::ZERO;
        }
        assert!(matches!(
            TransactionProof::from_block(
                &block,
                1,
                serialize(&block.txdata[1]),
                serialize(&block.txdata[0])
            ),
            Err(InclusionError::Integrity(_))
        ));
    }
}

#[test]
fn supplied_count_is_geometry_and_does_not_prove_completeness() {
    let block = block(3);
    let mut proof = proof(&block, 1);
    // Three leaves and four leaves with the last duplicated share a root.
    for path in [
        &mut proof.txid_path,
        &mut proof.coinbase_path,
        &mut proof.witness_path,
        &mut proof.coinbase_witness_path,
    ] {
        path.tx_count = 4;
    }
    proof.verify(Chain::BitcoinRegtest, &block.header).unwrap();
}

#[test]
fn real_litecoin_fixture_preserves_raw_transparent_and_hogex_bytes() {
    use litecoin::consensus::Decodable;
    let raw = include_bytes!("../../tests/vectors/litecoin-mweb/block-4892705.bin");
    let hash = "2b70f30e5c2a5e9e8510cc6a9c86339b2f7ffe618a32bc40902fd4cb842fd459"
        .parse()
        .unwrap();
    let block = decode::esplora_block(raw, Chain::LitecoinTestnet, hash).unwrap();
    assert_eq!(raw[80], 4); // This fixture uses a one-byte CompactSize count.
    let mut remaining = &raw[81..];
    let mut transactions = Vec::new();
    for _ in 0..4 {
        let before = remaining;
        litecoin::Transaction::consensus_decode_from_finite_reader(&mut remaining).unwrap();
        transactions.push(before[..before.len() - remaining.len()].to_vec());
    }
    assert!(remaining.is_empty());
    for position in 1..4 {
        let proof = TransactionProof::from_block(
            &block,
            position,
            transactions[position as usize].clone(),
            transactions[0].clone(),
        )
        .unwrap();
        let included = proof.verify(Chain::LitecoinTestnet, &block.header).unwrap();
        assert_eq!(included.transaction(), &block.txdata[position as usize]);
        assert_eq!(included.raw(), transactions[position as usize]);
        assert_eq!(included.block_hash(), hash);
        assert_eq!(included.position(), position);
        if position == 3 {
            assert_ne!(included.raw(), serialize(included.transaction()));
        }
    }
}
