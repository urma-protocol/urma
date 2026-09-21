use bitcoin::{
    Block, Network,
    consensus::{deserialize, serialize},
};
use urma_chain::{decode, observation::Chain};

#[test]
fn public_litecoin_block_preserves_transparent_ids_and_witnesses() {
    let raw = include_bytes!("../../tests/vectors/litecoin-mweb/block-4892705.bin");
    let hash = "2b70f30e5c2a5e9e8510cc6a9c86339b2f7ffe618a32bc40902fd4cb842fd459"
        .parse()
        .unwrap();
    assert!(deserialize::<Block>(raw).is_err());
    assert!(decode::block(raw, Chain::LitecoinTestnet, hash).is_err());
    let block = decode::esplora_block(raw, Chain::LitecoinTestnet, hash).unwrap();
    assert_eq!(
        block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect::<Vec<_>>(),
        [
            "d8df94476533566d0afc40a5db0d7bce8e8ce219c6074681d5d7e48dc75a15f3",
            "fb867ec774a6aa42bfddb38c340338fe78c9c434549c8f39e3b9e49a969905c2",
            "3b310f5660608d68b40cc3b8148f1e6766972d14b6d6d05becb459b44d32bfb3",
            "2651a3074353b50d7a1c1a29f15ea21f0dde6aed7c9b5de053f01128fb4218e7",
        ]
    );
    assert!(block.check_merkle_root());
    assert!(block.check_witness_commitment());
    let mut corrupt = raw.to_vec();
    corrupt[0] ^= 1;
    assert!(decode::esplora_block(&corrupt, Chain::LitecoinTestnet, hash).is_err());
    let mut trailing = raw.to_vec();
    trailing.extend_from_slice(&[0, 0]);
    assert!(decode::esplora_block(&trailing, Chain::LitecoinTestnet, hash).is_err());
    assert!(decode::esplora_block(&raw[..raw.len() - 1], Chain::LitecoinTestnet, hash).is_err());
    assert!(decode::esplora_block(raw, Chain::BitcoinTestnet4, hash).is_err());
    let mut witness = raw.to_vec();
    witness[214] ^= 1;
    assert!(matches!(
        decode::esplora_block(&witness, Chain::LitecoinTestnet, hash),
        Err(decode::DecodeError::Integrity(
            urma_chain::validation::BlockValidationError::WitnessCommitmentMismatch
        ))
    ));
    let mut merkle = raw.to_vec();
    merkle[120] ^= 1;
    assert!(matches!(
        decode::esplora_block(&merkle, Chain::LitecoinTestnet, hash),
        Err(decode::DecodeError::Integrity(
            urma_chain::validation::BlockValidationError::MerkleRootMismatch
        ))
    ));
}

#[test]
fn hogex_transaction_hashes_and_confidential_transaction_rejection() {
    let raw = include_bytes!("../../tests/vectors/litecoin-mweb/block-4892705.bin");
    let tx = decode::transaction(&raw[1150..], Chain::LitecoinTestnet).unwrap();
    assert_eq!(
        tx.compute_txid().to_string(),
        "2651a3074353b50d7a1c1a29f15ea21f0dde6aed7c9b5de053f01128fb4218e7"
    );
    assert_eq!(
        tx.compute_wtxid().to_string(),
        tx.compute_txid().to_string()
    );
    let mut mw: litecoin::Transaction = litecoin::consensus::deserialize(&raw[1150..]).unwrap();
    mw.is_hog_ex = false;
    mw.mw_tx = Some(litecoin::blockdata::mimblewimble::Transaction {
        kernel_offset: [0; 32],
        stealth_offset: [0; 32],
        body: litecoin::blockdata::mimblewimble::TxBody {
            inputs: vec![],
            outputs: vec![],
            kernels: vec![litecoin::consensus::deserialize(&[0; 98]).unwrap()],
        },
    });
    for confidential_only in [false, true] {
        if confidential_only {
            mw.input.clear();
            mw.output.clear();
        }
        let result =
            decode::transaction(&litecoin::consensus::serialize(&mw), Chain::LitecoinTestnet);
        assert!(
            matches!(result, Err(decode::DecodeError::UnsupportedMwebTransaction)),
            "{result:?}"
        );
    }
}

#[test]
fn extension_suffix_is_parsed_strictly_in_both_modes() {
    let raw = include_bytes!("../../tests/vectors/litecoin-mweb/block-4892705.bin");
    let hash = "2b70f30e5c2a5e9e8510cc6a9c86339b2f7ffe618a32bc40902fd4cb842fd459"
        .parse()
        .unwrap();
    let mut full = raw.to_vec();
    full.push(0);
    assert!(decode::block(&full, Chain::LitecoinTestnet, hash).is_ok());
    full.pop();
    full.extend_from_slice(&[1]);
    full.extend_from_slice(&[0; 166]);
    assert!(decode::block(&full, Chain::LitecoinTestnet, hash).is_ok());
    assert!(decode::esplora_block(&full, Chain::LitecoinTestnet, hash).is_ok());
    let mut no_version_bit = full.clone();
    no_version_bit[3] = 0;
    let header: bitcoin::block::Header = deserialize(&no_version_bit[..80]).unwrap();
    assert!(decode::block(&no_version_bit, Chain::LitecoinTestnet, header.block_hash()).is_ok());
    full.pop();
    assert!(decode::block(&full, Chain::LitecoinTestnet, hash).is_err());
    assert!(decode::esplora_block(&full, Chain::LitecoinTestnet, hash).is_err());
    let mut unknown = raw.to_vec();
    unknown[1155] = 0x10;
    assert!(decode::esplora_block(&unknown, Chain::LitecoinTestnet, hash).is_err());
    let mut invalid_presence = raw.to_vec();
    invalid_presence.push(2);
    assert!(decode::esplora_block(&invalid_presence, Chain::LitecoinTestnet, hash).is_err());
    let mut noncanonical_count = raw.to_vec();
    noncanonical_count.splice(80..81, [0xfd, 4, 0]);
    assert!(decode::esplora_block(&noncanonical_count, Chain::LitecoinTestnet, hash).is_err());
    let mut misplaced_hogex = raw.to_vec();
    misplaced_hogex[80] = 5;
    misplaced_hogex.extend_from_slice(&raw[1150..]);
    assert!(matches!(
        decode::esplora_block(&misplaced_hogex, Chain::LitecoinTestnet, hash),
        Err(decode::DecodeError::InvalidHogEx)
    ));
    assert!(matches!(
        decode::transaction(&vec![0; 8_000_001], Chain::LitecoinTestnet),
        Err(decode::DecodeError::LimitExceeded)
    ));
}

#[test]
fn bitcoin_decoding_is_unchanged() {
    let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    let raw = serialize(&block);
    assert_eq!(
        decode::block(&raw, Chain::BitcoinRegtest, block.block_hash()).unwrap(),
        block
    );
    assert_eq!(
        decode::transaction(&serialize(&block.txdata[0]), Chain::BitcoinRegtest).unwrap(),
        block.txdata[0]
    );
}
