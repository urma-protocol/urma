use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Network, TxMerkleNode};
use urma_chain::observation::Chain;
use urma_chain::pow::{PowError, chain_work, check_header_pow, expected_bits, pow_hash};

const LITECOIN_GENESIS_MERKLE: &str =
    "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9";

fn litecoin_genesis(time: u32, nonce: u32) -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: LITECOIN_GENESIS_MERKLE.parse::<TxMerkleNode>().unwrap(),
        time,
        bits: CompactTarget::from_consensus(0x1e0f_fff0),
        nonce,
    }
}

fn fixture(name: &str) -> Vec<Header> {
    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    text.lines()
        .map(|line| deserialize::<Header>(&hex::decode(line).unwrap()).unwrap())
        .collect()
}

#[test]
fn litecoin_genesis_headers_hash_and_meet_scrypt_pow() {
    let mainnet = litecoin_genesis(1_317_972_665, 2_084_524_493);
    assert_eq!(
        mainnet.block_hash(),
        Chain::LitecoinMainnet.genesis().unwrap().0
    );
    check_header_pow(&mainnet, Chain::LitecoinMainnet).unwrap();
    let testnet = litecoin_genesis(1_486_949_366, 293_345);
    assert_eq!(
        testnet.block_hash(),
        Chain::LitecoinTestnet.genesis().unwrap().0
    );
    check_header_pow(&testnet, Chain::LitecoinTestnet).unwrap();
    assert_ne!(
        pow_hash(&mainnet, Chain::LitecoinMainnet).unwrap(),
        mainnet.block_hash()
    );
}

#[test]
fn bitcoin_genesis_headers_use_sha256d_pow() {
    for (network, chain) in [
        (Network::Regtest, Chain::BitcoinRegtest),
        (Network::Testnet4, Chain::BitcoinTestnet4),
    ] {
        let header = bitcoin::blockdata::constants::genesis_block(network).header;
        assert_eq!(pow_hash(&header, chain).unwrap(), header.block_hash());
        check_header_pow(&header, chain).unwrap();
    }
}

#[test]
fn tampered_headers_fail_pow_and_limits() {
    let mut header = litecoin_genesis(1_317_972_665, 2_084_524_493);
    header.nonce += 1;
    assert!(matches!(
        check_header_pow(&header, Chain::LitecoinMainnet),
        Err(PowError::Unmet)
    ));
    header.bits = CompactTarget::from_consensus(0x1f00_ffff);
    assert!(matches!(
        check_header_pow(&header, Chain::LitecoinMainnet),
        Err(PowError::InvalidTarget)
    ));
    header.bits = CompactTarget::from_consensus(0);
    assert!(matches!(
        check_header_pow(&header, Chain::LitecoinMainnet),
        Err(PowError::InvalidTarget)
    ));
}

fn window_is_consistent(chain: Chain, headers: &[Header], first_height: u64) {
    for pair in headers.windows(2) {
        assert_eq!(pair[1].prev_blockhash, pair[0].block_hash());
    }
    for header in headers {
        check_header_pow(header, chain).unwrap();
    }
    for index in 2..headers.len() {
        let expected =
            expected_bits(chain, &headers[..index], first_height, headers[index].time).unwrap();
        assert_eq!(
            expected,
            headers[index].bits,
            "{chain:?} height {}",
            first_height + u64::try_from(index).unwrap()
        );
    }
    let total = chain_work(headers).unwrap();
    assert!(total > chain_work(&headers[..headers.len() - 1]).unwrap());
}

#[test]
fn litecoin_mainnet_retarget_boundary_3185280_matches_core() {
    let headers = fixture("ltc-mainnet-retarget-3185280.hex");
    assert_eq!(headers.len(), 2018);
    window_is_consistent(Chain::LitecoinMainnet, &headers, 3_185_280 - 2017);
    assert_ne!(headers[2017].bits, headers[2016].bits);
}

#[test]
fn litecoin_testnet_retarget_boundary_4902912_matches_core() {
    let headers = fixture("ltc-testnet-retarget-4902912.hex");
    assert_eq!(headers.len(), 2018);
    window_is_consistent(Chain::LitecoinTestnet, &headers, 4_902_912 - 2017);
}

#[test]
fn retarget_refuses_short_windows_and_empty_input() {
    let headers = fixture("ltc-mainnet-retarget-3185280.hex");
    assert!(matches!(
        expected_bits(
            Chain::LitecoinMainnet,
            &headers[1..2017],
            3_185_280 - 2016,
            0
        ),
        Err(PowError::ShortWindow {
            needed: 2017,
            got: 2016
        })
    ));
    assert!(matches!(
        expected_bits(Chain::LitecoinMainnet, &[], 0, 0),
        Err(PowError::EmptyWindow)
    ));
    assert!(matches!(chain_work(&[]), Err(PowError::EmptyWindow)));
}

#[test]
fn chain_parameters_match_litecoin_core() {
    let mainnet = Chain::LitecoinMainnet.params();
    assert_eq!(
        (mainnet.magic, mainnet.port),
        ([0xfb, 0xc0, 0xb6, 0xdb], 9333)
    );
    let testnet = Chain::LitecoinTestnet.params();
    assert_eq!(
        (testnet.magic, testnet.port),
        ([0xfd, 0xd2, 0xc8, 0xf1], 19335)
    );
    assert_eq!(mainnet.target_timespan / mainnet.target_spacing, 2016);
    assert!(testnet.allow_min_difficulty && !mainnet.allow_min_difficulty);
}
