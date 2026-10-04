use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use urma_chain::observation::Chain;
use urma_chain::pow::{check_header_pow, pow_limit};
use urma_runtime::config::{LITECOIN_MAINNET_CHECKPOINT, LITECOIN_TESTNET_CHECKPOINT};
use urma_runtime::p2p::HeaderChain;

fn fixture(name: &str) -> Vec<Header> {
    let path = format!(
        "{}/../urma-chain/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| deserialize::<Header>(&hex::decode(line).unwrap()).unwrap())
        .collect()
}

fn anchored(
    chain: Chain,
    headers: &[Header],
    first_height: u64,
    dir: &std::path::Path,
) -> HeaderChain {
    HeaderChain::anchored(
        chain,
        dir.join("headers.bin"),
        first_height,
        headers[0],
        headers[1].block_hash(),
    )
    .unwrap()
}

#[test]
fn embedded_checkpoints_hash_to_their_cross_checked_blocks() {
    for (chain, checkpoint, hash) in [
        (
            Chain::LitecoinMainnet,
            &LITECOIN_MAINNET_CHECKPOINT,
            "3d72f3b771193d234afe50762ed0d11adfed33457c06f2274b03f477a683819a",
        ),
        (
            Chain::LitecoinTestnet,
            &LITECOIN_TESTNET_CHECKPOINT,
            "310ae524e04aea7770f11b39b998458f68fb2c3ebc530c0b9351b55b57a4170e",
        ),
    ] {
        let header: Header = deserialize(&hex::decode(checkpoint.header).unwrap()).unwrap();
        assert_eq!(header.block_hash().to_string(), hash);
        assert_eq!((checkpoint.height + 1) % 2016, 0);
        check_header_pow(&header, chain).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let chain_state = HeaderChain::open(chain, dir.path()).unwrap();
        assert_eq!(chain_state.tip_height(), checkpoint.height);
        assert_eq!(chain_state.tip_hash(), header.block_hash());
        assert_eq!(chain_state.locator(), vec![header.block_hash()]);
        let cache = dir
            .path()
            .join(format!("{}-headers.bin", chain.label().replace(' ', "-")));
        std::fs::write(&cache, vec![7u8; 160]).unwrap();
        let recovered = HeaderChain::open(chain, dir.path()).unwrap();
        assert_eq!(recovered.tip_hash(), header.block_hash());
        assert!(!cache.exists());
    }
    assert!(HeaderChain::open(Chain::BitcoinRegtest, std::env::temp_dir().as_path()).is_err());
}

#[test]
fn real_headers_extend_persist_and_reload_through_a_retarget_boundary() {
    let headers = fixture("ltc-mainnet-retarget-3185280.hex");
    let first_height = 3_185_280 - 2017;
    let dir = tempfile::tempdir().unwrap();
    let mut chain = anchored(Chain::LitecoinMainnet, &headers, first_height, dir.path());
    let now = headers[2017].time + 60;
    assert_eq!(
        format!("{:?}", chain.extend(&headers[1..1001], now).unwrap()),
        "Appended(1000)"
    );
    assert_eq!(
        format!("{:?}", chain.extend(&headers[900..], now).unwrap()),
        "Appended(1017)"
    );
    assert_eq!(chain.tip_height(), 3_185_280);
    assert_eq!(chain.tip_hash(), headers[2017].block_hash());
    assert_eq!(
        chain.height_of(headers[2017].block_hash()).unwrap(),
        3_185_280
    );
    assert_eq!(
        chain.hash_at(first_height).unwrap(),
        headers[0].block_hash()
    );
    assert!(chain.hash_at(first_height - 1).is_err());
    assert!(chain.hash_at(3_185_281).is_err());
    assert_eq!(
        format!("{:?}", chain.extend(&headers[2000..], now).unwrap()),
        "Ignored"
    );
    let locator = chain.locator();
    assert_eq!(locator[0], headers[2017].block_hash());
    assert_eq!(locator[locator.len() - 1], headers[0].block_hash());
    assert!(locator.len() < 30);
    chain.persist().unwrap();
    let reloaded = anchored(Chain::LitecoinMainnet, &headers, first_height, dir.path());
    assert_eq!(reloaded.tip_height(), 3_185_280);
    assert_eq!(reloaded.tip_hash(), headers[2017].block_hash());
    assert_eq!(reloaded.synced_count(), 2017);
}

#[test]
fn tampered_headers_are_rejected_and_leave_the_chain_untouched() {
    let headers = fixture("ltc-mainnet-retarget-3185280.hex");
    let first_height = 3_185_280 - 2017;
    let dir = tempfile::tempdir().unwrap();
    let mut chain = anchored(Chain::LitecoinMainnet, &headers, first_height, dir.path());
    let now = headers[2017].time + 60;
    chain.extend(&headers[1..2017], now).unwrap();
    let mut wrong_bits = headers[2017];
    wrong_bits.bits = headers[2016].bits;
    assert!(chain.extend(&[wrong_bits], now).is_err());
    let mut future = headers[2017];
    future.time = now + 7201;
    assert!(chain.extend(&[future], now).is_err());
    let mut disconnected = headers[2017];
    disconnected.prev_blockhash = headers[5].block_hash();
    assert!(chain.extend(&[disconnected], now).is_err());
    assert_eq!(chain.tip_height(), 3_185_279);
    chain.extend(&[headers[2017]], now).unwrap();
    assert_eq!(chain.tip_height(), 3_185_280);
}

fn mined(prev: &Header, time: u32, chain: Chain) -> Header {
    let mut header = Header {
        version: prev.version,
        prev_blockhash: prev.block_hash(),
        merkle_root: prev.merkle_root,
        time,
        bits: pow_limit(chain).to_compact_lossy(),
        nonce: 0,
    };
    while check_header_pow(&header, chain).is_err() {
        header.nonce += 1;
    }
    header
}

#[test]
fn a_heavier_branch_reorganizes_the_header_chain_and_an_equal_one_does_not() {
    let chain_id = Chain::BitcoinRegtest;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
    let h1 = mined(&genesis, genesis.time + 1, chain_id);
    let h2 = mined(&h1, h1.time + 1, chain_id);
    let h3 = mined(&h2, h2.time + 1, chain_id);
    let dir = tempfile::tempdir().unwrap();
    let mut chain = HeaderChain::anchored(
        chain_id,
        dir.path().join("regtest.bin"),
        0,
        genesis,
        h1.block_hash(),
    )
    .unwrap();
    let now = h3.time + 100;
    assert_eq!(
        format!("{:?}", chain.extend(&[h1, h2, h3], now).unwrap()),
        "Appended(3)"
    );
    let same_a = mined(&h1, h1.time + 2, chain_id);
    let same_b = mined(&same_a, same_a.time + 1, chain_id);
    assert_eq!(
        format!("{:?}", chain.extend(&[same_a, same_b], now).unwrap()),
        "Ignored"
    );
    assert_eq!(chain.tip_hash(), h3.block_hash());
    let heavy_c = mined(&same_b, same_b.time + 1, chain_id);
    assert_eq!(
        format!(
            "{:?}",
            chain.extend(&[same_a, same_b, heavy_c], now).unwrap()
        ),
        "Reorganized { fork_height: 1, appended: 3 }"
    );
    assert_eq!(chain.tip_height(), 4);
    assert_eq!(chain.tip_hash(), heavy_c.block_hash());
    assert!(chain.height_of(h2.block_hash()).is_err());
    assert!(chain.height_of(h3.block_hash()).is_err());
    assert_eq!(chain.height_of(same_b.block_hash()).unwrap(), 3);
    assert_eq!(chain.hash_at(1).unwrap(), h1.block_hash());
    chain.persist().unwrap();
    let reloaded = HeaderChain::anchored(
        chain_id,
        dir.path().join("regtest.bin"),
        0,
        genesis,
        h1.block_hash(),
    )
    .unwrap();
    assert_eq!(reloaded.tip_hash(), heavy_c.block_hash());
}
