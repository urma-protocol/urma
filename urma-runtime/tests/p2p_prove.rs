use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use urma_chain::observation::Chain;
use urma_runtime::p2p::HeaderChain;

fn fixture() -> Vec<Header> {
    let path = format!(
        "{}/../urma-chain/tests/fixtures/ltc-testnet-retarget-4902912.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| deserialize::<Header>(&hex::decode(line).unwrap()).unwrap())
        .collect()
}

fn chain_at(dir: &std::path::Path, headers: &[Header]) -> HeaderChain {
    HeaderChain::anchored(
        Chain::LitecoinTestnet,
        dir.join("headers.bin"),
        4_902_912 - 2017,
        headers[0],
        headers[1].block_hash(),
    )
    .unwrap()
}

#[test]
fn concurrent_proofs_give_the_sequential_chain_and_an_identical_cache_file() {
    let headers = fixture();
    let now = headers[2017].time + 60;
    let dir = tempfile::tempdir().unwrap();
    let mut chain = chain_at(dir.path(), &headers);
    assert_eq!(
        format!("{:?}", chain.extend(&headers[1..], now).unwrap()),
        "Appended(2017)"
    );
    chain.persist().unwrap();
    let written = std::fs::read(dir.path().join("headers.bin")).unwrap();
    let expected: Vec<u8> = headers
        .iter()
        .flat_map(|header| serialize(header))
        .collect();
    assert_eq!(written, expected);
    let one_by_one = tempfile::tempdir().unwrap();
    let mut sequential = chain_at(one_by_one.path(), &headers);
    for header in &headers[1..] {
        sequential
            .extend(std::slice::from_ref(header), now)
            .unwrap();
    }
    sequential.persist().unwrap();
    assert_eq!(
        std::fs::read(one_by_one.path().join("headers.bin")).unwrap(),
        written
    );
    assert_eq!(sequential.tip_hash(), chain.tip_hash());
    let reloaded = chain_at(dir.path(), &headers);
    assert_eq!(reloaded.tip_hash(), chain.tip_hash());
}

#[test]
fn a_tampered_header_is_rejected_wherever_it_sits_in_the_batch() {
    let headers = fixture();
    let now = headers[2017].time + 60;
    for tampered_at in [1, 1000, 2017] {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_at(dir.path(), &headers);
        let mut batch = headers[1..].to_vec();
        batch[tampered_at - 1].nonce ^= 1;
        let refused = chain.extend(&batch, now).unwrap_err().to_string();
        assert!(
            refused.contains("proof of work") || refused.contains("checkpointed block"),
            "offset {tampered_at}: {refused}"
        );
        assert_eq!(chain.tip_hash(), headers[0].block_hash());
        assert_eq!(chain.synced_count(), 0);
        chain.extend(&headers[1..], now).unwrap();
        assert_eq!(chain.tip_hash(), headers[2017].block_hash());
    }
}
