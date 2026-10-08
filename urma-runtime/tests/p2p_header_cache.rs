use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{CompactTarget, Network};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use urma_chain::observation::Chain;
use urma_chain::pow::{check_header_pow, expected_bits};
use urma_runtime::config::{P2P_HEADER_CACHE_REVALIDATE, P2P_MAX_FUTURE_SECS};
use urma_runtime::p2p::HeaderChain;

const CHAIN: Chain = Chain::BitcoinRegtest;

fn mine(mut header: Header) -> Header {
    while check_header_pow(&header, CHAIN).is_err() {
        header.nonce = header.nonce.checked_add(1).unwrap();
    }
    header
}

fn successor(prev: &Header, time: u32, bits: CompactTarget) -> Header {
    mine(Header {
        prev_blockhash: prev.block_hash(),
        time,
        bits,
        nonce: 0,
        ..*prev
    })
}

fn initial_headers() -> Vec<Header> {
    let anchor = bitcoin::blockdata::constants::genesis_block(Network::Regtest).header;
    vec![anchor, successor(&anchor, anchor.time + 1, anchor.bits)]
}

fn append_until(headers: &mut Vec<Header>, count: usize) {
    while headers.len() < count {
        let last = headers.last().unwrap();
        headers.push(successor(last, last.time + 1, last.bits));
    }
}

fn write_cache(dir: &Path, headers: &[Header]) -> Vec<u8> {
    let raw: Vec<u8> = headers.iter().flat_map(serialize).collect();
    std::fs::write(dir.join("headers.bin"), &raw).unwrap();
    raw
}

fn open_cache(dir: &Path, headers: &[Header]) -> HeaderChain {
    HeaderChain::anchored(
        CHAIN,
        dir.join("headers.bin"),
        0,
        headers[0],
        headers[1].block_hash(),
    )
    .unwrap()
}

fn assert_rejected_cache(headers: &[Header], live_reason: &str) {
    for header in headers {
        check_header_pow(header, CHAIN).unwrap();
    }
    for pair in headers.windows(2) {
        assert_eq!(pair[1].prev_blockhash, pair[0].block_hash());
    }
    let dir = tempfile::tempdir().unwrap();
    let mut live = open_cache(dir.path(), headers);
    let now = headers.last().unwrap().time + 1;
    let error = live.extend(&headers[1..], now).unwrap_err();
    assert!(error.to_string().contains(live_reason), "{error}");
    assert_eq!(live.tip_height(), 0);

    write_cache(dir.path(), headers);
    let reloaded = open_cache(dir.path(), headers);
    assert_eq!(reloaded.tip_hash(), headers[0].block_hash());
    assert_eq!(reloaded.synced_count(), 0);
    assert!(!dir.path().join("headers.bin").exists());
}

#[test]
fn connected_pow_valid_cache_with_wrong_difficulty_is_rejected_even_before_tail() {
    for count in [3, P2P_HEADER_CACHE_REVALIDATE + 3] {
        let mut headers = initial_headers();
        let prev = headers.last().unwrap();
        // Regtest does not retarget: this harder, valid PoW target is still wrong.
        headers.push(successor(
            prev,
            prev.time + 1,
            CompactTarget::from_consensus(0x203f_ffff),
        ));
        append_until(&mut headers, count);
        assert_rejected_cache(&headers, "differ from the required");
    }
}

#[test]
fn connected_pow_valid_cache_with_invalid_mtp_is_rejected_even_before_tail() {
    for count in [3, P2P_HEADER_CACHE_REVALIDATE + 3] {
        let mut headers = initial_headers();
        let prev = headers.last().unwrap();
        // With two preceding headers the median is the later timestamp.
        headers.push(successor(prev, prev.time, prev.bits));
        append_until(&mut headers, count);
        assert_rejected_cache(&headers, "not after the median");
    }
}

#[test]
fn valid_cache_reloads_with_identical_bytes_tip_and_index() {
    let mut headers = initial_headers();
    append_until(&mut headers, P2P_HEADER_CACHE_REVALIDATE + 3);
    let dir = tempfile::tempdir().unwrap();
    let mut live = open_cache(dir.path(), &headers);
    live.extend(&headers[1..], headers.last().unwrap().time)
        .unwrap();
    live.persist().unwrap();
    let raw = std::fs::read(dir.path().join("headers.bin")).unwrap();

    let reloaded = open_cache(dir.path(), &headers);
    assert_eq!(reloaded.tip_hash(), live.tip_hash());
    assert_eq!(reloaded.tip_height(), live.tip_height());
    for (offset, header) in headers.iter().enumerate() {
        assert_eq!(reloaded.header_at(offset as u64).unwrap(), *header);
        assert_eq!(
            reloaded.height_of(header.block_hash()).unwrap(),
            offset as u64
        );
    }
    assert_eq!(std::fs::read(dir.path().join("headers.bin")).unwrap(), raw);
}

#[test]
fn clock_regression_does_not_delete_previously_admitted_cache() {
    let regressed_now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut anchor = initial_headers()[0];
    anchor.time = regressed_now;
    anchor.nonce = 0;
    let anchor = mine(anchor);
    let h1 = successor(
        &anchor,
        regressed_now + P2P_MAX_FUTURE_SECS + 60,
        anchor.bits,
    );
    let h2 = successor(&h1, h1.time + 1, h1.bits);
    let headers = [anchor, h1, h2];
    let dir = tempfile::tempdir().unwrap();
    let mut live = open_cache(dir.path(), &headers);
    assert!(
        live.extend(&headers[1..], regressed_now)
            .unwrap_err()
            .to_string()
            .contains("too far in the future")
    );
    assert_eq!(live.tip_hash(), anchor.block_hash());

    // The same headers were admissible while the clock was ahead, before rollback.
    live.extend(&headers[1..], h2.time).unwrap();
    live.persist().unwrap();
    let raw = std::fs::read(dir.path().join("headers.bin")).unwrap();
    let reloaded = open_cache(dir.path(), &headers);
    assert_eq!(reloaded.tip_hash(), h2.block_hash());
    assert_eq!(reloaded.synced_count(), 2);
    assert_eq!(std::fs::read(dir.path().join("headers.bin")).unwrap(), raw);
}

fn invalidate_pow(header: &mut Header) {
    while check_header_pow(header, CHAIN).is_ok() {
        header.nonce = header.nonce.checked_add(1).unwrap();
    }
}

#[test]
fn reload_reproves_only_the_last_2016_headers_and_trusts_the_older_prefix() {
    let count = P2P_HEADER_CACHE_REVALIDATE + 3;
    // Offset 2 is just outside the trailing window; offset 3 is its first header.
    for invalid_at in [2, 3, count - 1] {
        let mut headers = initial_headers();
        append_until(&mut headers, invalid_at + 1);
        invalidate_pow(&mut headers[invalid_at]);
        // Remine descendants to keep continuity and context valid independently of PoW.
        append_until(&mut headers, count);
        let dir = tempfile::tempdir().unwrap();
        let raw = write_cache(dir.path(), &headers);
        let reloaded = open_cache(dir.path(), &headers);
        if invalid_at == 2 {
            assert_eq!(reloaded.tip_hash(), headers.last().unwrap().block_hash());
            assert_eq!(std::fs::read(dir.path().join("headers.bin")).unwrap(), raw);
        } else {
            assert_eq!(reloaded.tip_hash(), headers[0].block_hash());
            assert!(!dir.path().join("headers.bin").exists());
        }
    }
}

#[test]
fn reload_still_requires_the_pinned_first_successor() {
    let mut headers = initial_headers();
    let trusted_next = headers[1].block_hash();
    headers[1] = successor(&headers[0], headers[1].time + 1, headers[1].bits);
    assert_ne!(headers[1].block_hash(), trusted_next);
    let dir = tempfile::tempdir().unwrap();
    write_cache(dir.path(), &headers);
    let reloaded = HeaderChain::anchored(
        CHAIN,
        dir.path().join("headers.bin"),
        0,
        headers[0],
        trusted_next,
    )
    .unwrap();
    assert_eq!(reloaded.tip_hash(), headers[0].block_hash());
    assert!(!dir.path().join("headers.bin").exists());
}

#[test]
fn pinned_retarget_successor_reloads_without_precheckpoint_history() {
    let fixture = std::fs::read_to_string(format!(
        "{}/../urma-chain/tests/fixtures/ltc-mainnet-retarget-3185280.hex",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let headers: Vec<Header> = fixture
        .lines()
        .skip(2016)
        .map(|line| deserialize(&hex::decode(line).unwrap()).unwrap())
        .collect();
    assert_eq!(headers.len(), 2);
    assert_ne!(headers[0].bits, headers[1].bits);
    let chain = Chain::LitecoinMainnet;
    let height = 3_185_279;
    // The pinned successor supplies the retarget that cannot be calculated
    // from the single anchor header alone.
    assert!(expected_bits(chain, &headers[..1], height, headers[1].time).is_err());
    let dir = tempfile::tempdir().unwrap();
    let open = || {
        HeaderChain::anchored(
            chain,
            dir.path().join("headers.bin"),
            height,
            headers[0],
            headers[1].block_hash(),
        )
        .unwrap()
    };
    let mut live = open();
    live.extend(&headers[1..], headers[1].time + 60).unwrap();
    live.persist().unwrap();
    let raw = std::fs::read(dir.path().join("headers.bin")).unwrap();
    let reloaded = open();
    assert_eq!(reloaded.tip_height(), height + 1);
    assert_eq!(reloaded.tip_hash(), headers[1].block_hash());
    assert_eq!(std::fs::read(dir.path().join("headers.bin")).unwrap(), raw);
}
