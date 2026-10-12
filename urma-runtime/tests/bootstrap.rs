//! Strict bootstrap regressions. Ancestors are contextual input, not selected
//! history. Only cheap regtest headers are mined here; no consensus/UTXO claim.

use bitcoin::{
    CompactTarget, Network,
    block::{Header, Version},
    consensus::encode::{deserialize, serialize},
    hashes::Hash,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use urma_chain::{
    observation::Chain,
    pow::{check_header_pow, expected_bits},
};
use urma_runtime::p2p::{HeaderBootstrap, HeaderChain, context_headers};

const REGTEST: Chain = Chain::BitcoinRegtest;

fn fixture(name: &str) -> Vec<Header> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../urma-chain/tests/fixtures")
        .join(name);
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| deserialize(&hex::decode(line).unwrap()).unwrap())
        .collect()
}

// Inspect only files in this test's owned temporary cache. Discover paths via
// public filesystem effects, without guessing HeaderChain's private filename.
fn files(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                walk(root, &entry.path(), found);
            } else {
                assert!(kind.is_file(), "unexpected non-file in owned cache");
                found.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(directory, directory, &mut found);
    found
}

fn raw(headers: &[Header]) -> Vec<u8> {
    headers.iter().flat_map(serialize).collect()
}

fn assert_context_hidden(chain: &HeaderChain, ancestors: &[Header]) {
    let first_height = chain.start_height() - ancestors.len() as u64;
    let locator = chain.locator();
    for (index, header) in ancestors.iter().enumerate() {
        assert!(chain.header_at(first_height + index as u64).is_err());
        assert!(chain.height_of(header.block_hash()).is_err());
        assert!(!locator.contains(&header.block_hash()));
    }
}

fn real_retarget(chain_id: Chain, name: &str, boundary: u64) {
    let headers = fixture(name);
    assert_eq!(headers.len(), 2018);
    let ancestors = headers[..2016].to_vec();
    let anchor = headers[2016];
    let successor = headers[2017];
    assert_eq!(ancestors.len(), 2016);
    assert_ne!(anchor.bits, successor.bits);
    assert_eq!(
        expected_bits(chain_id, &headers[..2017], boundary - 2017, successor.time).unwrap(),
        successor.bits
    );
    // With no contextual ancestors, this same retarget cannot be calculated.
    assert!(expected_bits(chain_id, &[anchor], boundary - 1, successor.time).is_err());
    let bootstrap =
        HeaderBootstrap::new(chain_id, boundary - 1, anchor, ancestors.clone()).unwrap();
    assert_eq!(
        std::mem::discriminant(&bootstrap.chain()),
        std::mem::discriminant(&chain_id)
    );
    assert_eq!(bootstrap.height(), boundary - 1);
    assert_eq!(bootstrap.header().block_hash(), anchor.block_hash());
    assert_eq!(bootstrap.ancestors().to_vec(), ancestors);
    let directory = tempfile::tempdir().unwrap();
    let mut chain = HeaderChain::open_bootstrap(directory.path(), bootstrap).unwrap();
    assert_eq!(chain.start_height(), boundary - 1);
    assert_eq!(chain.tip_height(), boundary - 1);
    assert_eq!(chain.synced_count(), 0);
    assert_eq!(chain.header_at(boundary - 1).unwrap(), anchor);
    assert_context_hidden(&chain, &ancestors);
    // No successor hash is supplied. The very first extension must apply bits
    // and MTP checks using the contextual ancestors, rather than a pinned bypass.
    chain.extend(&[successor], successor.time + 60).unwrap();
    assert_eq!(chain.tip_height(), boundary);
    assert_eq!(chain.tip_hash(), successor.block_hash());
    assert_eq!(chain.synced_count(), 1);
    assert_eq!(chain.height_of(successor.block_hash()).unwrap(), boundary);
    assert_context_hidden(&chain, &ancestors);
    chain.persist().unwrap();
    let before = files(directory.path());
    assert!(
        before
            .values()
            .any(|bytes| *bytes == raw(&[anchor, successor]))
    );
    drop(chain);
    let bootstrap =
        HeaderBootstrap::new(chain_id, boundary - 1, anchor, ancestors.clone()).unwrap();
    let reopened = HeaderChain::open_bootstrap(directory.path(), bootstrap).unwrap();
    assert_eq!(reopened.tip_height(), boundary);
    assert_eq!(reopened.tip_hash(), successor.block_hash());
    assert_eq!(reopened.synced_count(), 1);
    assert_eq!(reopened.header_at(boundary).unwrap(), successor);
    assert_context_hidden(&reopened, &ancestors);
    assert_eq!(files(directory.path()), before);
}

#[test]
fn mainnet_first_successor_retargets_from_separate_2016_ancestors() {
    real_retarget(
        Chain::LitecoinMainnet,
        "ltc-mainnet-retarget-3185280.hex",
        3_185_280,
    );
}

#[test]
fn testnet_first_successor_retargets_from_separate_2016_ancestors() {
    real_retarget(
        Chain::LitecoinTestnet,
        "ltc-testnet-retarget-4902912.hex",
        4_902_912,
    );
}

fn litecoin_genesis(time: u32, nonce: u32) -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"
            .parse()
            .unwrap(),
        time,
        bits: CompactTarget::from_consensus(0x1e0f_fff0),
        nonce,
    }
}

#[test]
fn zero_height_accepts_exact_network_genesis_with_empty_context() {
    for (chain_id, header) in [
        (
            REGTEST,
            bitcoin::blockdata::constants::genesis_block(Network::Regtest).header,
        ),
        (
            Chain::BitcoinTestnet4,
            bitcoin::blockdata::constants::genesis_block(Network::Testnet4).header,
        ),
        (
            Chain::LitecoinMainnet,
            litecoin_genesis(1_317_972_665, 2_084_524_493),
        ),
        (
            Chain::LitecoinTestnet,
            litecoin_genesis(1_486_949_366, 293_345),
        ),
    ] {
        assert_eq!(header.block_hash(), chain_id.genesis().unwrap().0);
        let bootstrap = HeaderBootstrap::new(chain_id, 0, header, vec![]).unwrap();
        assert_eq!(bootstrap.height(), 0);
        assert!(bootstrap.ancestors().is_empty());
        let directory = tempfile::tempdir().unwrap();
        let chain = HeaderChain::open_bootstrap(directory.path(), bootstrap).unwrap();
        assert_eq!(chain.header_at(0).unwrap(), header);
        assert_eq!(chain.tip_height(), 0);
        assert_eq!(chain.locator(), vec![header.block_hash()]);
        chain.persist().unwrap();
        let before = files(directory.path());
        let bootstrap = HeaderBootstrap::new(chain_id, 0, header, vec![]).unwrap();
        let reopened = HeaderChain::open_bootstrap(directory.path(), bootstrap).unwrap();
        assert_eq!(reopened.tip_hash(), header.block_hash());
        assert_eq!(files(directory.path()), before);
    }
}

#[test]
fn zero_height_refuses_wrong_network_and_nonempty_context_before_cache_phase() {
    let mainnet = litecoin_genesis(1_317_972_665, 2_084_524_493);
    let testnet = litecoin_genesis(1_486_949_366, 293_345);
    // These headers have valid Litecoin PoW independently of the network name.
    check_header_pow(&mainnet, Chain::LitecoinTestnet).unwrap();
    check_header_pow(&testnet, Chain::LitecoinMainnet).unwrap();
    for (chain_id, header, ancestors) in [
        (Chain::LitecoinTestnet, mainnet, vec![]),
        (Chain::LitecoinMainnet, testnet, vec![]),
        (Chain::LitecoinMainnet, mainnet, vec![mainnet]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("canary"), b"owned cache sentinel").unwrap();
        let before = files(directory.path());
        let result = HeaderBootstrap::new(chain_id, 0, header, ancestors)
            .map(|bootstrap| HeaderChain::open_bootstrap(directory.path(), bootstrap));
        // Outer Err means construction failed; cache-opening closure never ran.
        assert!(result.is_err());
        assert_eq!(files(directory.path()), before);
    }
}

fn mine(mut header: Header) -> Header {
    for nonce in 0..1_000_000 {
        header.nonce = nonce;
        if check_header_pow(&header, REGTEST).is_ok() {
            return header;
        }
    }
    panic!("bounded easy regtest mining exhausted");
}

fn successor(previous: &Header, time: u32, bits: CompactTarget) -> Header {
    mine(Header {
        prev_blockhash: previous.block_hash(),
        time,
        bits,
        nonce: 0,
        ..*previous
    })
}

struct RegtestContext {
    ancestors: Vec<Header>,
    anchor: Header,
    height: u64,
}

impl RegtestContext {
    fn new() -> Self {
        Self::at_height(11)
    }

    fn at_height(height: u64) -> Self {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).header;
        let count = height.min(context_headers(REGTEST) as u64) as usize;
        assert!(count > 0);
        let mut ancestors = vec![genesis];
        for offset in 1..count {
            ancestors.push(successor(
                ancestors.last().unwrap(),
                genesis.time + offset as u32 * 10,
                genesis.bits,
            ));
        }
        let anchor = successor(
            ancestors.last().unwrap(),
            genesis.time + count as u32 * 10,
            genesis.bits,
        );
        // The height labels are fixture inputs, not assertions of real placement.
        Self {
            ancestors,
            anchor,
            height,
        }
    }

    fn bootstrap(&self) -> HeaderBootstrap {
        HeaderBootstrap::new(REGTEST, self.height, self.anchor, self.ancestors.clone()).unwrap()
    }

    fn open(&self, directory: &Path) -> HeaderChain {
        HeaderChain::open_bootstrap(directory, self.bootstrap()).unwrap()
    }

    fn median(&self) -> u32 {
        let mut times: Vec<_> = self.ancestors[self.ancestors.len() - 10..]
            .iter()
            .map(|h| h.time)
            .chain([self.anchor.time])
            .collect();
        times.sort_unstable();
        assert_eq!(times.len(), 11);
        times[5]
    }
}

fn assert_context_count_and_height_minimum() {
    for (chain_id, count) in [
        (Chain::LitecoinMainnet, 2016),
        (Chain::LitecoinTestnet, 2016),
        (REGTEST, 2015),
        (Chain::BitcoinTestnet4, 2015),
    ] {
        assert_eq!(context_headers(chain_id), count);
    }
    for height in [1, 10, 11, 2015, 2016] {
        let context = RegtestContext::at_height(height);
        let bootstrap = context.bootstrap();
        assert_eq!(bootstrap.height(), height);
        assert_eq!(bootstrap.ancestors().len(), height.min(2015) as usize);
        let mut short = context.ancestors.clone();
        short.remove(0);
        assert!(HeaderBootstrap::new(REGTEST, height, context.anchor, short).is_err());
        let mut long = context.ancestors.clone();
        long.insert(0, long[0]);
        assert!(HeaderBootstrap::new(REGTEST, height, context.anchor, long).is_err());
    }
}

#[test]
fn invalid_ancestor_shapes_and_pow_fail_before_cache_phase() {
    assert_context_count_and_height_minimum();
    // A full context above genesis avoids attributing shape/PoW failures to the
    // separate genesis-prefix identity check.
    let context = RegtestContext::at_height(context_headers(REGTEST) as u64 + 100);
    let mut reversed = context.ancestors.clone();
    reversed.reverse();
    let mut unlinked = context.ancestors.clone();
    unlinked[5] = successor(&unlinked[4], unlinked[5].time + 1, unlinked[5].bits);
    let mut invalid_pow = context.ancestors.clone();
    invalid_pow[5].bits = CompactTarget::from_consensus(0);
    // Keep all later links and their PoW valid, isolating the bad ancestor's PoW.
    for index in 6..invalid_pow.len() {
        invalid_pow[index] = successor(
            &invalid_pow[index - 1],
            invalid_pow[index].time,
            context.anchor.bits,
        );
    }
    let bad_pow_anchor = successor(
        invalid_pow.last().unwrap(),
        context.anchor.time,
        context.anchor.bits,
    );
    assert!(check_header_pow(&invalid_pow[5], REGTEST).is_err());
    check_header_pow(&bad_pow_anchor, REGTEST).unwrap();
    for (index, header) in invalid_pow.iter().enumerate() {
        if index != 5 {
            check_header_pow(header, REGTEST).unwrap();
        }
    }
    for pair in invalid_pow.windows(2) {
        assert_eq!(pair[1].prev_blockhash, pair[0].block_hash());
    }
    assert_eq!(
        bad_pow_anchor.prev_blockhash,
        invalid_pow.last().unwrap().block_hash()
    );
    let mut invalid_anchor = context.anchor;
    invalid_anchor.bits = CompactTarget::from_consensus(0);
    assert_eq!(
        invalid_anchor.prev_blockhash,
        context.ancestors.last().unwrap().block_hash()
    );
    assert!(check_header_pow(&invalid_anchor, REGTEST).is_err());
    let mut too_long = vec![context.ancestors[0]];
    too_long.extend_from_slice(&context.ancestors);
    for (anchor, ancestors, reason) in [
        (
            context.anchor,
            context.ancestors[1..].to_vec(),
            "needs exactly",
        ),
        (context.anchor, too_long, "needs exactly"),
        (context.anchor, reversed, "do not connect"),
        (context.anchor, unlinked, "do not connect"),
        (bad_pow_anchor, invalid_pow, "fails proof of work"),
        (
            invalid_anchor,
            context.ancestors.clone(),
            "fails proof of work",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("canary"),
            b"must not change on invalid bootstrap",
        )
        .unwrap();
        let before = files(directory.path());
        let result = HeaderBootstrap::new(REGTEST, context.height, anchor, ancestors)
            .map(|bootstrap| HeaderChain::open_bootstrap(directory.path(), bootstrap));
        let error = result
            .err()
            .expect("invalid constructor input reached cache-opening phase");
        assert!(error.to_string().contains(reason), "{error}");
        assert_eq!(files(directory.path()), before);
    }
}

#[test]
fn first_successor_uses_full_eleven_header_mtp_and_strict_bits_without_pin() {
    let context = RegtestContext::new();
    let directory = tempfile::tempdir().unwrap();
    let mut chain = context.open(directory.path());
    let at_median = successor(&context.anchor, context.median(), context.anchor.bits);
    check_header_pow(&at_median, REGTEST).unwrap();
    assert!(
        chain
            .extend(&[at_median], context.anchor.time + 60)
            .is_err()
    );
    assert_eq!(chain.tip_hash(), context.anchor.block_hash());
    let harder = successor(
        &context.anchor,
        context.anchor.time + 1,
        CompactTarget::from_consensus(0x203f_ffff),
    );
    check_header_pow(&harder, REGTEST).unwrap();
    assert_ne!(harder.bits, context.anchor.bits);
    assert!(chain.extend(&[harder], context.anchor.time + 60).is_err());
    assert_eq!(chain.synced_count(), 0);
    // Time regresses relative to the parent, yet is strictly after the FULL
    // previous-eleven median. An anchor-only MTP check would wrongly reject it.
    let good = successor(&context.anchor, context.median() + 1, context.anchor.bits);
    assert!(good.time < context.anchor.time);
    chain.extend(&[good], context.anchor.time + 60).unwrap();
    assert_eq!(chain.tip_hash(), good.block_hash());
    assert_eq!(chain.synced_count(), 1);
    assert_context_hidden(&chain, &context.ancestors);
    // Another valid first successor must work without a supplied hash pin.
    let other_dir = tempfile::tempdir().unwrap();
    let mut other = context.open(other_dir.path());
    let alternate = successor(&context.anchor, good.time + 1, good.bits);
    assert_ne!(alternate.block_hash(), good.block_hash());
    other
        .extend(&[alternate], context.anchor.time + 60)
        .unwrap();
    assert_eq!(other.tip_hash(), alternate.block_hash());
    chain.persist().unwrap();
    let before = files(directory.path());
    let reopened = context.open(directory.path());
    assert_eq!(reopened.tip_hash(), good.block_hash());
    assert_eq!(files(directory.path()), before);
}

#[test]
fn equal_header_at_different_bootstrap_heights_has_separate_cache_identity() {
    let context = RegtestContext::at_height(context_headers(REGTEST) as u64 + 100);
    let directory = tempfile::tempdir().unwrap();
    let good = successor(
        &context.anchor,
        context.anchor.time + 1,
        context.anchor.bits,
    );
    let mut first = context.open(directory.path());
    first.extend(&[good], good.time + 60).unwrap();
    first.persist().unwrap();
    let first_files = files(directory.path());
    assert!(!first_files.is_empty());
    let other_height = context.height + 1;
    let other_bootstrap = || {
        HeaderBootstrap::new(
            REGTEST,
            other_height,
            context.anchor,
            context.ancestors.clone(),
        )
        .unwrap()
    };
    let second = HeaderChain::open_bootstrap(directory.path(), other_bootstrap()).unwrap();
    assert_eq!(second.start_height(), other_height);
    assert_eq!(second.tip_hash(), context.anchor.block_hash());
    assert_eq!(second.synced_count(), 0);
    assert_eq!(files(directory.path()), first_files);
    second.persist().unwrap();
    let both_files = files(directory.path());
    assert!(
        both_files
            .keys()
            .any(|path| !first_files.contains_key(path))
    );
    for (path, bytes) in &first_files {
        assert_eq!(both_files.get(path), Some(bytes));
    }
    let first_reopened = context.open(directory.path());
    let second_reopened = HeaderChain::open_bootstrap(directory.path(), other_bootstrap()).unwrap();
    assert_eq!(first_reopened.tip_height(), context.height + 1);
    assert_eq!(first_reopened.tip_hash(), good.block_hash());
    assert_eq!(second_reopened.tip_height(), other_height);
    assert_eq!(second_reopened.tip_hash(), context.anchor.block_hash());
    assert_eq!(files(directory.path()), both_files);
}

#[test]
fn grown_window_and_fork_suffix_use_context_then_selected_predecessors() {
    let context = RegtestContext::new();
    let directory = tempfile::tempdir().unwrap();
    let mut chain = context.open(directory.path());
    let mut selected = Vec::new();
    let mut previous = context.anchor;
    let count = context_headers(REGTEST) + 16;
    for offset in 1..=count {
        let next = successor(
            &previous,
            context.anchor.time + offset as u32,
            previous.bits,
        );
        selected.push(next);
        previous = next;
    }
    chain.extend(&selected[..2], previous.time + 60).unwrap();
    chain.extend(&selected[2..], previous.time + 60).unwrap();
    assert_eq!(chain.synced_count(), count as u64);
    let fork_at = selected[0];
    let mut fork = Vec::new();
    let mut previous = fork_at;
    for offset in 1..=count {
        let next = successor(
            &previous,
            context.anchor.time + 100 + offset as u32,
            previous.bits,
        );
        fork.push(next);
        previous = next;
    }
    let mut bad = fork.clone();
    // Last header's bits violation is independent of PoW and predecessor links.
    let last = bad.len() - 1;
    bad[last] = successor(
        &bad[last - 1],
        bad[last].time,
        CompactTarget::from_consensus(0x203f_ffff),
    );
    check_header_pow(&bad[last], REGTEST).unwrap();
    assert!(chain.extend(&bad, previous.time + 60).is_err());
    assert_eq!(chain.tip_hash(), selected.last().unwrap().block_hash());
    assert_eq!(chain.synced_count(), count as u64);
    let mut bad_mtp = fork.clone();
    let mut times: Vec<_> = bad_mtp[last - 11..last]
        .iter()
        .map(|header| header.time)
        .collect();
    times.sort_unstable();
    bad_mtp[last] = successor(&bad_mtp[last - 1], times[5], bad_mtp[last].bits);
    check_header_pow(&bad_mtp[last], REGTEST).unwrap();
    let error = chain
        .extend(&bad_mtp, previous.time + 60)
        .err()
        .expect("invalid suffix MTP accepted");
    assert!(
        error.to_string().contains("not after the median"),
        "{error}"
    );
    assert_eq!(chain.tip_hash(), selected.last().unwrap().block_hash());
    assert_eq!(chain.synced_count(), count as u64);
    chain.extend(&fork, previous.time + 60).unwrap();
    assert_eq!(chain.tip_height(), context.height + count as u64 + 1);
    assert_eq!(chain.tip_hash(), previous.block_hash());
    assert!(chain.height_of(selected[1].block_hash()).is_err());
    assert_eq!(
        chain.height_of(fork_at.block_hash()).unwrap(),
        context.height + 1
    );
    assert_context_hidden(&chain, &context.ancestors);
    chain.persist().unwrap();
    let before = files(directory.path());
    let reopened = context.open(directory.path());
    assert_eq!(reopened.tip_hash(), previous.block_hash());
    assert_eq!(reopened.tip_height(), context.height + count as u64 + 1);
    assert_context_hidden(&reopened, &context.ancestors);
    assert_eq!(files(directory.path()), before);
}
