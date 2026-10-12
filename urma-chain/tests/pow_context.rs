//! Synthetic headers exercise difficulty selection only. No PoW, continuity,
//! transaction consensus or block validity is claimed by these fixtures.

use bitcoin::{CompactTarget, Network, block::Header};
use urma_chain::{
    observation::Chain,
    pow::{PowError, expected_bits},
};

const CHAIN: Chain = Chain::LitecoinTestnet;
const REGULAR: u32 = 0x1e0f_fff0;

fn window(bits: &[u32]) -> Vec<Header> {
    bits.iter()
        .enumerate()
        .map(|(index, bits)| {
            let mut header = bitcoin::blockdata::constants::genesis_block(Network::Regtest).header;
            header.bits = CompactTarget::from_consensus(*bits);
            header.time = 20_000 + u32::try_from(index).unwrap() * 150;
            header
        })
        .collect()
}

// Keep this regression compatible with the unrepaired implementation: it does
// not name the new error variant, so its baseline failure is behavioral.
#[test]
fn mid_period_all_minimum_short_window_requires_older_context() {
    let limit = CHAIN.params().pow_limit_bits;
    let headers = window(&[limit, limit, limit]);
    let first_height = CHAIN.params().retarget_interval + 17;
    let result = expected_bits(CHAIN, &headers, first_height, headers[2].time + 150);
    assert!(
        result.is_err(),
        "all-minimum window beginning mid-period cannot identify prior regular difficulty: {result:?}"
    );
}

#[test]
fn missing_context_reports_the_earliest_available_height() {
    let limit = CHAIN.params().pow_limit_bits;
    for (first_height, size) in [(17, 1), (2033, 3), (4040, 4)] {
        let headers = window(&vec![limit; size]);
        let error = expected_bits(
            CHAIN,
            &headers,
            first_height,
            headers.last().unwrap().time + 150,
        )
        .unwrap_err();
        assert!(
            matches!(&error, PowError::MissingDifficultyContext { first_height: height } if *height == first_height),
            "unexpected error at {first_height}: {error}"
        );
        assert!(error.to_string().contains(&first_height.to_string()));
        assert!(error.to_string().contains("context"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn grace_exactly_300_requires_context_but_301_allows_minimum_without_history() {
    let limit = CHAIN.params().pow_limit_bits;
    assert_eq!(CHAIN.params().target_spacing * 2, 300);
    let headers = window(&[limit, limit]);
    let last = headers.last().unwrap();
    assert!(matches!(
        expected_bits(CHAIN, &headers, 2033, last.time + 300),
        Err(PowError::MissingDifficultyContext { first_height: 2033 })
    ));
    assert_eq!(
        expected_bits(CHAIN, &headers, 2033, last.time + 301).unwrap(),
        CompactTarget::from_consensus(limit)
    );
}

#[test]
fn grace_exactly_300_uses_known_regular_bits_and_301_switches_to_minimum() {
    let limit = CHAIN.params().pow_limit_bits;
    let headers = window(&[REGULAR, limit]);
    let last = headers.last().unwrap();
    assert_eq!(
        expected_bits(CHAIN, &headers, 2033, last.time + 300).unwrap(),
        CompactTarget::from_consensus(REGULAR)
    );
    assert_eq!(
        expected_bits(CHAIN, &headers, 2033, last.time + 301).unwrap(),
        CompactTarget::from_consensus(limit)
    );
}

#[test]
fn earliest_nonminimum_in_a_midperiod_window_is_sufficient() {
    let limit = CHAIN.params().pow_limit_bits;
    let headers = window(&[REGULAR, limit, limit]);
    assert_eq!(
        expected_bits(CHAIN, &headers, 2033, headers[2].time + 150).unwrap(),
        CompactTarget::from_consensus(REGULAR)
    );
}

#[test]
fn lookup_stops_at_the_most_recent_nonminimum() {
    let limit = CHAIN.params().pow_limit_bits;
    let newer_regular = 0x1e00_ffff;
    let headers = window(&[REGULAR, newer_regular, limit, limit]);
    assert_eq!(
        expected_bits(CHAIN, &headers, 2033, headers[3].time + 150).unwrap(),
        CompactTarget::from_consensus(newer_regular)
    );
}

#[test]
fn minimum_at_a_period_boundary_is_sufficient_at_window_start_or_inside() {
    let limit = CHAIN.params().pow_limit_bits;
    let interval = CHAIN.params().retarget_interval;
    for (first_height, bits) in [
        (interval, vec![limit, limit]),
        // Regular bits before the boundary are irrelevant after it.
        (interval - 1, vec![REGULAR, limit, limit]),
    ] {
        let headers = window(&bits);
        assert_eq!(
            expected_bits(
                CHAIN,
                &headers,
                first_height,
                headers.last().unwrap().time + 150
            )
            .unwrap(),
            CompactTarget::from_consensus(limit)
        );
    }
}

#[test]
fn genesis_height_is_a_known_boundary_for_minimum_and_nonminimum() {
    let limit = CHAIN.params().pow_limit_bits;
    for (bits, expected) in [
        (vec![limit, limit, limit], limit),
        (vec![REGULAR, limit, limit], REGULAR),
    ] {
        let headers = window(&bits);
        assert_eq!(
            expected_bits(CHAIN, &headers, 0, headers.last().unwrap().time + 150).unwrap(),
            CompactTarget::from_consensus(expected)
        );
    }
}

#[test]
fn no_retarget_network_needs_no_earlier_regular_difficulty() {
    let chain = Chain::BitcoinRegtest;
    assert!(!chain.params().retargets);
    let limit = chain.params().pow_limit_bits;
    for bits in [[limit, limit], [REGULAR, REGULAR]] {
        let mut headers = window(&bits);
        headers[1].time = u32::MAX;
        for first_height in [2033, chain.params().retarget_interval - 2] {
            // No-retarget returns current bits even at a boundary, without
            // evaluating minimum-difficulty grace or overflowing header time.
            assert_eq!(
                expected_bits(chain, &headers, first_height, 0).unwrap(),
                headers[1].bits
            );
        }
    }
}
