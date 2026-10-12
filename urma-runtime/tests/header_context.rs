use bitcoin::{
    block::Header,
    consensus::encode::{deserialize, serialize},
};
use std::{
    error::Error as StdError,
    path::{Path, PathBuf},
};
use urma_chain::{
    observation::Chain,
    pow::{PowError, check_header_pow, expected_bits},
};
use urma_runtime::{
    error::{Context, Error},
    p2p::HeaderChain,
};

// All headers come unchanged from committed, real Litecoin retarget fixtures.
// These tests exercise context/classification/cache behavior, without sockets,
// mining synthetic headers or claiming worker/provider policy coverage.
struct Case {
    chain: Chain,
    first_height: u64,
    headers: [Header; 3],
}

fn fixture(name: &str) -> Vec<Header> {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../urma-chain/tests/fixtures")
            .join(name),
    )
    .unwrap()
    .lines()
    .map(|line| deserialize(&hex::decode(line).unwrap()).unwrap())
    .collect()
}

fn cases() -> [Case; 2] {
    let mainnet = fixture("ltc-mainnet-retarget-3185280.hex");
    let testnet = fixture("ltc-testnet-retarget-4902912.hex");
    assert_eq!(mainnet.len(), 2018);
    assert_eq!(testnet.len(), 2018);
    let cases = [
        Case {
            chain: Chain::LitecoinMainnet,
            first_height: 3_185_278,
            headers: mainnet[2015..2018].try_into().unwrap(),
        },
        // Two consecutive minimum-difficulty blocks, then the authentic
        // ordinary-difficulty successor only 34 seconds after its parent.
        Case {
            chain: Chain::LitecoinTestnet,
            first_height: 4_902_534,
            headers: testnet[1639..1642].try_into().unwrap(),
        },
    ];
    for case in &cases {
        for header in &case.headers {
            check_header_pow(header, case.chain).unwrap();
        }
        for pair in case.headers.windows(2) {
            assert_eq!(pair[1].prev_blockhash, pair[0].block_hash());
        }
        assert_pow_cause(case, &missing_context(case));
    }
    cases
}

fn missing_context(case: &Case) -> PowError {
    expected_bits(
        case.chain,
        &case.headers[..2],
        case.first_height,
        case.headers[2].time,
    )
    .unwrap_err()
}

fn assert_pow_cause(case: &Case, cause: &PowError) {
    match case.chain {
        Chain::LitecoinMainnet => assert!(
            matches!(
                cause,
                PowError::ShortWindow {
                    needed: 2017,
                    got: 2
                }
            ),
            "{cause:?}"
        ),
        Chain::LitecoinTestnet => assert!(
            matches!(cause, PowError::MissingDifficultyContext { first_height } if *first_height == case.first_height),
            "{cause:?}"
        ),
        _ => unreachable!(),
    }
}

fn pow_source(error: &Error) -> &PowError {
    let mut source: &(dyn StdError + 'static) = error;
    loop {
        if let Some(cause) = source.downcast_ref::<PowError>() {
            return cause;
        }
        source = source
            .source()
            .expect("typed PowError must remain in the source chain");
    }
}

fn assert_context(case: &Case, error: &Error) {
    assert!(error.is_header_context(), "{error:?}");
    assert_pow_cause(case, pow_source(error));
}

fn anchored(case: &Case, path: &Path) -> Result<HeaderChain, Error> {
    HeaderChain::anchored(
        case.chain,
        path.to_owned(),
        case.first_height,
        case.headers[0],
        case.headers[1].block_hash(),
    )
}

#[test]
fn typed_context_retains_pow_source_through_recursive_context_wrappers() {
    for case in cases() {
        let typed = Error::HeaderContext(missing_context(&case));
        assert_context(&case, &typed);
        assert_pow_cause(
            &case,
            typed.source().unwrap().downcast_ref::<PowError>().unwrap(),
        );
        let message = typed.to_string();
        let once = Err::<(), Error>(typed).context("read cache").unwrap_err();
        assert_context(&case, &once);
        assert!(matches!(
            once.source().unwrap().downcast_ref::<Error>(),
            Some(Error::HeaderContext(_))
        ));
        let twice = Err::<(), Error>(once)
            .with_context(|| "open anchored chain".to_owned())
            .unwrap_err();
        assert_context(&case, &twice);
        assert!(matches!(
            twice.source().unwrap().downcast_ref::<Error>(),
            Some(Error::Context { .. })
        ));

        // Classification must depend on the type, not the displayed wording.
        let untyped = Error::Invalid(message);
        assert!(!untyped.is_header_context());
        assert!(untyped.source().is_none());
        let wrapped = Err::<(), Error>(untyped)
            .context("read cache")
            .with_context(|| "outer".to_owned())
            .unwrap_err();
        assert!(!wrapped.is_header_context());
    }
}

#[test]
fn anchored_short_context_cache_returns_typed_error_without_reset_or_deletion() {
    for case in cases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headers.bin");
        let raw: Vec<u8> = case.headers.iter().flat_map(serialize).collect();
        std::fs::write(&path, &raw).unwrap();
        for _ in 0..2 {
            let error = match anchored(&case, &path) {
                Err(error) => error,
                Ok(_) => panic!("short context must propagate, not silently reset"),
            };
            assert!(matches!(error, Error::Context { .. })); // Cache offset wrapper.
            assert_context(&case, &error);
            assert!(path.is_file());
            assert_eq!(std::fs::read(&path).unwrap(), raw);
        }
    }
}

#[test]
fn live_short_context_failure_rolls_back_tip_index_and_partial_batch() {
    for case in cases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headers.bin");
        let mut chain = anchored(&case, &path).unwrap();
        chain.persist().unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(before, serialize(&case.headers[0]));
        let error = chain
            .extend(&case.headers[1..], case.headers[2].time + 60)
            .unwrap_err();
        assert_context(&case, &error);
        assert_eq!(chain.tip_height(), case.first_height);
        assert_eq!(chain.tip_hash(), case.headers[0].block_hash());
        assert_eq!(chain.synced_count(), 0);
        assert_eq!(chain.locator(), [case.headers[0].block_hash()]);
        assert_eq!(chain.header_at(case.first_height).unwrap(), case.headers[0]);
        for (i, header) in case.headers.iter().enumerate().skip(1) {
            assert!(chain.height_of(header.block_hash()).is_err());
            assert!(chain.header_at(case.first_height + i as u64).is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        chain.persist().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // The earlier valid pinned successor was also rolled back; it can
        // still be admitted normally after the rejected multi-header batch.
        chain
            .extend(&case.headers[1..2], case.headers[2].time + 60)
            .unwrap();
        assert_eq!(chain.synced_count(), 1);
        assert_eq!(chain.tip_hash(), case.headers[1].block_hash());
    }
}

#[test]
fn pinned_first_retarget_successor_still_loads_without_previous_history() {
    let headers = fixture("ltc-mainnet-retarget-3185280.hex");
    let tail = &headers[2016..2018];
    assert_ne!(tail[0].bits, tail[1].bits);
    assert!(matches!(
        expected_bits(Chain::LitecoinMainnet, &tail[..1], 3_185_279, tail[1].time),
        Err(PowError::ShortWindow { .. })
    ));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("headers.bin");
    let open = || {
        HeaderChain::anchored(
            Chain::LitecoinMainnet,
            path.clone(),
            3_185_279,
            tail[0],
            tail[1].block_hash(),
        )
        .unwrap()
    };
    let mut live = open();
    live.extend(&tail[1..], tail[1].time + 60).unwrap();
    live.persist().unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(raw, tail.iter().flat_map(serialize).collect::<Vec<_>>());
    let reloaded = open();
    assert_eq!(reloaded.tip_height(), 3_185_280);
    assert_eq!(reloaded.tip_hash(), tail[1].block_hash());
    assert_eq!(reloaded.synced_count(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), raw);
}

#[test]
fn corrupt_cache_and_wrong_checkpoint_or_pinned_successor_keep_legacy_reset() {
    let case = cases().into_iter().next().unwrap();
    for damage in [
        "trailing-byte",
        "wrong-checkpoint",
        "wrong-pinned-successor",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headers.bin");
        let mut raw: Vec<u8> = match damage {
            "wrong-checkpoint" => case.headers[1..].iter().flat_map(serialize).collect(),
            _ => case.headers[..2].iter().flat_map(serialize).collect(),
        };
        if damage == "trailing-byte" {
            raw.push(0);
        }
        std::fs::write(&path, raw).unwrap();
        // A wrong pin is another actual fixture header's hash; no PoW header
        // is changed or invented for the negative control.
        let next = if damage == "wrong-pinned-successor" {
            case.headers[2].block_hash()
        } else {
            case.headers[1].block_hash()
        };
        let fresh = HeaderChain::anchored(
            case.chain,
            path.clone(),
            case.first_height,
            case.headers[0],
            next,
        )
        .unwrap();
        assert_eq!(fresh.tip_hash(), case.headers[0].block_hash(), "{damage}");
        assert_eq!(fresh.tip_height(), case.first_height);
        assert_eq!(fresh.synced_count(), 0);
        assert!(!path.exists(), "{damage}");
    }
}
