use bitcoin::{BlockHash, Txid, hashes::Hash};
use rand::{SeedableRng, rngs::StdRng};
use std::{num::NonZeroU64, process::Command};
use urma_chain::observation::{BlockRef, ChainId, InclusionTrust, Observation, Placement};
use urma_core::{container, format::ContentType};
use urma_identity::keys::RecoverySecret;
use urma_profiles::private::{CapturedOriginal, FileOriginal, seal_capture, seal_file};
use urma_wallet::wallet::{FeeBudget, FeeRate, WalletError};
use urma_workflows::publication::{JournalError, ResumeAction, reconcile};
use zeroize::Zeroizing;

#[test]
fn private_adapters_share_the_canonical_codec_with_injected_entropy() {
    let root = [41; 32];
    let secret = RecoverySecret::import(Zeroizing::new(root));
    let bytes = b"same original, different application contract";
    let file = seal_file(
        &secret,
        FileOriginal {
            bytes,
            content_type: ContentType::Opaque,
        },
        &mut StdRng::seed_from_u64(17),
    )
    .unwrap();
    let capture = seal_capture(
        &secret,
        CapturedOriginal {
            bytes,
            content_type: ContentType::Opaque,
        },
        &mut StdRng::seed_from_u64(17),
    )
    .unwrap();
    let core = container::seal(
        &root,
        bytes,
        ContentType::Opaque,
        &mut StdRng::seed_from_u64(17),
    )
    .unwrap();
    assert_eq!(file, core);
    assert_eq!(capture, core);
    assert_eq!(&*container::open(&root, &file).unwrap(), bytes);
}

#[test]
fn budgets_and_reorg_observations_cannot_imply_success() {
    let chain = ChainId(BlockHash::from_byte_array([1; 32]));
    let budget = FeeBudget {
        chain,
        rate: FeeRate(NonZeroU64::new(2).unwrap()),
        maximum_base_units: 100,
    };
    assert_eq!(budget.quote(50).unwrap(), 100);
    assert!(matches!(budget.quote(51), Err(WalletError::BudgetExceeded)));
    assert!(matches!(budget.quote(u64::MAX), Err(WalletError::Overflow)));
    let block = BlockRef {
        height: 5,
        hash: BlockHash::from_byte_array([2; 32]),
    };
    let txid = Txid::from_byte_array([3; 32]);
    let mut observation = Observation {
        chain,
        txid,
        tip: block,
        placement: Placement::Orphaned(block),
        trust: InclusionTrust::ProviderClaim,
    };
    assert_eq!(
        reconcile(chain, txid, &observation).unwrap(),
        ResumeAction::ReconcileReorg
    );
    observation.placement = Placement::Unknown;
    assert_eq!(
        reconcile(chain, txid, &observation).unwrap(),
        ResumeAction::RecheckMissing
    );
    let other = ChainId(BlockHash::from_byte_array([4; 32]));
    assert!(matches!(
        reconcile(other, txid, &observation),
        Err(JournalError::ObservationMismatch)
    ));
}

#[test]
fn nested_cli_help_and_missing_arguments_are_honest() {
    let binary = env!("CARGO_BIN_EXE_urma");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for group in ["git", "wire", "archive", "capture", "key", "wallet"] {
        assert!(help.contains(group));
        assert!(
            Command::new(binary)
                .args([group, "--help"])
                .status()
                .unwrap()
                .success()
        );
    }
    for args in [
        vec!["git", "prepare", "missing-repository"],
        vec!["git", "publish", "missing-plan"],
        vec!["git", "resume", "missing-plan"],
        vec!["capture", "ingest", "missing-image"],
        vec!["capture", "recover", "missing-directory"],
        vec!["wire", "index"],
        vec!["wallet", "status"],
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    let malformed = Command::new(binary)
        .args(["git", "inspect", "not-a-txid"])
        .output()
        .unwrap();
    assert_eq!(malformed.status.code(), Some(2));
    assert!(
        !Command::new(binary)
            .arg("seal")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn quote_is_pure_bounded_arithmetic_and_no_wallet_claim() {
    let genesis = "01".repeat(32);
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .args([
            "wallet",
            "quote",
            "--genesis",
            &genesis,
            "--vbytes",
            "100",
            "--rate",
            "2",
            "--max-fee",
            "200",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["fee_base_units"], 200);
    assert_eq!(value["estimate_only"], true);
    assert_eq!(value["broadcast"], false);
    let over = Command::new(env!("CARGO_BIN_EXE_urma"))
        .args([
            "wallet",
            "quote",
            "--genesis",
            &genesis,
            "--vbytes",
            "101",
            "--rate",
            "2",
            "--max-fee",
            "200",
        ])
        .output()
        .unwrap();
    assert!(!over.status.success());
    assert!(over.stdout.is_empty());
}
