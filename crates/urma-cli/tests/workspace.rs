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
        vec!["git", "clone", "not-a-txid"],
        vec!["git", "publish", "--plan"],
        vec!["git", "resume", "missing-plan"],
        vec!["capture", "ingest", "missing-image"],
        vec!["capture", "recover", "missing-directory"],
        vec!["wire", "plan"],
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
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["wallet", "quote", "100", "--rate", "2", "--max-fee", "200"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["fee_base_units"], 200);
    assert_eq!(value["estimate_only"], true);
    assert_eq!(value["broadcast"], false);
    let over = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(["wallet", "quote", "101", "--rate", "2", "--max-fee", "200"])
        .output()
        .unwrap();
    assert!(!over.status.success());
    assert!(over.stdout.is_empty());
}

#[test]
fn clone_accepts_the_human_interface_and_refuses_node_flags() {
    let binary = env!("CARGO_BIN_EXE_urma");
    let help = Command::new(binary)
        .args(["git", "clone", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("Litecoin mainnet is the default"));
    assert!(text.contains("published repository name"));
    for plumbing in ["--cookie", "--rpc-url", "--vault", "--limits", "--chain"] {
        assert!(!text.contains(plumbing));
        let rejected = Command::new(binary)
            .args(["git", "clone", &"0".repeat(64), plumbing, "unused"])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(2));
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("urma-000000000000")).unwrap();
    for network in [vec![], vec!["--testnet"]] {
        let output = Command::new(binary)
            .current_dir(directory.path())
            .args(["git", "clone", &"0".repeat(64), "urma-000000000000"])
            .args(network)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("already exists; choose another directory")
        );
    }
}

#[test]
fn publication_name_is_overridable_and_validated_before_network_access() {
    let binary = env!("CARGO_BIN_EXE_urma");
    let help = Command::new(binary)
        .args(["git", "prepare", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--name"));
    assert!(text.contains("source directory name"));
    let invalid = Command::new(binary)
        .args(["git", "prepare", "--name", "../unsafe"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert!(
        String::from_utf8(invalid.stderr)
            .unwrap()
            .contains("unsafe repository name")
    );
    assert!(invalid.stdout.is_empty());
}
