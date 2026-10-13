use bitcoin::{
    Amount, Transaction, TxOut,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use std::{num::NonZeroU64, os::unix::fs::PermissionsExt, path::Path, process::Command};
use urma_chain::observation::Chain;
use urma_identity::{identity::IdentitySigner, keyring::Keyring, phrase::IdentityPhrase};
use urma_wallet::{
    funding::Funding,
    wallet::{FeeBudget, FeeRate},
};

#[test]
fn publication_verifies_same_author_and_funder_and_fee_bound() {
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let keys = Keyring::recover(&phrase).unwrap();
    let signer = keys.active().unwrap();
    let prev = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: urma_wallet::signing::script(&signer).unwrap(),
        }],
    };
    let funding = Funding {
        raw_transaction: hex::encode(serialize(&prev)),
        vout: 0,
    };
    let budget = FeeBudget {
        chain: Chain::BitcoinRegtest.genesis().unwrap(),
        rate: FeeRate(NonZeroU64::new(1).unwrap()),
        maximum_base_units: 2_000,
    };
    let record = urma_core::format::PublicRecord::Post("shared identity".into());
    let plan = urma_runtime::publication::prepare_signed_bytes(
        &record.encode().unwrap(),
        &signer,
        funding.clone(),
        Chain::BitcoinRegtest,
        budget,
    )
    .unwrap()
    .plan;
    let commit: Transaction = deserialize(&hex::decode(&plan.commit).unwrap()).unwrap();
    let reveal: Transaction = deserialize(&hex::decode(&plan.reveal).unwrap()).unwrap();
    let proof = urma_core::envelope::verify_reveal(&reveal, &commit).unwrap();
    assert_eq!(
        proof.author,
        signer.public_key().inner.x_only_public_key().0
    );
    let witness = commit.input[0].witness.to_vec();
    assert_eq!(witness[1], signer.public_key().to_bytes());
    let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0]).unwrap();
    let digest = SighashCache::new(&commit)
        .p2wpkh_signature_hash(
            0,
            &prev.output[0].script_pubkey,
            prev.output[0].value,
            EcdsaSighashType::All,
        )
        .unwrap();
    Secp256k1::new()
        .verify_ecdsa(
            &Message::from_digest(digest.to_byte_array()),
            &sig.signature,
            &signer.public_key().inner,
        )
        .unwrap();
    let other = keys
        .identity(urma_identity::identity::IdentitySlot::new(1).unwrap())
        .unwrap();
    assert!(
        urma_runtime::publication::prepare_signed_bytes(
            &record.encode().unwrap(),
            &other,
            funding.clone(),
            Chain::BitcoinRegtest,
            budget
        )
        .is_err()
    );
    assert!(
        urma_runtime::publication::prepare_signed_bytes(
            &record.encode().unwrap(),
            &signer,
            funding.clone(),
            Chain::LitecoinTestnet,
            budget
        )
        .is_err()
    );
    assert!(
        urma_runtime::publication::prepare_signed_bytes(
            &record.encode().unwrap(),
            &signer,
            funding,
            Chain::BitcoinRegtest,
            FeeBudget {
                maximum_base_units: 1,
                ..budget
            }
        )
        .is_err()
    );
}

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .args(args)
        .output()
        .unwrap()
}
fn unlocked(vault: &Path, password: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .env("URMA_VAULT", vault)
        .env("URMA_UNLOCK_FILE", password)
        .env("URMA_CONFIG", vault.with_extension("no-config"))
        .args(args)
        .output()
        .unwrap()
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn success(output: std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.lines().all(|line| line.starts_with("Log: ")),
        "{stderr}"
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_recovers_without_vault_and_never_prints_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let vault = root.join("identity.vault");
    let pass = root.join("password");
    let phrase = root.join("recovery");
    let password = "private CLI test password";
    std::fs::write(&pass, password).unwrap();
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    let created = cli(&[
        "key",
        "create",
        "--vault",
        path(&vault),
        "--password-file",
        path(&pass),
        "--recovery-out",
        path(&phrase),
        "--name",
        "journalist",
    ]);
    let words = std::fs::read_to_string(&phrase).unwrap();
    for output in [&created.stdout, &created.stderr] {
        let text = String::from_utf8_lossy(output);
        assert!(!text.contains(&words));
        assert!(!text.contains(password));
    }
    success(created);
    assert_eq!(
        std::fs::metadata(&phrase).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = success(unlocked(&vault, &pass, &["key", "list"]));
    let more = root.join("more.vault");
    success(unlocked(
        &vault,
        &pass,
        &["key", "add", "--name", "editor", "--output", path(&more)],
    ));
    let selected = root.join("selected.vault");
    success(unlocked(
        &more,
        &pass,
        &["key", "select", "--slot", "1", "--output", path(&selected)],
    ));
    let selected_public = success(unlocked(&selected, &pass, &["key", "list"]));
    assert_eq!(selected_public["identities"][1]["active"], true);
    for p in [&vault, &more, &selected] {
        std::fs::remove_file(p).unwrap();
    }
    let recovered = root.join("recovered.vault");
    let report = success(cli(&[
        "key",
        "recover",
        "--phrase-file",
        path(&phrase),
        "--password-file",
        path(&pass),
        "--output",
        path(&recovered),
    ]));
    assert_eq!(report["metadata_recovered"], false);
    let public = success(unlocked(&recovered, &pass, &["key", "list"]));
    assert_eq!(public["identities"].as_array().unwrap().len(), 64);
    assert_eq!(
        public["identities"][0]["author"],
        original["identities"][0]["author"]
    );
    assert_eq!(
        public["identities"][1]["author"],
        selected_public["identities"][1]["author"]
    );
    assert_eq!(words.split_whitespace().count(), 12);
    let address = success(unlocked(
        &recovered,
        &pass,
        &["wallet", "address", "--testnet"],
    ));
    assert_eq!(address["balance_checked"], false);
    assert_eq!(address["path"], "m/84'/1'/0'/0/0");
    assert_eq!(
        address["designated_address"],
        public["wallets"]["litecoin-testnet"]["designated_address"]
    );
    assert_eq!(public["identities"][0].get("funding_public_key"), None);
    std::fs::write(&pass, "another private wrong password").unwrap();
    let denied = unlocked(&recovered, &pass, &["key", "list"]);
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains("another private wrong password"));
    let json = public.to_string();
    assert!(!json.contains(&words));
    assert!(!json.contains(password));
}

fn vectors() -> (std::path::PathBuf, serde_json::Value) {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/identity-vault-v2");
    let json = std::fs::read(directory.join("vectors.json")).unwrap();
    (directory, serde_json::from_slice(&json).unwrap())
}

fn private_file(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn on_network(vault: &Path, password: &Path, network: &str, args: &[&str]) -> serde_json::Value {
    success(
        Command::new(env!("CARGO_BIN_EXE_urma"))
            .env("URMA_OUTPUT", "json")
            .env("URMA_VAULT", vault)
            .env("URMA_UNLOCK_FILE", password)
            .env("URMA_CONFIG", vault.with_extension("no-config"))
            .env("URMA_NETWORK", network)
            .args(args)
            .output()
            .unwrap(),
    )
}

#[test]
fn recovered_v2_vault_reproduces_public_authors_addresses_and_descriptors() {
    let (_, v) = vectors();
    let temp = tempfile::tempdir().unwrap();
    let (phrase, pass, vault) = (
        temp.path().join("phrase"),
        temp.path().join("password"),
        temp.path().join("recovered.vault"),
    );
    private_file(&phrase, v["phrase"].as_str().unwrap());
    private_file(&pass, v["vault"]["password"].as_str().unwrap());
    let args = ["key", "recover", "--phrase-file", path(&phrase)];
    let mut args = args.to_vec();
    args.extend(["--password-file", path(&pass), "--output", path(&vault)]);
    success(cli(&args));
    let listed = success(unlocked(&vault, &pass, &["key", "list"]));
    assert_eq!(listed["fingerprint"], v["fingerprint"]);
    for slot in v["slots"].as_array().unwrap() {
        let index = usize::try_from(slot["slot"].as_u64().unwrap()).unwrap();
        assert_eq!(listed["identities"][index]["author"], slot["author"]);
    }
    for chain in v["chains"].as_array().unwrap() {
        let name = chain["chain"].as_str().unwrap();
        let wallet = &listed["wallets"][name];
        assert_eq!(wallet["path"], chain["path"], "{name}");
        assert_eq!(wallet["designated_address"], chain["external_0"], "{name}");
        let exported = on_network(&vault, &pass, name, &["wallet", "export"]);
        assert_eq!(exported["chain"], name);
        assert_eq!(exported["path"], chain["path"]);
        assert_eq!(exported["fingerprint"], v["fingerprint"]);
        assert_eq!(exported["account_xpub"], chain["account_xpub"]);
        assert_eq!(exported["descriptors"]["external"], chain["descriptors"][0]);
        assert_eq!(exported["descriptors"]["internal"], chain["descriptors"][1]);
        assert_eq!(exported["secrets"], false);
        let address = on_network(&vault, &pass, name, &["wallet", "address"]);
        assert_eq!(address["designated_address"], chain["external_0"], "{name}");
        let text = format!("{listed}{exported}{address}");
        assert!(!text.contains(v["phrase"].as_str().unwrap()));
        assert!(!text.contains(v["master_xprv"].as_str().unwrap()));
        assert!(!text.contains(v["seed"].as_str().unwrap()));
    }
}

#[test]
fn v2_vault_vector_unlocks_and_v1_vaults_and_wrong_lengths_are_refused() {
    let (directory, v) = vectors();
    let temp = tempfile::tempdir().unwrap();
    let pass = temp.path().join("password");
    private_file(&pass, v["vault"]["password"].as_str().unwrap());
    let valid = directory.join("valid.vault");
    let listed = success(unlocked(&valid, &pass, &["key", "list"]));
    let names: Vec<&str> = v["vault"]["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    for (slot, name) in names.iter().enumerate() {
        assert_eq!(listed["identities"][slot]["name"], *name);
        assert_eq!(
            listed["identities"][slot]["author"],
            v["slots"][slot]["author"]
        );
    }
    let active = usize::try_from(v["vault"]["active_slot"].as_u64().unwrap()).unwrap();
    assert_eq!(listed["identities"][active]["active"], true);
    let old = unlocked(&directory.join("version-1.vault"), &pass, &["key", "list"]);
    assert!(!old.status.success());
    assert!(old.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&old.stderr);
    assert!(
        stderr.contains("unsupported identity vault version"),
        "{stderr}"
    );
    for (label, words) in v["invalid_phrases"].as_object().unwrap() {
        let phrase = temp.path().join(label);
        private_file(&phrase, words.as_str().unwrap());
        let output = temp.path().join(format!("{label}.vault"));
        let refused = cli(&[
            "key",
            "recover",
            "--phrase-file",
            path(&phrase),
            "--password-file",
            path(&pass),
            "--output",
            path(&output),
        ]);
        assert!(!refused.status.success(), "{label} phrase accepted");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("expected 12 English BIP39 words"),
            "{label}: {stderr}"
        );
        assert!(!output.exists(), "{label} wrote a vault");
    }
}
