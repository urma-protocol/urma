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
use urma_identity::{
    identity::{IdentitySigner, IdentitySlot},
    keyring::Keyring,
    phrase::IdentityPhrase,
};
use urma_runtime::wallet::FundingInput;
use urma_wallet::{
    account::{Account, KeyPath},
    funding::Funding,
    wallet::{FeeBudget, FeeRate},
};

#[path = "../../urma-runtime/tests/support/publication_node.rs"]
#[allow(dead_code)]
mod publication_node;

fn regtest_budget(maximum: u64) -> FeeBudget {
    FeeBudget {
        chain: Chain::BitcoinRegtest.genesis().unwrap(),
        rate: FeeRate(NonZeroU64::new(1).unwrap()),
        maximum_base_units: maximum,
    }
}

#[test]
fn publication_signs_author_with_identity_and_funds_from_the_account() {
    let (_, v) = vectors();
    let keys =
        Keyring::recover(&IdentityPhrase::parse(v["phrase"].as_str().unwrap()).unwrap()).unwrap();
    let author = keys.identity(IdentitySlot::new(0).unwrap()).unwrap();
    let chain = Chain::BitcoinRegtest;
    let funder = Account::new(chain, keys.root().account(chain).unwrap()).unwrap();
    let prev = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: funder.receive_script().unwrap(),
        }],
    };
    let inputs = [FundingInput {
        funding: Funding {
            raw_transaction: hex::encode(serialize(&prev)),
            vout: 0,
        },
        path: KeyPath::RECEIVE,
    }];
    let record = urma_core::format::PublicRecord::Post("split roles".into())
        .encode()
        .unwrap();
    let prepare = |budget| {
        urma_runtime::publication::prepare_signed_bytes(&record, &author, &funder, &inputs, budget)
    };
    let plan = prepare(regtest_budget(2_000)).unwrap().plan;
    let commit: Transaction = deserialize(&hex::decode(&plan.commit).unwrap()).unwrap();
    let reveal: Transaction = deserialize(&hex::decode(&plan.reveal).unwrap()).unwrap();
    let proof = urma_core::envelope::verify_reveal(&reveal, &commit).unwrap();
    assert_eq!(proof.author.to_string(), v["slots"][0]["author"]);
    assert_eq!(
        reveal.output[0].script_pubkey,
        funder.receive_script().unwrap()
    );
    assert_eq!(
        funder.receive_address().unwrap(),
        v["chains"][3]["external_0"]
    );
    let funding_key = commit.input[0].witness.to_vec()[1].clone();
    assert_ne!(
        funding_key,
        author.public_key().to_bytes(),
        "roles share a key"
    );
    let funding_key = bitcoin::PublicKey::from_slice(&funding_key).unwrap();
    let sig = bitcoin::ecdsa::Signature::from_slice(&commit.input[0].witness.to_vec()[0]).unwrap();
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
            &funding_key.inner,
        )
        .unwrap();
    assert!(prepare(regtest_budget(1)).is_err(), "fee bound ignored");
    let litecoin = FeeBudget {
        chain: Chain::LitecoinTestnet.genesis().unwrap(),
        ..regtest_budget(2_000)
    };
    assert!(prepare(litecoin).is_err(), "budget chain mismatch accepted");
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

fn with_node(
    mock: &publication_node::Mock,
    vault: &Path,
    password: &Path,
    args: &[&str],
) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_urma"))
        .env("URMA_OUTPUT", "json")
        .env("URMA_VAULT", vault)
        .env("URMA_UNLOCK_FILE", password)
        .env("URMA_CONFIG", vault.with_extension("no-config"))
        .env("URMA_NETWORK", "bitcoin-regtest")
        .env("URMA_RPC_URL", &mock.config.rpc_url)
        .env("URMA_NODE_AUTH_FILE", &mock.config.cookie_file)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn wallet_commands_scan_select_and_send_from_the_bip84_account() {
    let temp = tempfile::tempdir().unwrap();
    let mock = publication_node::Mock::new(temp.path());
    let (phrase, pass, vault) = (
        temp.path().join("phrase"),
        temp.path().join("password"),
        temp.path().join("wallet.vault"),
    );
    private_file(&phrase, &format!("{}about", "abandon ".repeat(11)));
    private_file(&pass, "private wallet test password");
    let mut recover = vec!["key", "recover", "--phrase-file", path(&phrase)];
    recover.extend(["--password-file", path(&pass), "--output", path(&vault)]);
    success(cli(&recover));
    let funder = &mock.funder;
    let status = with_node(&mock, &vault, &pass, &["wallet", "status"]);
    assert_eq!(
        status["designated_address"],
        funder.receive_address().unwrap()
    );
    assert_eq!(status["spendable_confirmed_balance"], 100_000_000);
    assert_eq!(status["outputs"], 1);
    assert_eq!(status["outputs_verified"], true);
    assert_eq!(status.get("utxos"), None);
    let utxos = with_node(&mock, &vault, &pass, &["wallet", "utxos"]);
    assert_eq!(utxos["utxos"][0]["path"], "m/84'/1'/0'/0/0");
    assert_eq!(
        utxos["utxos"][0]["address"],
        funder.receive_address().unwrap()
    );
    let next = with_node(&mock, &vault, &pass, &["wallet", "address", "--next"]);
    let second = KeyPath::new(urma_wallet::account::Branch::External, 1);
    assert_eq!(next["path"], "m/84'/1'/0'/0/1");
    assert_eq!(next["address"], funder.address(second).unwrap());
    let destination = funder.address(second).unwrap();
    let mut send = vec!["wallet", "send", "--to", destination.as_str()];
    send.extend(["--amount", "50000", "--max-fee", "10000", "--yes"]);
    let sent = with_node(&mock, &vault, &pass, &send);
    assert_eq!(sent["status"], "broadcast");
    assert_eq!(sent["inputs"].as_array().unwrap().len(), 1);
    let change = KeyPath::new(urma_wallet::account::Branch::Internal, 0);
    assert_eq!(sent["change"]["path"], "m/84'/1'/0'/1/0");
    assert_eq!(sent["change"]["address"], funder.address(change).unwrap());
    let submissions = mock.state.lock().unwrap().submissions.clone();
    assert_eq!(submissions.len(), 1);
    let raw: Transaction = deserialize(&hex::decode(&submissions[0]).unwrap()).unwrap();
    assert_eq!(raw.compute_txid().to_string(), sent["txid"]);
    assert_eq!(raw.output[1].script_pubkey, funder.script(change).unwrap());
}
