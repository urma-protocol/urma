use bitcoin::{
    NetworkKind,
    bip32::Xpriv,
    secp256k1::{Message, Secp256k1},
};
use serde_json::Value;
use std::path::PathBuf;
use urma_chain::observation::Chain;
use urma_identity::{
    bip85,
    identity::{IdentitySigner, IdentitySlot},
    keyring::Keyring,
    phrase::IdentityPhrase,
    root::{Branch, Root},
};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/vectors/identity-vault-v2/vectors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn chain(label: &str) -> Chain {
    match label {
        "bitcoin-mainnet" => Chain::BitcoinMainnet,
        "litecoin-mainnet" => Chain::LitecoinMainnet,
        "bitcoin-testnet4" => Chain::BitcoinTestnet4,
        "bitcoin-regtest" => Chain::BitcoinRegtest,
        "litecoin-testnet" => Chain::LitecoinTestnet,
        other => panic!("unknown vector chain {other}"),
    }
}

fn bytes32(value: &Value) -> [u8; 32] {
    hex::decode(text(value)).unwrap().try_into().unwrap()
}

#[test]
fn phrase_seed_master_and_fingerprint() {
    let v = vectors();
    let phrase = IdentityPhrase::parse(text(&v["phrase"])).unwrap();
    assert_eq!(phrase.export_words().unwrap().as_str(), text(&v["phrase"]));
    let seed = phrase.seed().unwrap();
    assert_eq!(hex::encode(&seed[..]), text(&v["seed"]));
    let master = Xpriv::new_master(NetworkKind::Main, &seed[..]).unwrap();
    assert_eq!(master.to_string(), text(&v["master_xprv"]));
    let root = Root::from_phrase(&phrase).unwrap();
    assert_eq!(root.fingerprint().to_string(), text(&v["fingerprint"]));
    for (name, words) in v["invalid_phrases"].as_object().unwrap() {
        assert!(IdentityPhrase::parse(text(words)).is_err(), "{name}");
    }
}

#[test]
fn wallet_accounts_descriptors_and_addresses() {
    let v = vectors();
    let phrase = IdentityPhrase::parse(text(&v["phrase"])).unwrap();
    let keyring = Keyring::recover(&phrase).unwrap();
    let root = keyring.root();
    let secp = Secp256k1::new();
    for row in v["chains"].as_array().unwrap() {
        let chain = chain(text(&row["chain"]));
        assert_eq!(chain.address_hrp(), text(&row["hrp"]));
        let xpub = root.account_xpub(chain).unwrap();
        assert_eq!(xpub.to_string(), text(&row["account_xpub"]));
        let account = root.account(chain).unwrap();
        assert_eq!(bitcoin::bip32::Xpub::from_priv(&secp, &account), xpub);
        assert_eq!(account.depth, 3);
        assert_eq!(
            account.network == NetworkKind::Main,
            text(&row["account_xpub"]).starts_with("xpub")
        );
        let descriptors = root.descriptors(chain).unwrap();
        assert_eq!(descriptors[0], text(&row["descriptors"][0]));
        assert_eq!(descriptors[1], text(&row["descriptors"][1]));
        let address = |branch, index| root.address(chain, branch, index).unwrap();
        assert_eq!(address(Branch::External, 0), text(&row["external_0"]));
        assert_eq!(address(Branch::External, 1), text(&row["external_1"]));
        assert_eq!(address(Branch::Internal, 0), text(&row["internal_0"]));
    }
    assert_eq!(
        root.account_xpub(Chain::BitcoinTestnet4).unwrap(),
        root.account_xpub(Chain::LitecoinTestnet).unwrap()
    );
    assert!(
        root.address(Chain::BitcoinMainnet, Branch::External, 1 << 31)
            .is_err()
    );
}

#[test]
fn identity_slots_bip85_hex_and_bip340() {
    let v = vectors();
    let phrase = IdentityPhrase::parse(text(&v["phrase"])).unwrap();
    let master = Xpriv::new_master(NetworkKind::Main, phrase.seed().unwrap().as_ref()).unwrap();
    let keyring = Keyring::recover(&phrase).unwrap();
    assert_eq!(keyring.identities().len(), 64);
    assert_eq!(keyring.active_slot().index(), 0);
    assert_eq!(keyring.identities()[63].name, "identity-63");
    let digest = Message::from_digest(bytes32(&v["digest"]));
    let aux = bytes32(&v["aux"]);
    let secp = Secp256k1::new();
    for row in v["slots"].as_array().unwrap() {
        let index = u16::try_from(row["slot"].as_u64().unwrap()).unwrap();
        let slot = IdentitySlot::new(index).unwrap();
        let path = text(&row["path"])
            .replace('\'', "h")
            .parse::<bitcoin::bip32::DerivationPath>()
            .unwrap();
        let child = master.derive_priv(&secp, &path).unwrap();
        assert_eq!(
            hex::encode(child.private_key.secret_bytes()),
            text(&row["k"])
        );
        let entropy = bip85::hex(&master, 32, u32::from(index)).unwrap();
        assert_eq!(hex::encode(entropy.as_slice()), text(&row["entropy"]));
        assert_eq!(text(&row["scalar"]), text(&row["entropy"]));
        let key = keyring.identity(slot).unwrap();
        assert_eq!(key.author().0.to_string(), text(&row["author"]));
        let signature = key.sign_author_with_aux_rand(digest, &aux);
        assert_eq!(hex::encode(signature.serialize()), text(&row["signature"]));
        let plain = key.sign_author(digest).unwrap();
        secp.verify_schnorr(&plain, &digest, &key.author().0)
            .unwrap();
        assert_eq!(key.public_key().inner.x_only_public_key().0, key.author().0);
    }
    assert!(IdentitySlot::new(64).is_err());
}
