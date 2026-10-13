use serde_json::Value;
use std::{collections::HashSet, path::PathBuf};
use urma_chain::observation::Chain;
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    address::destination_script,
    wallet::WalletError,
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

fn root(v: &Value) -> Root {
    Root::from_phrase(&IdentityPhrase::parse(text(&v["phrase"])).unwrap()).unwrap()
}

const CHAINS: [Chain; 5] = [
    Chain::BitcoinMainnet,
    Chain::LitecoinMainnet,
    Chain::BitcoinTestnet4,
    Chain::BitcoinRegtest,
    Chain::LitecoinTestnet,
];

#[test]
fn account_reproduces_the_published_xpub_and_addresses_per_chain() {
    let v = vectors();
    let root = root(&v);
    let rows = v["chains"].as_array().unwrap();
    assert_eq!(rows.len(), CHAINS.len());
    for row in rows {
        let chain = chain(text(&row["chain"]));
        let account = Account::from_root(chain, &root).unwrap();
        assert_eq!(account.chain().address_hrp(), text(&row["hrp"]));
        assert_eq!(account.xpub().to_string(), text(&row["account_xpub"]));
        let external = |index| {
            account
                .address(KeyPath::new(Branch::External, index))
                .unwrap()
        };
        assert_eq!(external(0), text(&row["external_0"]));
        assert_eq!(external(1), text(&row["external_1"]));
        assert_eq!(
            account.address(KeyPath::new(Branch::Internal, 0)).unwrap(),
            text(&row["internal_0"])
        );
        assert_eq!(account.receive_address().unwrap(), text(&row["external_0"]));
        assert_eq!(KeyPath::RECEIVE, KeyPath::new(Branch::External, 0));
    }
}

#[test]
fn receive_script_is_the_witness_script_of_the_published_receive_address() {
    let v = vectors();
    let root = root(&v);
    for row in v["chains"].as_array().unwrap() {
        let chain = chain(text(&row["chain"]));
        let account = Account::from_root(chain, &root).unwrap();
        let script = account.receive_script().unwrap();
        assert!(script.is_p2wpkh());
        assert_eq!(
            script,
            destination_script(text(&row["external_0"]), chain).unwrap()
        );
        assert_eq!(script, account.script(KeyPath::RECEIVE).unwrap());
        assert_eq!(
            account.script(KeyPath::new(Branch::Internal, 0)).unwrap(),
            destination_script(text(&row["internal_0"]), chain).unwrap()
        );
    }
}

#[test]
fn every_branch_and_index_matches_the_root_and_never_repeats() {
    let v = vectors();
    let root = root(&v);
    for chain in CHAINS {
        let account = Account::from_root(chain, &root).unwrap();
        let mut seen = HashSet::new();
        for branch in [Branch::External, Branch::Internal] {
            for index in 0..25 {
                let path = KeyPath::new(branch, index);
                let address = account.address(path).unwrap();
                assert_eq!(address, root.address(chain, branch, index).unwrap());
                assert!(address.starts_with(&format!("{}1q", chain.address_hrp())));
                assert_eq!(
                    account.script(path).unwrap(),
                    destination_script(&address, chain).unwrap()
                );
                assert!(seen.insert(address), "{chain:?} {path:?} repeats");
            }
        }
    }
}

#[test]
fn testnet_contexts_share_one_key_under_their_own_prefixes() {
    let v = vectors();
    let root = root(&v);
    let scripts: Vec<_> = [
        Chain::BitcoinTestnet4,
        Chain::BitcoinRegtest,
        Chain::LitecoinTestnet,
    ]
    .into_iter()
    .map(|chain| {
        let account = Account::from_root(chain, &root).unwrap();
        account.script(KeyPath::new(Branch::Internal, 3)).unwrap()
    })
    .collect();
    assert!(scripts.windows(2).all(|pair| pair[0] == pair[1]));
    let bitcoin = Account::from_root(Chain::BitcoinMainnet, &root).unwrap();
    let litecoin = Account::from_root(Chain::LitecoinMainnet, &root).unwrap();
    assert_ne!(
        bitcoin.receive_script().unwrap(),
        litecoin.receive_script().unwrap()
    );
}

#[test]
fn hardened_child_indexes_are_refused() {
    let v = vectors();
    let root = root(&v);
    let account = Account::from_root(Chain::LitecoinMainnet, &root).unwrap();
    let hardened = KeyPath::new(Branch::External, 1 << 31);
    assert!(matches!(
        account.address(hardened),
        Err(WalletError::Derivation(_))
    ));
    assert!(matches!(
        account.script(hardened),
        Err(WalletError::Derivation(_))
    ));
}
