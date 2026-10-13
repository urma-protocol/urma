#[path = "support/wallet_electrum.rs"]
mod wallet_electrum;

use bitcoin::CompressedPublicKey;
use std::num::NonZeroU64;
use urma_chain::observation::Chain;
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_runtime::{
    error::Error,
    transfer::{TransferRequest, prepare},
    wallet::{Coin, Selection},
};
use urma_wallet::account::{Account, Branch, KeyPath};
use wallet_electrum::{Fixture, PHRASE, funder, scripthash, start};

fn external(index: u32) -> KeyPath {
    KeyPath::new(Branch::External, index)
}

fn internal(index: u32) -> KeyPath {
    KeyPath::new(Branch::Internal, index)
}

fn listed(fixture: &Fixture, account: &Account, path: KeyPath) -> bool {
    let key = scripthash(&account.script(path).unwrap());
    fixture.listed.lock().unwrap().contains(&key)
}

fn values(coins: &[Coin]) -> Vec<u64> {
    coins.iter().map(|coin| coin.value).collect()
}

fn paths(selection: &Selection) -> Vec<KeyPath> {
    selection.inputs.iter().map(|input| input.path).collect()
}

fn request(account: &Account, amount: u64, max_fee: u64) -> TransferRequest {
    TransferRequest {
        destination: account.script(external(30)).unwrap(),
        amount,
        rate: NonZeroU64::MIN,
        max_fee,
    }
}

#[test]
fn wallet_view_discovers_coins_across_a_gap_of_twenty() {
    let account = funder();
    let coins = [
        (external(0), 10_000),
        (external(20), 20_000),
        (external(41), 30_000),
        (internal(5), 40_000),
    ];
    let (fixture, mock) = start(&account, &coins);
    let view = mock.node().wallet(&account).unwrap();
    assert_eq!(values(&view.coins), [40_000, 20_000, 10_000]);
    let found: Vec<KeyPath> = view.coins.iter().map(|coin| coin.path).collect();
    assert_eq!(found, [internal(5), external(20), external(0)]);
    let outpoints: Vec<_> = view.coins.iter().map(|coin| coin.outpoint).collect();
    assert_eq!(
        outpoints,
        [
            fixture.outpoint(3),
            fixture.outpoint(1),
            fixture.outpoint(0)
        ]
    );
    assert!(view.coins.iter().all(|coin| coin.height == 1));
    assert_eq!(view.next_change, 6);
    assert_eq!(view.reported, 3);
    assert!(view.verified);
    assert!(listed(&fixture, &account, external(40)));
    assert!(!listed(&fixture, &account, external(41)));
    assert!(listed(&fixture, &account, internal(25)));
    assert!(!listed(&fixture, &account, internal(26)));
}

#[test]
fn empty_wallet_scans_one_gap_per_branch() {
    let account = funder();
    let (fixture, mock) = start(&account, &[]);
    let view = mock.node().wallet(&account).unwrap();
    assert!(view.coins.is_empty());
    assert_eq!(view.next_change, 0);
    assert_eq!(view.reported, 0);
    for branch in [Branch::External, Branch::Internal] {
        assert!(listed(&fixture, &account, KeyPath::new(branch, 19)));
        assert!(!listed(&fixture, &account, KeyPath::new(branch, 20)));
    }
}

#[test]
fn several_coins_on_one_address_are_all_reported() {
    let account = funder();
    let coins = [
        (external(0), 1_000),
        (external(0), 3_000),
        (internal(0), 2_000),
    ];
    let (_fixture, mock) = start(&account, &coins);
    let view = mock.node().wallet(&account).unwrap();
    assert_eq!(values(&view.coins), [3_000, 2_000, 1_000]);
    assert_eq!(view.next_change, 1);
}

#[test]
fn wallet_view_refuses_an_account_of_another_chain() {
    let account = funder();
    let (_fixture, mock) = start(&account, &[(external(0), 10_000)]);
    let root = Root::from_phrase(&IdentityPhrase::parse(PHRASE).unwrap()).unwrap();
    let litecoin = Account::new(
        Chain::LitecoinTestnet,
        root.account(Chain::LitecoinTestnet).unwrap(),
    )
    .unwrap();
    assert!(mock.node().wallet(&litecoin).is_err());
    assert!(mock.node().select_coins(&litecoin, 1_000, 0).is_err());
}

#[test]
fn selection_takes_the_largest_coins_first_and_charges_each_input() {
    let account = funder();
    let coins = [
        (external(0), 5_000),
        (external(1), 80_000),
        (internal(0), 30_000),
        (internal(1), 50_000),
    ];
    let (fixture, mock) = start(&account, &coins);
    let node = mock.node();
    let one = node.select_coins(&account, 60_000, 0).unwrap();
    assert_eq!(paths(&one), [external(1)]);
    assert_eq!(one.total, 80_000);
    assert_eq!(one.next_change, 2);
    let two = node.select_coins(&account, 100_000, 0).unwrap();
    assert_eq!(paths(&two), [external(1), internal(1)]);
    assert_eq!(two.total, 130_000);
    let charged = node.select_coins(&account, 115_000, 10_000).unwrap();
    assert_eq!(paths(&charged), [external(1), internal(1), internal(0)]);
    assert_eq!(charged.total, 160_000);
    for input in &charged.inputs {
        let (outpoint, previous) = input.funding.prevout().unwrap();
        assert_eq!(outpoint.txid, fixture.outpoint(0).txid);
        assert_eq!(previous.script_pubkey, account.script(input.path).unwrap());
    }
}

#[test]
fn selection_refuses_more_than_fifty_inputs() {
    let account = funder();
    let coins: Vec<(KeyPath, u64)> = (0..60).map(|index| (external(index % 3), 1_000)).collect();
    let (_fixture, mock) = start(&account, &coins);
    let node = mock.node();
    let within = node.select_coins(&account, 50_000, 0).unwrap();
    assert_eq!(within.inputs.len(), 50);
    let refused = node.select_coins(&account, 51_000, 0).err().unwrap();
    assert!(refused.to_string().contains("50"), "{refused}");
    assert!(!matches!(refused, Error::Missing(_)));
}

#[test]
fn insufficient_funds_are_refused() {
    let account = funder();
    let coins = [(external(0), 60_000), (internal(0), 75_000)];
    let (_fixture, mock) = start(&account, &coins);
    let node = mock.node();
    assert!(matches!(
        node.select_coins(&account, 200_000, 0),
        Err(Error::Missing(_))
    ));
    assert!(matches!(
        node.select_coins(&account, 134_000, 1_000),
        Err(Error::Missing(_))
    ));
    assert!(node.select_coins(&account, 133_000, 1_000).is_ok());
}

#[test]
fn transfer_change_takes_the_next_unused_internal_path() {
    let account = funder();
    let coins = [(internal(2), 100_000), (external(3), 40_000)];
    let (_fixture, mock) = start(&account, &coins);
    let paid = prepare(&mock.node(), &account, &request(&account, 50_000, 10_000)).unwrap();
    let change = paid.change.unwrap();
    assert_eq!(change.path, internal(3));
    assert_eq!(change.value, 100_000 - 50_000 - paid.fee);
    let tx = &paid.transaction;
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        tx.output[0].script_pubkey,
        account.script(external(30)).unwrap()
    );
    assert_eq!(
        tx.output[1].script_pubkey,
        account.script(internal(3)).unwrap()
    );
    let public = CompressedPublicKey::from_slice(tx.input[0].witness.nth(1).unwrap()).unwrap();
    assert_eq!(
        bitcoin::ScriptBuf::new_p2wpkh(&public.wpubkey_hash()),
        account.script(internal(2)).unwrap()
    );
}

#[test]
fn dust_change_is_folded_into_the_fee_only_within_max_fee() {
    let account = funder();
    let (_fixture, mock) = start(&account, &[(internal(2), 100_000)]);
    let node = mock.node();
    let probe = prepare(&node, &account, &request(&account, 50_000, 10_000)).unwrap();
    assert!(probe.change.is_some());
    let amount = 100_000 - probe.fee - 100;
    let folded = prepare(&node, &account, &request(&account, amount, 10_000)).unwrap();
    assert!(folded.change.is_none());
    assert_eq!(folded.fee, 100_000 - amount);
    assert_eq!(folded.transaction.output.len(), 1);
    assert!(prepare(&node, &account, &request(&account, amount, folded.fee - 1)).is_err());
}
