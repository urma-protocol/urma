#[path = "support/wallet_electrum.rs"]
mod wallet_electrum;

use std::num::NonZeroU64;
use urma_chain::observation::Chain;
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_runtime::{
    error::Error,
    node::Node,
    wallet::{Coin, Selection},
};
use urma_wallet::account::{Account, Branch, KeyPath};
use wallet_electrum::{PHRASE, funder, start};

fn external(index: u32) -> KeyPath {
    KeyPath::new(Branch::External, index)
}

fn internal(index: u32) -> KeyPath {
    KeyPath::new(Branch::Internal, index)
}

fn values(coins: &[Coin]) -> Vec<u64> {
    coins.iter().map(|coin| coin.value).collect()
}

fn select(
    node: &Node,
    account: &Account,
    target: u64,
    max_fee: u64,
) -> Result<Selection, Error> {
    node.select_coins(account, target, NonZeroU64::MIN, max_fee)
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
    let paths: Vec<KeyPath> = view.coins.iter().map(|coin| coin.path).collect();
    assert_eq!(paths, [internal(5), external(20), external(0)]);
    let outpoints: Vec<_> = view.coins.iter().map(|coin| coin.outpoint).collect();
    assert_eq!(
        outpoints,
        [fixture.outpoint(3), fixture.outpoint(1), fixture.outpoint(0)]
    );
    assert!(view.coins.iter().all(|coin| coin.height == 1));
    assert_eq!(view.next_change, 6);
    assert_eq!(view.reported, 3);
    assert!(view.verified);
    assert!(fixture.listed(&account, external(40)));
    assert!(!fixture.listed(&account, external(41)));
    assert!(fixture.listed(&account, internal(25)));
    assert!(!fixture.listed(&account, internal(26)));
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
        assert!(fixture.listed(&account, KeyPath::new(branch, 19)));
        assert!(!fixture.listed(&account, KeyPath::new(branch, 20)));
    }
}

#[test]
fn several_coins_on_one_address_are_all_reported() {
    let account = funder();
    let coins = [(external(0), 1_000), (external(0), 3_000), (internal(0), 2_000)];
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
    assert!(select(&mock.node(), &litecoin, 1_000, 10_000).is_err());
}

#[test]
fn selection_takes_the_largest_coins_first() {
    let account = funder();
    let coins = [
        (external(0), 5_000),
        (external(1), 80_000),
        (internal(0), 30_000),
        (internal(1), 50_000),
    ];
    let (_fixture, mock) = start(&account, &coins);
    let node = mock.node();
    let one = select(&node, &account, 60_000, 10_000).unwrap();
    assert_eq!(values(&one.coins), [80_000]);
    assert_eq!(one.coins[0].path, external(1));
    assert!(one.fee > 0 && one.fee <= 10_000);
    assert_eq!(one.change, 80_000 - 60_000 - one.fee);
    let two = select(&node, &account, 100_000, 10_000).unwrap();
    assert_eq!(values(&two.coins), [80_000, 50_000]);
    assert!(two.fee > one.fee);
    assert_eq!(two.change, 130_000 - 100_000 - two.fee);
}

#[test]
fn selection_refuses_more_than_fifty_inputs() {
    let account = funder();
    let coins: Vec<(KeyPath, u64)> = (0..60).map(|index| (external(index % 3), 1_000)).collect();
    let (_fixture, mock) = start(&account, &coins);
    let node = mock.node();
    let within = select(&node, &account, 30_000, 20_000).unwrap();
    assert!(within.coins.len() <= 50);
    assert!(within.coins.len() > 30);
    assert!(select(&node, &account, 52_000, 20_000).is_err());
}

#[test]
fn dust_change_is_folded_into_the_fee_only_within_max_fee() {
    let account = funder();
    let (_fixture, mock) = start(&account, &[(internal(2), 100_000)]);
    let node = mock.node();
    let probe = select(&node, &account, 50_000, 10_000).unwrap();
    assert!(probe.change > 0);
    let target = 100_000 - probe.fee - 100;
    let folded = select(&node, &account, target, 10_000).unwrap();
    assert_eq!(values(&folded.coins), [100_000]);
    assert_eq!(folded.change, 0);
    assert_eq!(folded.fee, 100_000 - target);
    assert!(select(&node, &account, target, folded.fee - 1).is_err());
}

#[test]
fn insufficient_funds_are_refused() {
    let account = funder();
    let coins = [(external(0), 60_000), (internal(0), 75_000)];
    let (_fixture, mock) = start(&account, &coins);
    let node = mock.node();
    assert!(matches!(
        select(&node, &account, 200_000, 10_000),
        Err(Error::Missing(_))
    ));
    assert!(matches!(
        select(&node, &account, 135_000, 10_000),
        Err(Error::Missing(_))
    ));
}
