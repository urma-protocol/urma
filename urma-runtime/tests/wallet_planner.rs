#[path = "support/wallet_electrum.rs"]
mod wallet_electrum;

use bitcoin::{
    CompressedPublicKey, OutPoint, ScriptBuf, Transaction, TxIn,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use urma_core::format::PublicRecord;
use urma_runtime::{
    config,
    node::Node,
    plan::{PlanLimits, PublicationPlan, prepare_atomic, prepare_multipart},
};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    funding::Funding,
};
use wallet_electrum::{funder, start};

fn author() -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap())
}

fn decode(raw: &str) -> Transaction {
    deserialize(&hex::decode(raw).unwrap()).unwrap()
}

fn witness_script(tx: &Transaction, index: usize) -> ScriptBuf {
    let public = CompressedPublicKey::from_slice(tx.input[index].witness.nth(1).unwrap()).unwrap();
    ScriptBuf::new_p2wpkh(&public.wpubkey_hash())
}

fn limits(max_fee: u64, max_records: u32) -> PlanLimits {
    PlanLimits {
        fee_rate: 1,
        max_fee,
        max_records,
    }
}

fn atomic(node: &Node, account: &Account, max_fee: u64) -> PublicationPlan {
    let record = PublicRecord::Post("wallet v2 return".into());
    prepare_atomic(node, &author(), account, &record, limits(max_fee, 1)).unwrap()
}

fn script_hex(script: &ScriptBuf) -> String {
    hex::encode(script.as_bytes())
}

#[test]
fn atomic_plan_returns_to_the_designated_address_from_the_largest_coin() {
    let account = funder();
    let coins = [
        (KeyPath::new(Branch::Internal, 3), 200_000),
        (KeyPath::new(Branch::External, 7), 300_000),
    ];
    let (fixture, mock) = start(&account, &coins);
    let plan = atomic(&mock.node(), &account, 20_000);
    plan.validate().unwrap();
    let receive = account.receive_script().unwrap();
    assert_eq!(plan.return_script, script_hex(&receive));
    assert_eq!(plan.author, author().x_only_public_key().0.to_string());
    let [pair] = plan.records.as_slice() else {
        panic!("atomic plan holds one record");
    };
    let [funding] = pair.funding.as_slice() else {
        panic!("one coin covers the plan");
    };
    assert_eq!(funding.vout, 1);
    assert_eq!(decode(&funding.raw_transaction), fixture.funding);
    let commit = decode(&pair.commit);
    let reveal = decode(&pair.reveal);
    assert_eq!(commit.input.len(), 1);
    assert_eq!(commit.input[0].previous_output, fixture.outpoint(1));
    assert_eq!(
        witness_script(&commit, 0),
        account.script(coins[1].0).unwrap()
    );
    assert_eq!(commit.output[1].script_pubkey, receive);
    assert_eq!(reveal.output[0].script_pubkey, receive);
    assert_eq!(
        reveal.output[0].value.to_sat(),
        config::publication_return(account.chain())
    );
    assert_eq!(plan.root_txid, reveal.compute_txid().to_string());
}

#[test]
fn first_commit_spends_every_selected_coin_in_value_order() {
    let account = funder();
    let coins = [
        (KeyPath::new(Branch::External, 4), 2_600),
        (KeyPath::new(Branch::Internal, 2), 3_000),
    ];
    let (fixture, mock) = start(&account, &coins);
    let plan = atomic(&mock.node(), &account, 2_000);
    plan.validate().unwrap();
    let pair = &plan.records[0];
    assert_eq!(pair.funding.len(), 2);
    let commit = decode(&pair.commit);
    let spent: Vec<OutPoint> = commit
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    assert_eq!(spent, [fixture.outpoint(1), fixture.outpoint(0)]);
    assert_eq!(
        witness_script(&commit, 0),
        account.script(coins[1].0).unwrap()
    );
    assert_eq!(
        witness_script(&commit, 1),
        account.script(coins[0].0).unwrap()
    );
    assert_eq!(
        commit.output[1].script_pubkey,
        account.receive_script().unwrap()
    );
}

#[test]
fn later_commits_chain_from_vout_one_at_the_receive_path() {
    let account = funder();
    let (fixture, mock) = start(&account, &[(KeyPath::new(Branch::Internal, 0), 500_000)]);
    let plan = prepare_multipart(
        &mock.node(),
        &author(),
        &account,
        &[0x5a; 600],
        *b"wallettv",
        limits(60_000, 16),
    )
    .unwrap();
    plan.validate().unwrap();
    assert!(plan.records.len() >= 3);
    let receive = account.receive_script().unwrap();
    let first = decode(&plan.records[0].commit);
    assert_eq!(first.input[0].previous_output, fixture.outpoint(0));
    assert_eq!(
        witness_script(&first, 0),
        account.script(KeyPath::new(Branch::Internal, 0)).unwrap()
    );
    for window in plan.records.windows(2) {
        let previous = decode(&window[0].commit);
        let commit = decode(&window[1].commit);
        let reveal = decode(&window[1].reveal);
        let [chained] = window[1].funding.as_slice() else {
            panic!("later records chain from one prevout");
        };
        assert_eq!(chained.raw_transaction, window[0].commit);
        assert_eq!(chained.vout, 1);
        assert_eq!(commit.input.len(), 1);
        assert_eq!(
            commit.input[0].previous_output,
            OutPoint::new(previous.compute_txid(), 1)
        );
        assert_eq!(previous.output[1].script_pubkey, receive);
        assert_eq!(witness_script(&commit, 0), receive);
        assert_eq!(commit.output[1].script_pubkey, receive);
        assert_eq!(reveal.output[0].script_pubkey, receive);
    }
}

#[test]
fn validation_rejects_a_return_script_other_than_the_designated_address() {
    let account = funder();
    let (_fixture, mock) = start(&account, &[(KeyPath::new(Branch::External, 0), 300_000)]);
    let plan = atomic(&mock.node(), &account, 20_000);
    plan.validate().unwrap();
    let receive = account.receive_script().unwrap();
    let hash = bitcoin::PubkeyHash::from_byte_array(receive.as_bytes()[2..22].try_into().unwrap());
    let wrong = [
        account.script(KeyPath::new(Branch::Internal, 0)).unwrap(),
        account.script(KeyPath::new(Branch::External, 1)).unwrap(),
        ScriptBuf::new_p2pkh(&hash),
        ScriptBuf::new(),
    ];
    for script in wrong {
        let mut tampered = plan.clone();
        tampered.return_script = script_hex(&script);
        assert!(tampered.validate().is_err(), "{script:?} accepted");
    }
    let mut garbage = plan.clone();
    garbage.return_script = "zz".into();
    assert!(garbage.validate().is_err());
}

#[test]
fn validation_rejects_undeclared_or_altered_prevouts() {
    let account = funder();
    let coins = [
        (KeyPath::new(Branch::External, 4), 2_600),
        (KeyPath::new(Branch::Internal, 2), 3_000),
    ];
    let (fixture, mock) = start(&account, &coins);
    let plan = atomic(&mock.node(), &account, 2_000);
    plan.validate().unwrap();
    let mut dropped = plan.clone();
    dropped.records[0].funding.pop();
    assert!(dropped.validate().is_err());
    let mut swapped = plan.clone();
    swapped.records[0].funding.reverse();
    assert!(swapped.validate().is_err());
    let mut extra = plan.clone();
    extra.records[0].funding.push(Funding {
        raw_transaction: hex::encode(serialize(&fixture.funding)),
        vout: 0,
    });
    assert!(extra.validate().is_err());
    let mut lookalike = fixture.funding.clone();
    lookalike.input = vec![TxIn {
        previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([8; 32]), 0),
        ..TxIn::default()
    }];
    let mut foreign = plan.clone();
    foreign.records[0].funding[0].raw_transaction = hex::encode(serialize(&lookalike));
    assert!(foreign.validate().is_err());
    let mut richer = fixture.funding.clone();
    richer.output[1].value = bitcoin::Amount::from_sat(3_001);
    let mut altered = plan.clone();
    altered.records[0].funding[0].raw_transaction = hex::encode(serialize(&richer));
    assert!(altered.validate().is_err());
}

#[test]
fn validation_rejects_a_chained_record_off_vout_one() {
    let account = funder();
    let (_fixture, mock) = start(&account, &[(KeyPath::new(Branch::Internal, 0), 500_000)]);
    let plan = prepare_multipart(
        &mock.node(),
        &author(),
        &account,
        &[0x5a; 600],
        *b"wallettv",
        limits(60_000, 16),
    )
    .unwrap();
    let mut moved = plan.clone();
    moved.records[1].funding[0].vout = 0;
    assert!(moved.validate().is_err());
    let mut doubled = plan.clone();
    let chained = doubled.records[1].funding[0].clone();
    doubled.records[1].funding.push(chained);
    assert!(doubled.validate().is_err());
}
