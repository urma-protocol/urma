use bitcoin::{
    Amount, BlockHash, CompressedPublicKey, OutPoint, Transaction, TxIn, TxOut, Txid, absolute,
    ecdsa::Signature, hashes::Hash, transaction::Version,
};
use std::num::NonZeroU64;
use urma_chain::observation::{Chain, ChainId};
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    signing::verify_p2wpkh_signature,
    wallet::{FeeBudget, FeeRate, SpendRequest, WalletError},
};

fn account(chain: Chain) -> Account {
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    Account::new(chain, root.account(chain).unwrap()).unwrap()
}

fn budget(maximum: u64) -> FeeBudget {
    FeeBudget {
        chain: ChainId(BlockHash::all_zeros()),
        rate: FeeRate(NonZeroU64::MIN),
        maximum_base_units: maximum,
    }
}

#[test]
fn receive_address_is_the_bip84_external_zero() {
    assert_eq!(
        account(Chain::BitcoinMainnet).receive_address().unwrap(),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    for chain in [Chain::LitecoinMainnet, Chain::LitecoinTestnet] {
        let account = account(chain);
        for path in [KeyPath::RECEIVE, KeyPath::new(Branch::Internal, 7)] {
            assert_eq!(
                account.address(path).unwrap(),
                root.address(chain, path.branch, path.index).unwrap()
            );
        }
    }
}

#[test]
fn account_refuses_a_key_of_another_network() {
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    let mainnet = root.account(Chain::LitecoinMainnet).unwrap();
    assert!(matches!(
        Account::new(Chain::LitecoinTestnet, mainnet),
        Err(WalletError::WrongNetwork)
    ));
}

#[test]
fn every_input_is_signed_by_its_own_child() {
    let account = account(Chain::LitecoinTestnet);
    let paths = [KeyPath::RECEIVE, KeyPath::new(Branch::Internal, 3)];
    let prevouts: Vec<TxOut> = paths
        .iter()
        .map(|path| TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: account.script(*path).unwrap(),
        })
        .collect();
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), vout),
                ..TxIn::default()
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: account.receive_script().unwrap(),
        }],
    };
    let request = SpendRequest {
        transaction: &transaction,
        prevouts: &prevouts,
        budget: budget(1_000),
    };
    let signed = account.sign(&request, &paths).unwrap();
    for (index, previous) in prevouts.iter().enumerate() {
        let witness = &signed.input[index].witness;
        let signature = Signature::from_slice(witness.nth(0).unwrap()).unwrap();
        let public = CompressedPublicKey::from_slice(witness.nth(1).unwrap()).unwrap();
        verify_p2wpkh_signature(&transaction, index, previous, &signature, &public).unwrap();
    }
    let swapped = [paths[1], paths[0]];
    assert!(matches!(
        account.sign(&request, &swapped),
        Err(WalletError::WrongIdentity)
    ));
    let tight = SpendRequest {
        budget: budget(999),
        ..request
    };
    assert!(matches!(
        account.sign(&tight, &paths),
        Err(WalletError::BudgetExceeded)
    ));
}
