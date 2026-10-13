use bitcoin::{
    Amount, BlockHash, CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxIn,
    TxOut, Txid, absolute, ecdsa::Signature, hashes::Hash, transaction::Version,
};
use std::num::NonZeroU64;
use urma_chain::observation::{Chain, ChainId};
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    signing::verify_p2wpkh_signature,
    wallet::{FeeBudget, FeeRate, SpendRequest, WalletError},
};

const PHRASE: &str = "abandon amount liar amount expire adjust cage candy arch gather drum buyer";

fn account(chain: Chain) -> Account {
    let root = Root::from_phrase(&IdentityPhrase::parse(PHRASE).unwrap()).unwrap();
    Account::new(chain, root.account(chain).unwrap()).unwrap()
}

fn budget() -> FeeBudget {
    FeeBudget {
        chain: ChainId(BlockHash::all_zeros()),
        rate: FeeRate(NonZeroU64::MIN),
        maximum_base_units: 1_000_000,
    }
}

fn prevout(script: ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: script,
    }
}

fn spending(inputs: u32, destination: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..inputs)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), vout),
                ..TxIn::default()
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: destination,
        }],
    }
}

fn refused(
    account: &Account,
    tx: &Transaction,
    prevouts: &[TxOut],
    paths: &[KeyPath],
) -> WalletError {
    let request = SpendRequest {
        transaction: tx,
        prevouts,
        budget: budget(),
    };
    account.sign(&request, paths).unwrap_err()
}

#[test]
fn prevout_of_another_path_is_refused() {
    let account = account(Chain::LitecoinMainnet);
    let tx = spending(1, account.receive_script().unwrap());
    let internal = prevout(account.script(KeyPath::new(Branch::Internal, 1)).unwrap());
    for claimed in [
        KeyPath::new(Branch::External, 1),
        KeyPath::new(Branch::Internal, 0),
        KeyPath::new(Branch::Internal, 2),
    ] {
        assert!(matches!(
            refused(&account, &tx, std::slice::from_ref(&internal), &[claimed]),
            WalletError::WrongIdentity
        ));
    }
}

#[test]
fn prevout_of_another_account_or_script_form_is_refused() {
    let bitcoin = account(Chain::BitcoinMainnet);
    let litecoin = account(Chain::LitecoinMainnet);
    let tx = spending(1, bitcoin.receive_script().unwrap());
    let foreign = prevout(litecoin.receive_script().unwrap());
    assert!(matches!(
        refused(&bitcoin, &tx, &[foreign], &[KeyPath::RECEIVE]),
        WalletError::WrongIdentity
    ));
    let own = bitcoin.receive_script().unwrap();
    let hash = PubkeyHash::from_byte_array(own.as_bytes()[2..22].try_into().unwrap());
    let legacy = prevout(ScriptBuf::new_p2pkh(&hash));
    assert!(matches!(
        refused(&bitcoin, &tx, &[legacy], &[KeyPath::RECEIVE]),
        WalletError::WrongIdentity
    ));
}

#[test]
fn one_wrong_input_refuses_the_whole_spend() {
    let account = account(Chain::BitcoinRegtest);
    let tx = spending(3, account.receive_script().unwrap());
    let paths = [
        KeyPath::RECEIVE,
        KeyPath::new(Branch::Internal, 0),
        KeyPath::new(Branch::External, 5),
    ];
    let mut prevouts: Vec<TxOut> = paths
        .iter()
        .map(|path| prevout(account.script(*path).unwrap()))
        .collect();
    prevouts[2] = prevout(account.script(KeyPath::new(Branch::External, 6)).unwrap());
    assert!(matches!(
        refused(&account, &tx, &prevouts, &paths),
        WalletError::WrongIdentity
    ));
}

#[test]
fn input_prevout_and_path_counts_must_agree() {
    let account = account(Chain::BitcoinTestnet4);
    let paths = [KeyPath::RECEIVE, KeyPath::new(Branch::Internal, 0)];
    let prevouts: Vec<TxOut> = paths
        .iter()
        .map(|path| prevout(account.script(*path).unwrap()))
        .collect();
    let tx = spending(2, account.receive_script().unwrap());
    assert!(matches!(
        refused(&account, &tx, &prevouts, &paths[..1]),
        WalletError::InvalidFunding
    ));
    assert!(matches!(
        refused(&account, &tx, &prevouts[..1], &paths),
        WalletError::InvalidFunding
    ));
    let empty = spending(0, account.receive_script().unwrap());
    assert!(matches!(
        refused(&account, &empty, &[], &[]),
        WalletError::InvalidFunding
    ));
}

#[test]
fn duplicate_outpoints_and_prefilled_script_sigs_are_refused() {
    let account = account(Chain::LitecoinTestnet);
    let paths = [KeyPath::RECEIVE, KeyPath::new(Branch::Internal, 0)];
    let prevouts: Vec<TxOut> = paths
        .iter()
        .map(|path| prevout(account.script(*path).unwrap()))
        .collect();
    let mut duplicate = spending(2, account.receive_script().unwrap());
    duplicate.input[1].previous_output = duplicate.input[0].previous_output;
    assert!(matches!(
        refused(&account, &duplicate, &prevouts, &paths),
        WalletError::InvalidFunding
    ));
    let mut prefilled = spending(2, account.receive_script().unwrap());
    prefilled.input[1].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    assert!(matches!(
        refused(&account, &prefilled, &prevouts, &paths),
        WalletError::InvalidFunding
    ));
}

#[test]
fn each_witness_key_hashes_to_its_own_path_script() {
    let account = account(Chain::LitecoinMainnet);
    let paths = [
        KeyPath::new(Branch::Internal, 9),
        KeyPath::RECEIVE,
        KeyPath::new(Branch::External, 19),
    ];
    let prevouts: Vec<TxOut> = paths
        .iter()
        .map(|path| prevout(account.script(*path).unwrap()))
        .collect();
    let tx = spending(
        3,
        account.script(KeyPath::new(Branch::Internal, 10)).unwrap(),
    );
    let request = SpendRequest {
        transaction: &tx,
        prevouts: &prevouts,
        budget: budget(),
    };
    let signed = account.sign(&request, &paths).unwrap();
    assert_eq!(signed.output, tx.output);
    for (index, (previous, path)) in prevouts.iter().zip(paths).enumerate() {
        let witness = &signed.input[index].witness;
        assert_eq!(witness.len(), 2);
        let public = CompressedPublicKey::from_slice(witness.nth(1).unwrap()).unwrap();
        assert_eq!(
            ScriptBuf::new_p2wpkh(&public.wpubkey_hash()),
            account.script(path).unwrap()
        );
        let signature = Signature::from_slice(witness.nth(0).unwrap()).unwrap();
        verify_p2wpkh_signature(&tx, index, previous, &signature, &public).unwrap();
    }
}
