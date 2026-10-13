use bitcoin::{
    Amount, ScriptBuf, Transaction, TxIn, TxOut, absolute,
    consensus::{deserialize, serialize},
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use std::num::NonZeroU64;
use urma_chain::observation::Chain;
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind},
};
use urma_identity::{phrase::IdentityPhrase, root::Root};
use urma_runtime::{
    config,
    error::Error,
    plan::PublicationPlan,
    publication::{SignedPublicPair, prepare_signed_bytes},
    wallet::FundingInput,
};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    funding::Funding,
    wallet::{FeeBudget, FeeRate, WalletError},
};

fn signer(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn account(chain: Chain) -> Account {
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    Account::new(chain, root.account(chain).unwrap()).unwrap()
}

fn funding(script: ScriptBuf, value: u64) -> Funding {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        }],
    };
    Funding {
        raw_transaction: hex::encode(serialize(&tx)),
        vout: 0,
    }
}

fn received(account: &Account) -> Vec<FundingInput> {
    vec![FundingInput {
        funding: funding(account.receive_script().unwrap(), 100_000),
        path: KeyPath::RECEIVE,
    }]
}

fn budget(chain: Chain, maximum: u64) -> FeeBudget {
    FeeBudget {
        chain: chain.genesis().unwrap(),
        rate: FeeRate(NonZeroU64::new(1).unwrap()),
        maximum_base_units: maximum,
    }
}

fn plan(
    chain: Chain,
    funder: &Account,
    author: &Keypair,
    pairs: &[SignedPublicPair],
) -> PublicationPlan {
    let last: Transaction =
        deserialize(&hex::decode(&pairs[pairs.len() - 1].plan.reveal).unwrap()).unwrap();
    PublicationPlan {
        version: 1,
        chain,
        author: author.x_only_public_key().0.to_string(),
        return_script: hex::encode(funder.receive_script().unwrap().as_bytes()),
        root_txid: last.compute_txid().to_string(),
        total_fee: pairs.iter().map(|pair| pair.fee).sum(),
        maximum_fee: 100_000,
        records: pairs.iter().map(|pair| pair.plan.clone()).collect(),
    }
}

#[test]
fn signed_pairs_preserve_author_chain_return_and_chained_funding() {
    let author = signer(7);
    let record = PublicRecord::Post("signed pair".into()).encode().unwrap();
    for chain in [Chain::BitcoinRegtest, Chain::LitecoinTestnet] {
        let funder = account(chain);
        let budget = budget(chain, 10_000);
        let first =
            prepare_signed_bytes(&record, &author, &funder, &received(&funder), budget).unwrap();
        let commit: Transaction = deserialize(&hex::decode(&first.plan.commit).unwrap()).unwrap();
        let reveal: Transaction = deserialize(&hex::decode(&first.plan.reveal).unwrap()).unwrap();
        let proof = envelope::verify_reveal(&reveal, &commit).unwrap();
        assert_eq!(proof.author, author.x_only_public_key().0);
        assert_eq!(
            reveal.output[0].value.to_sat(),
            config::publication_return(chain)
        );
        assert_eq!(
            reveal.output[0].script_pubkey,
            funder.receive_script().unwrap()
        );
        assert_eq!(
            commit.output[1].script_pubkey,
            funder.receive_script().unwrap()
        );
        assert_eq!(
            first.fee,
            100_000 - commit.output[1].value.to_sat() - reveal.output[0].value.to_sat()
        );
        assert!(!commit.input[0].witness.is_empty());
        let chained = vec![FundingInput {
            funding: Funding {
                raw_transaction: first.plan.commit.clone(),
                vout: 1,
            },
            path: KeyPath::RECEIVE,
        }];
        let second = prepare_signed_bytes(&record, &author, &funder, &chained, budget).unwrap();
        let next: Transaction = deserialize(&hex::decode(&second.plan.commit).unwrap()).unwrap();
        assert_eq!(next.input[0].previous_output.txid, commit.compute_txid());
        assert_eq!(next.input[0].previous_output.vout, 1);
        let fee = first.fee;
        plan(chain, &funder, &author, &[first, second])
            .validate()
            .unwrap();
        let exact = budget_with(budget, fee);
        prepare_signed_bytes(&record, &author, &funder, &received(&funder), exact).unwrap();
        let too_small = budget_with(budget, fee - 1);
        assert!(matches!(
            prepare_signed_bytes(&record, &author, &funder, &received(&funder), too_small),
            Err(Error::Wallet(WalletError::BudgetExceeded))
        ));
    }
}

fn budget_with(budget: FeeBudget, maximum: u64) -> FeeBudget {
    FeeBudget {
        maximum_base_units: maximum,
        ..budget
    }
}

#[test]
fn many_inputs_from_separate_paths_fund_the_first_commit() {
    let author = signer(7);
    let chain = Chain::LitecoinTestnet;
    let funder = account(chain);
    let record = PublicRecord::Post("many inputs".into()).encode().unwrap();
    let inputs: Vec<FundingInput> = [KeyPath::RECEIVE, KeyPath::new(Branch::Internal, 4)]
        .into_iter()
        .map(|path| FundingInput {
            funding: funding(funder.script(path).unwrap(), 20_000),
            path,
        })
        .collect();
    let pair =
        prepare_signed_bytes(&record, &author, &funder, &inputs, budget(chain, 10_000)).unwrap();
    let commit: Transaction = deserialize(&hex::decode(&pair.plan.commit).unwrap()).unwrap();
    assert_eq!(commit.input.len(), 2);
    let reveal: Transaction = deserialize(&hex::decode(&pair.plan.reveal).unwrap()).unwrap();
    assert_eq!(
        pair.fee,
        40_000 - commit.output[1].value.to_sat() - reveal.output[0].value.to_sat()
    );
    let mut valid = plan(chain, &funder, &author, std::slice::from_ref(&pair));
    valid.validate().unwrap();
    valid.return_script = hex::encode(
        funder
            .script(KeyPath::new(Branch::Internal, 0))
            .unwrap()
            .as_bytes(),
    );
    assert!(valid.validate().is_err());
}

#[test]
fn signed_pairs_reject_foreign_funding_and_chain() {
    let author = signer(7);
    let funder = account(Chain::BitcoinRegtest);
    let record = PublicRecord::Post("identity".into()).encode().unwrap();
    let budget = budget(Chain::BitcoinRegtest, 10_000);
    let foreign = vec![FundingInput {
        funding: funding(
            funder.script(KeyPath::new(Branch::Internal, 3)).unwrap(),
            100_000,
        ),
        path: KeyPath::RECEIVE,
    }];
    assert!(matches!(
        prepare_signed_bytes(&record, &author, &funder, &foreign, budget),
        Err(Error::Wallet(WalletError::WrongIdentity))
    ));
    let litecoin = account(Chain::LitecoinTestnet);
    assert!(
        prepare_signed_bytes(&record, &author, &litecoin, &received(&litecoin), budget).is_err()
    );
}

#[test]
fn avatar_signed_proofs_use_only_the_amended_128_byte_payload() {
    let author = signer(9);
    let record = PublicRecord::Avatar(Box::new([0xEF; 128]));
    let bytes = record.encode().unwrap();
    assert_eq!(bytes.len(), 136);
    assert_eq!(&bytes[..8], b"URMA\x00\x06\x00\x00");
    for chain in [Chain::BitcoinRegtest, Chain::LitecoinTestnet] {
        let funder = account(chain);
        let budget = budget(chain, 10_000);
        let pair =
            prepare_signed_bytes(&bytes, &author, &funder, &received(&funder), budget).unwrap();
        let commit: Transaction = deserialize(&hex::decode(&pair.plan.commit).unwrap()).unwrap();
        let reveal: Transaction = deserialize(&hex::decode(&pair.plan.reveal).unwrap()).unwrap();
        let proof = envelope::verify_reveal(&reveal, &commit).unwrap();
        assert_eq!(proof.record, bytes);
        assert_eq!(proof.author, author.x_only_public_key().0);
        assert_eq!(PublicRecord::decode(&proof.record).unwrap(), record);
        for size in [127, 129, 512] {
            let invalid = [RecordKind::Avatar.prefix().to_vec(), vec![0xEF; size]].concat();
            assert!(
                prepare_signed_bytes(&invalid, &author, &funder, &received(&funder), budget)
                    .is_err()
            );
            assert!(envelope::build(&invalid, &author).is_err());
        }
    }
}

#[test]
fn private_reveals_keep_ephemeral_authors_and_litecoin_return() {
    use rand::{SeedableRng, rngs::StdRng};
    use urma_core::{container, format::ContentType};
    use urma_runtime::litecoin;
    let author = signer(7);
    let back = account(Chain::LitecoinTestnet).receive_script().unwrap();
    let mut rng = StdRng::seed_from_u64(41);
    let records = container::seal(&[4; 32], b"private", ContentType::Opaque, &mut rng).unwrap();
    let first =
        litecoin::prepare(&records, 7, funding(back.clone(), 100_000), 1, 0, &mut rng).unwrap();
    let second =
        litecoin::prepare(&records, 7, funding(back.clone(), 100_000), 1, 0, &mut rng).unwrap();
    let mut authors = Vec::new();
    for plan in [first, second] {
        let commit: Transaction = deserialize(&hex::decode(plan.commit).unwrap()).unwrap();
        let reveal: Transaction = deserialize(&hex::decode(&plan.reveals[0]).unwrap()).unwrap();
        let envelope = envelope::verify_reveal(&reveal, &commit).unwrap();
        authors.push(envelope.author);
        assert_ne!(envelope.author, author.x_only_public_key().0);
        assert_eq!(
            reveal.output[0].value.to_sat(),
            config::LITECOIN_RETURN_LITOSHIS
        );
        assert_eq!(reveal.output[0].script_pubkey, back);
    }
    assert_ne!(authors[0], authors[1]);
}
