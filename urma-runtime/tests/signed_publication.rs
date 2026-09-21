use bitcoin::{
    Amount, Transaction, TxIn, TxOut, absolute,
    consensus::{deserialize, serialize},
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use std::num::NonZeroU64;
use urma_chain::observation::Chain;
use urma_core::{envelope, format::PublicRecord};
use urma_runtime::{config, error::Error, publication::prepare_signed_bytes};
use urma_wallet::{
    funding::Funding,
    wallet::{FeeBudget, FeeRate, WalletError},
};

fn signer(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn funding(signer: &Keypair) -> Funding {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: urma_wallet::signing::script(signer).unwrap(),
        }],
    };
    Funding {
        raw_transaction: hex::encode(serialize(&tx)),
        vout: 0,
    }
}

#[test]
fn signed_pairs_preserve_author_chain_return_and_chained_funding() {
    let author = signer(7);
    let record = PublicRecord::Post("signed pair".into()).encode().unwrap();
    for chain in [Chain::BitcoinRegtest, Chain::LitecoinTestnet] {
        let budget = FeeBudget {
            chain: chain.genesis().unwrap(),
            rate: FeeRate(NonZeroU64::new(1).unwrap()),
            maximum_base_units: 10_000,
        };
        let first =
            prepare_signed_bytes(&record, &author, funding(&author), chain, budget).unwrap();
        let commit: Transaction = deserialize(&hex::decode(&first.plan.commit).unwrap()).unwrap();
        let reveal: Transaction = deserialize(&hex::decode(&first.plan.reveal).unwrap()).unwrap();
        let proof = envelope::verify_reveal(&reveal, &commit).unwrap();
        assert_eq!(proof.author, author.x_only_public_key().0);
        assert_eq!(
            reveal.output[0].value.to_sat(),
            config::publication_return(chain)
        );
        assert_eq!(
            first.fee,
            100_000 - commit.output[1].value.to_sat() - reveal.output[0].value.to_sat()
        );
        assert!(!commit.input[0].witness.is_empty());
        let second = prepare_signed_bytes(
            &record,
            &author,
            Funding {
                raw_transaction: first.plan.commit,
                vout: 1,
            },
            chain,
            budget,
        )
        .unwrap();
        let next: Transaction = deserialize(&hex::decode(second.plan.commit).unwrap()).unwrap();
        assert_eq!(next.input[0].previous_output.txid, commit.compute_txid());
        assert_eq!(next.input[0].previous_output.vout, 1);
        let exact = FeeBudget {
            maximum_base_units: first.fee,
            ..budget
        };
        prepare_signed_bytes(&record, &author, funding(&author), chain, exact).unwrap();
        let too_small = FeeBudget {
            maximum_base_units: first.fee - 1,
            ..budget
        };
        assert!(matches!(
            prepare_signed_bytes(&record, &author, funding(&author), chain, too_small),
            Err(Error::Wallet(WalletError::BudgetExceeded))
        ));
    }
}

#[test]
fn signed_pairs_reject_wrong_author_and_chain() {
    let author = signer(7);
    let record = PublicRecord::Post("identity".into()).encode().unwrap();
    let budget = FeeBudget {
        chain: Chain::BitcoinRegtest.genesis().unwrap(),
        rate: FeeRate(NonZeroU64::new(1).unwrap()),
        maximum_base_units: 10_000,
    };
    assert!(matches!(
        prepare_signed_bytes(
            &record,
            &signer(8),
            funding(&author),
            Chain::BitcoinRegtest,
            budget
        ),
        Err(Error::Wallet(WalletError::WrongIdentity))
    ));
    assert!(
        prepare_signed_bytes(
            &record,
            &author,
            funding(&author),
            Chain::LitecoinTestnet,
            budget
        )
        .is_err()
    );
}

#[test]
fn private_reveals_keep_ephemeral_authors_and_litecoin_return() {
    use rand::{SeedableRng, rngs::StdRng};
    use urma_core::{container, format::ContentType};
    use urma_runtime::litecoin;
    let author = signer(7);
    let mut rng = StdRng::seed_from_u64(41);
    let records = container::seal(&[4; 32], b"private", ContentType::Opaque, &mut rng).unwrap();
    let first = litecoin::prepare(&records, 7, funding(&author), 1, 0, &mut rng).unwrap();
    let second = litecoin::prepare(&records, 7, funding(&author), 1, 0, &mut rng).unwrap();
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
        assert_eq!(
            reveal.output[0].script_pubkey,
            urma_wallet::signing::script(&author).unwrap()
        );
    }
    assert_ne!(authors[0], authors[1]);
}
