use anyhow::{Context, Result};
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, WPubkeyHash, Witness,
    absolute::LockTime,
    block::{Header, Version},
    consensus::{deserialize, serialize},
    hashes::Hash,
    script::Builder,
    secp256k1::{Keypair, Secp256k1},
    transaction::Version as TxVersion,
};
use std::collections::BTreeMap;
use urma_chain::observation::Chain;
use urma_core::format::PublicRecord;
use urma_names::{
    index::NamesIndex,
    name::Name,
    payload::{Genesis, Mode, OwnerOp, Payload},
    scan::{self, Registration, Source},
    state::{Rejection, Resolution, Target, Verdict},
};
use urma_runtime::publication;
use urma_wallet::funding::Funding;

#[derive(Debug)]
enum FakeError {
    Missing(String),
}

impl std::fmt::Display for FakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(what) => write!(f, "missing {what}"),
        }
    }
}

impl std::error::Error for FakeError {}

struct FakeChain {
    blocks: Vec<Block>,
    transactions: BTreeMap<Txid, Transaction>,
}

impl Source for FakeChain {
    type Error = FakeError;

    fn genesis(&self) -> Result<BlockHash, FakeError> {
        Ok(self.blocks[0].block_hash())
    }
    fn tip_height(&self) -> Result<u64, FakeError> {
        Ok(u64::try_from(self.blocks.len()).unwrap() - 1)
    }
    fn block_hash(&self, height: u64) -> Result<BlockHash, FakeError> {
        Ok(self.block(height)?.block_hash())
    }
    fn block(&self, height: u64) -> Result<Block, FakeError> {
        self.blocks
            .get(usize::try_from(height).unwrap())
            .cloned()
            .ok_or(FakeError::Missing(format!("block {height}")))
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, FakeError> {
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or(FakeError::Missing(format!("transaction {txid}")))
    }
}

fn coinbase(height: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new()
                .push_int(i64::try_from(height).unwrap())
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32]]),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([9; 20])),
        }],
    }
}

fn make_block(prev: BlockHash, height: u64, txs: Vec<Transaction>) -> Block {
    let mut txdata = vec![coinbase(height)];
    txdata.extend(txs);
    let mut block = Block {
        header: Header {
            version: Version::TWO,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    let witness_root = block.witness_root().unwrap();
    let commitment = Block::compute_witness_commitment(&witness_root, &[0u8; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert!(block.check_witness_commitment());
    block
}

impl FakeChain {
    fn new() -> Self {
        Self {
            blocks: vec![make_block(BlockHash::all_zeros(), 0, Vec::new())],
            transactions: BTreeMap::new(),
        }
    }

    fn push(&mut self, txs: Vec<Transaction>) -> u64 {
        let height = u64::try_from(self.blocks.len()).unwrap();
        let prev = self.blocks.last().unwrap().block_hash();
        for tx in &txs {
            self.transactions.insert(tx.compute_txid(), tx.clone());
        }
        self.blocks.push(make_block(prev, height, txs));
        height
    }

    fn truncate(&mut self, height: u64) {
        self.blocks.truncate(usize::try_from(height).unwrap() + 1);
    }
}

fn key(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32]).unwrap()
}

fn funding(seed: u8) -> Funding {
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20])),
        }],
    };
    Funding {
        raw_transaction: hex::encode(serialize(&tx)),
        vout: 0,
    }
}

struct Pair {
    commit: Transaction,
    reveal: Transaction,
}

fn pair(record: &PublicRecord, author: &Keypair, seed: u8) -> Result<Pair> {
    let plan = publication::prepare(record, author, funding(seed), Chain::BitcoinRegtest, 1)?;
    Ok(Pair {
        commit: deserialize(&hex::decode(plan.commit)?)?,
        reveal: deserialize(&hex::decode(plan.reveal)?)?,
    })
}

fn claim(registry: Txid, name: &str, salt: u8, target: u8) -> Result<PublicRecord> {
    Ok(Payload::Claim(OwnerOp {
        registry,
        salt: [salt; 16],
        name: Name::parse(name)?,
        target: Txid::from_byte_array([target; 32]),
    })
    .to_record()?)
}

fn reg(genesis: Txid, genesis_height: u64) -> Registration<'static> {
    Registration {
        network: "bitcoin-regtest",
        genesis,
        genesis_height,
    }
}

fn open_genesis(expiry_blocks: u32, reveal_max_blocks: u16) -> Result<PublicRecord> {
    Ok(Payload::Genesis(Genesis {
        mode: Mode::Open,
        expiry_blocks,
        reveal_max_blocks,
        threshold: 0,
        approvers: Vec::new(),
    })
    .to_record()?)
}

fn verdict(report: &scan::ScanReport, tx: &Transaction) -> Option<Verdict> {
    let txid = tx.compute_txid().to_string();
    report
        .records
        .iter()
        .find(|record| record.txid == txid)
        .map(|record| record.verdict)
}

#[test]
fn scanner_verifies_genesis_locates_commits_applies_records_and_follows_reorgs() -> Result<()> {
    let alice = key(1);
    let bob = key(2);
    let mallory = key(3);
    let genesis = Payload::Genesis(Genesis {
        mode: Mode::Open,
        expiry_blocks: 5000,
        reveal_max_blocks: 144,
        threshold: 0,
        approvers: Vec::new(),
    })
    .to_record()?;
    let g = pair(&genesis, &alice, 10)?;
    let registry = g.reveal.compute_txid();
    let early = pair(&claim(registry, "early", 3, 0x53)?, &bob, 16)?;
    let mut chain = FakeChain::new();
    chain.push(vec![g.commit.clone(), early.commit.clone()]);
    let genesis_height = chain.push(vec![g.reveal.clone()]);
    assert_eq!(genesis_height, 2);
    let b = pair(&claim(registry, "bob", 1, 0x51)?, &bob, 11)?;
    let same = pair(&claim(registry, "same", 1, 0x51)?, &bob, 12)?;
    let post = pair(&PublicRecord::Post("hello".into()), &bob, 13)?;
    let foreign = pair(
        &PublicRecord::ProfileRecord {
            profile: *b"URMANAM2",
            payload: vec![1, 2, 3],
        },
        &bob,
        14,
    )?;
    chain.push(vec![
        b.commit.clone(),
        post.commit.clone(),
        foreign.commit.clone(),
    ]);
    chain.push(vec![
        same.commit.clone(),
        same.reveal.clone(),
        b.reveal.clone(),
        post.reveal.clone(),
        foreign.reveal.clone(),
    ]);
    let m = pair(&claim(registry, "bob", 2, 0x52)?, &mallory, 15)?;
    chain.push(vec![m.commit.clone()]);
    chain.push(vec![m.reveal.clone()]);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("names-index.json");
    let report = scan::sync(&chain, &path, reg(registry, genesis_height), 3)?;
    assert_eq!(
        (
            report.scanned,
            report.rolled_back,
            report.height,
            report.tip,
            report.complete_to_tip
        ),
        (3, 0, 5, 6, false)
    );
    assert_eq!(verdict(&report, &b.reveal), Some(Verdict::Applied));
    assert_eq!(
        verdict(&report, &same.reveal),
        Some(Verdict::Invalid(Rejection::RevealWindow))
    );
    assert_eq!(verdict(&report, &post.reveal), None);
    assert_eq!(verdict(&report, &foreign.reveal), None);
    let report = scan::sync(&chain, &path, reg(registry, genesis_height), 10)?;
    assert_eq!(
        (report.scanned, report.height, report.complete_to_tip),
        (1, 6, true)
    );
    assert_eq!(
        verdict(&report, &m.reveal),
        Some(Verdict::Inert(Rejection::NameBound))
    );
    let index = NamesIndex::load(&path)?;
    let Resolution::Bound(bound) = index.registry.resolve(&Name::parse("bob")?) else {
        panic!("bob unbound")
    };
    assert_eq!(bound.owner, bob.x_only_public_key().0);
    assert_eq!(
        bound.target,
        Target::Publication(Txid::from_byte_array([0x51; 32]))
    );
    assert_eq!(bound.expiry, 4 + 5000);
    assert_eq!(bound.claim_txid, b.reveal.compute_txid());
    assert_eq!(index.blocks.len(), 4);
    assert_eq!(index.window.len(), 4);
    let mut bad = pair(&claim(registry, "bad", 4, 0x54)?, &bob, 17)?;
    let mut items: Vec<Vec<u8>> = bad.reveal.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    items[0][0] ^= 1;
    bad.reveal.input[0].witness = Witness::from_slice(&items);
    chain.push(vec![bad.commit.clone()]);
    chain.push(vec![bad.reveal.clone(), early.reveal.clone()]);
    let report = scan::sync(&chain, &path, reg(registry, genesis_height), 10)?;
    assert_eq!((report.scanned, report.height), (2, 8));
    assert!(report.records.is_empty());
    assert_eq!(
        NamesIndex::load(&path)?
            .registry
            .resolve(&Name::parse("early")?),
        Resolution::Unbound
    );
    chain.truncate(3);
    chain.push(vec![same.commit.clone()]);
    chain.push(vec![m.commit.clone()]);
    chain.push(vec![m.reveal.clone()]);
    let report = scan::sync(&chain, &path, reg(registry, genesis_height), 10)?;
    assert_eq!(
        (
            report.scanned,
            report.rolled_back,
            report.height,
            report.tip
        ),
        (3, 5, 6, 6)
    );
    assert_eq!(verdict(&report, &m.reveal), Some(Verdict::Applied));
    let index = NamesIndex::load(&path)?;
    let Resolution::Bound(bound) = index.registry.resolve(&Name::parse("bob")?) else {
        panic!("bob unbound after reorg")
    };
    assert_eq!(bound.owner, mallory.x_only_public_key().0);
    assert_eq!(
        bound.target,
        Target::Publication(Txid::from_byte_array([0x52; 32]))
    );
    assert_eq!(
        index.blocks.last().context("checkpoint")?.hash,
        chain.blocks[6].block_hash().to_string()
    );
    assert!(
        scan::sync(
            &chain,
            &path,
            reg(Txid::from_byte_array([1; 32]), genesis_height),
            10
        )
        .is_err()
    );
    let other = dir.path().join("other.json");
    assert!(scan::sync(&chain, &other, reg(registry, 3), 10).is_err());
    Ok(())
}

#[test]
fn incremental_and_fresh_scans_agree_when_the_genesis_block_is_orphaned() -> Result<()> {
    let alice = key(1);
    let g = pair(&open_genesis(50, 3)?, &alice, 10)?;
    let root = g.reveal.compute_txid();
    let mut chain = FakeChain::new();
    chain.push(vec![g.commit.clone()]);
    chain.push(vec![g.reveal.clone()]);
    chain.push(Vec::new());
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("index.json");
    let first = scan::sync(&chain, &path, reg(root, 2), 10)?;
    assert_eq!(first.genesis_hash, chain.blocks[2].block_hash().to_string());
    chain.truncate(1);
    chain.push(Vec::new());
    chain.push(Vec::new());
    let incremental = scan::sync(&chain, &path, reg(root, 2), 10);
    let fresh = scan::sync(&chain, &dir.path().join("fresh.json"), reg(root, 2), 10);
    assert!(
        incremental.is_err(),
        "orphaned genesis accepted by the incremental scan"
    );
    assert!(fresh.is_err(), "orphaned genesis accepted by a fresh scan");
    let message = format!("{}", incremental.err().context("error")?);
    assert!(message.contains("not on the current chain"), "{message}");
    assert_eq!(NamesIndex::load(&path)?.registry.height(), 3);
    chain.truncate(1);
    chain.push(vec![g.reveal.clone()]);
    chain.push(vec![g.commit.clone()]);
    let restored = scan::sync(&chain, &path, reg(root, 2), 10)?;
    assert_eq!(
        (restored.rolled_back, restored.scanned, restored.height),
        (1, 1, 3)
    );
    Ok(())
}

#[test]
fn one_block_reorg_at_the_window_edge_keeps_the_commit_visible() -> Result<()> {
    let alice = key(1);
    let g = pair(&open_genesis(5000, 3)?, &alice, 10)?;
    let root = g.reveal.compute_txid();
    let mut chain = FakeChain::new();
    chain.push(vec![g.commit.clone()]);
    chain.push(vec![g.reveal.clone()]);
    let c = pair(&claim(root, "audit", 1, 0x51)?, &alice, 11)?;
    while chain.blocks.len() < 1001 {
        chain.push(Vec::new());
    }
    chain.push(vec![c.commit.clone()]);
    chain.push(Vec::new());
    chain.push(Vec::new());
    chain.push(Vec::new());
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("index.json");
    scan::sync(&chain, &path, reg(root, 2), 10000)?;
    chain.truncate(1003);
    chain.push(vec![c.reveal.clone()]);
    let incremental = scan::sync(&chain, &path, reg(root, 2), 10)?;
    assert_eq!((incremental.rolled_back, incremental.scanned), (1, 1));
    let fresh = scan::sync(&chain, &dir.path().join("fresh.json"), reg(root, 2), 10000)?;
    assert_eq!(verdict(&incremental, &c.reveal), Some(Verdict::Applied));
    assert_eq!(verdict(&fresh, &c.reveal), Some(Verdict::Applied));
    let incremental_state = NamesIndex::load(&path)?;
    let fresh_state = NamesIndex::load(&dir.path().join("fresh.json"))?;
    assert_eq!(
        incremental_state.registry.resolve(&Name::parse("audit")?),
        fresh_state.registry.resolve(&Name::parse("audit")?)
    );
    assert!(matches!(
        incremental_state.registry.resolve(&Name::parse("audit")?),
        Resolution::Bound(..)
    ));
    assert_eq!(incremental_state.registry, fresh_state.registry);
    Ok(())
}

#[test]
fn an_index_is_bound_to_its_network_name() -> Result<()> {
    let alice = key(1);
    let g = pair(&open_genesis(50, 3)?, &alice, 10)?;
    let root = g.reveal.compute_txid();
    let mut chain = FakeChain::new();
    chain.push(vec![g.commit.clone()]);
    chain.push(vec![g.reveal.clone()]);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("index.json");
    let report = scan::sync(&chain, &path, reg(root, 2), 10)?;
    assert_eq!(report.network, "bitcoin-regtest");
    assert_eq!(NamesIndex::load(&path)?.network, "bitcoin-regtest");
    let other = Registration {
        network: "litecoin-mainnet",
        genesis: root,
        genesis_height: 2,
    };
    let refused = scan::sync(&chain, &path, other, 10);
    assert!(
        refused.is_err(),
        "index accepted under another network name"
    );
    Ok(())
}
