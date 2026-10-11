use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, ScriptBuf, Transaction, Witness,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use urma_chain::{decode, observation::Chain, validation::validate_block_integrity};
use urma_core::multipart::VerifiedRecord;
use urma_node::{
    Error,
    model::{ArchiveConfig, ChainPoint, Retention},
    source::ChainSource,
};

pub const FIRST_HEIGHT: u64 = 100;

pub fn vector(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/vectors")
            .join(name),
    )
    .unwrap()
}

pub struct SignedPair {
    pub commit: Transaction,
    pub reveal: Transaction,
    pub raw_commit: Vec<u8>,
    pub raw_reveal: Vec<u8>,
    pub verified: VerifiedRecord,
}

impl SignedPair {
    pub fn load(name: &str) -> Self {
        let raw_commit = vector(&format!("{name}.commit"));
        let raw_reveal = vector(&format!("{name}.reveal"));
        let commit = deserialize(&raw_commit).unwrap();
        let reveal: Transaction = deserialize(&raw_reveal).unwrap();
        // These independently signed public fixtures are never re-signed or
        // replaced with mocked authentication results.
        let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit).unwrap();
        assert_eq!(serialize(&commit), raw_commit);
        assert_eq!(serialize(&reveal), raw_reveal);
        Self {
            commit,
            reveal,
            raw_commit,
            raw_reveal,
            verified,
        }
    }

    pub fn transactions(&self) -> [Transaction; 2] {
        [self.commit.clone(), self.reveal.clone()]
    }
}

pub fn profile() -> SignedPair {
    SignedPair::load("proof-profile-utf8-two-byte128")
}

// Assemble witness-authenticated blocks around unchanged signed vector
// transactions. The mock owns branch selection; no PoW, difficulty, scripts,
// UTXO validity or regtest consensus is claimed by these fixtures.
pub fn witness_block(transactions: &[Transaction], previous: Option<&Block>, nonce: u32) -> Block {
    let mut block = genesis_block(Network::Regtest);
    if let Some(previous) = previous {
        block.header.prev_blockhash = previous.block_hash();
    }
    block.header.nonce = nonce;
    block.header.bits = CompactTarget::from_consensus(0);
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    block.txdata.extend_from_slice(transactions);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(bitcoin::TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    validate_block_integrity(&block, block.block_hash()).unwrap();
    block
}

pub fn point(height: u64, block: &Block) -> ChainPoint {
    ChainPoint {
        height,
        hash: block.block_hash(),
    }
}

pub fn config(block: &Block, retention: Retention) -> ArchiveConfig {
    ArchiveConfig {
        chain: Chain::BitcoinRegtest,
        application_start: point(FIRST_HEIGHT, block),
        retention,
    }
}

#[derive(Clone)]
pub struct Body {
    pub header: Header,
    pub raw: Vec<u8>,
}

impl From<&Block> for Body {
    fn from(block: &Block) -> Self {
        Self {
            header: block.header,
            raw: serialize(block),
        }
    }
}

pub struct MemorySource {
    pub chain: Chain,
    pub first_height: u64,
    branch: Mutex<Vec<Body>>,
    replace_on_fetch: Mutex<Option<Vec<Body>>>,
    pub body_calls: AtomicUsize,
    pub header_calls: AtomicUsize,
}

impl MemorySource {
    pub fn new(blocks: &[Block]) -> Self {
        Self::with_bodies(
            Chain::BitcoinRegtest,
            FIRST_HEIGHT,
            blocks.iter().map(Body::from).collect(),
        )
    }

    pub fn with_bodies(chain: Chain, first_height: u64, bodies: Vec<Body>) -> Self {
        assert!(!bodies.is_empty());
        Self {
            chain,
            first_height,
            branch: Mutex::new(bodies),
            replace_on_fetch: Mutex::new(None),
            body_calls: AtomicUsize::new(0),
            header_calls: AtomicUsize::new(0),
        }
    }

    pub fn replace_branch(&self, blocks: &[Block]) {
        *self.branch.lock().unwrap() = blocks.iter().map(Body::from).collect();
    }

    pub fn reorg_during_next_fetch(&self, blocks: &[Block]) {
        *self.replace_on_fetch.lock().unwrap() = Some(blocks.iter().map(Body::from).collect());
    }

    fn index(&self, height: u64) -> Result<usize, Error> {
        height
            .checked_sub(self.first_height)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or_else(|| Error::Invalid("mock height out of range".into()))
    }
}

impl ChainSource for MemorySource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        Ok(self.chain.genesis().unwrap().0)
    }

    fn tip(&self) -> Result<ChainPoint, Error> {
        let branch = self.branch.lock().unwrap();
        Ok(ChainPoint {
            height: self.first_height + u64::try_from(branch.len()).unwrap() - 1,
            hash: branch.last().unwrap().header.block_hash(),
        })
    }

    fn header(&self, height: u64) -> Result<Header, Error> {
        self.header_calls.fetch_add(1, Ordering::Relaxed);
        self.branch
            .lock()
            .unwrap()
            .get(self.index(height)?)
            .map(|body| body.header)
            .ok_or_else(|| Error::Invalid("mock header unavailable".into()))
    }

    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        self.body_calls.fetch_add(1, Ordering::Relaxed);
        let raw = self
            .branch
            .lock()
            .unwrap()
            .get(self.index(height)?)
            .ok_or_else(|| Error::Invalid("mock body unavailable".into()))?
            .raw
            .clone();
        if let Some(replacement) = self.replace_on_fetch.lock().unwrap().take() {
            *self.branch.lock().unwrap() = replacement;
        }
        Ok(raw)
    }
}

pub fn public_litecoin_block() -> (Block, Body) {
    let raw = vector("litecoin-mweb/block-4892705.bin");
    let hash = "2b70f30e5c2a5e9e8510cc6a9c86339b2f7ffe618a32bc40902fd4cb842fd459"
        .parse()
        .unwrap();
    let block = decode::esplora_block(&raw, Chain::LitecoinTestnet, hash).unwrap();
    let header = block.header;
    (block, Body { header, raw })
}

// Call only after dropping Engine. Inspection uses a separate read-only handle;
// tests never edit the archive or bypass its ownership/coordinator contract.
pub fn readonly_archive(directory: &Path) -> Connection {
    Connection::open_with_flags(
        directory.join("archive.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

pub fn stored_bytes(db: &Connection) -> BTreeMap<String, Vec<u8>> {
    db.prepare("SELECT wtxid,raw FROM transactions ORDER BY wtxid")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
