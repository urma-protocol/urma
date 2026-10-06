use bitcoin::{Block, BlockHash, Transaction, Txid, hashes::Hash};
use urma_wire::{
    Error, SyncError,
    index::{self, Index},
    reader::Reader,
};

struct UnavailableReader;

impl Reader for UnavailableReader {
    type Error = std::io::Error;

    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "source unavailable",
        ))
    }

    fn tip_height(&self) -> Result<u64, Self::Error> {
        unreachable!()
    }

    fn block_hash(&self, _height: u64) -> Result<BlockHash, Self::Error> {
        unreachable!()
    }

    fn block(&self, _height: u64) -> Result<(Block, BlockHash), Self::Error> {
        unreachable!()
    }

    fn transaction(&self, _txid: Txid) -> Result<Transaction, Self::Error> {
        unreachable!()
    }
}

#[test]
fn index_persistence_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wire-index.json");
    let index = Index {
        format: "URMA-WIRE-INDEX-1".into(),
        genesis: BlockHash::all_zeros().to_string(),
        start: 42,
        blocks: Vec::new(),
        entries: Vec::new(),
    };

    index.persist(&path).unwrap();
    let loaded = Index::load(&path).unwrap();
    assert_eq!(loaded.genesis, index.genesis);
    assert_eq!(loaded.start, 42);
}

#[test]
fn load_error_names_the_index_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing-index.json");
    let error = match Index::load(&path) {
        Ok(_) => panic!("missing index loaded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Context { .. }));
    assert!(error.to_string().contains(path.to_str().unwrap()));
}

#[test]
fn source_failures_retain_the_reader_error() {
    let directory = tempfile::tempdir().unwrap();
    let error = match index::sync(
        &UnavailableReader,
        &directory.path().join("wire-index.json"),
        0,
        1,
    ) {
        Ok(_) => panic!("unavailable source synchronized"),
        Err(error) => error,
    };
    let SyncError::Source(source) = error else {
        panic!("source error was reclassified as Wire data");
    };
    assert_eq!(source.kind(), std::io::ErrorKind::ConnectionRefused);
}

struct BlockReader {
    block: Block,
    claimed: BlockHash,
}
impl Reader for BlockReader {
    type Error = std::io::Error;
    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Ok(self.claimed)
    }
    fn tip_height(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn block_hash(&self, _: u64) -> Result<BlockHash, Self::Error> {
        Ok(self.claimed)
    }
    fn block(&self, _: u64) -> Result<(Block, BlockHash), Self::Error> {
        urma_chain::validation::validate_block_integrity(&self.block, self.claimed)
            .map_err(|cause| std::io::Error::new(std::io::ErrorKind::InvalidData, cause))?;
        Ok((self.block.clone(), self.claimed))
    }
    fn transaction(&self, _: Txid) -> Result<Transaction, Self::Error> {
        unreachable!()
    }
}

struct LyingReader(Block);
impl Reader for LyingReader {
    type Error = std::io::Error;
    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Ok(self.0.block_hash())
    }
    fn tip_height(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn block_hash(&self, _: u64) -> Result<BlockHash, Self::Error> {
        Ok(self.0.block_hash())
    }
    fn block(&self, _: u64) -> Result<(Block, BlockHash), Self::Error> {
        Ok((self.0.clone(), BlockHash::all_zeros()))
    }
    fn transaction(&self, _: Txid) -> Result<Transaction, Self::Error> {
        unreachable!()
    }
}

struct ChainReader {
    blocks: Vec<Block>,
    hash_calls: std::sync::atomic::AtomicUsize,
    block_calls: std::sync::atomic::AtomicUsize,
    fail_at: Option<u64>,
    lie_about_tip: bool,
}

impl ChainReader {
    fn chain(length: u64) -> Vec<Block> {
        use bitcoin::{Network, blockdata::constants::genesis_block};
        let mut blocks = vec![genesis_block(Network::Regtest)];
        for height in 1..length {
            let mut block = genesis_block(Network::Regtest);
            block.header.prev_blockhash = blocks[blocks.len() - 1].block_hash();
            block.header.nonce = u32::try_from(height).unwrap();
            blocks.push(block);
        }
        blocks
    }

    fn new(length: u64) -> Self {
        Self {
            blocks: Self::chain(length),
            hash_calls: std::sync::atomic::AtomicUsize::new(0),
            block_calls: std::sync::atomic::AtomicUsize::new(0),
            fail_at: None,
            lie_about_tip: false,
        }
    }
}

impl Reader for ChainReader {
    type Error = std::io::Error;
    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Ok(self.blocks[0].block_hash())
    }
    fn tip_height(&self) -> Result<u64, Self::Error> {
        Ok(u64::try_from(self.blocks.len() - 1).unwrap())
    }
    fn block_hash(&self, height: u64) -> Result<BlockHash, Self::Error> {
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.lie_about_tip && height == self.tip_height()? {
            return Ok(BlockHash::all_zeros());
        }
        Ok(self.blocks[usize::try_from(height).unwrap()].block_hash())
    }
    fn block(&self, height: u64) -> Result<(Block, BlockHash), Self::Error> {
        self.block_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.fail_at == Some(height) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer gone",
            ));
        }
        let block = self.blocks[usize::try_from(height).unwrap()].clone();
        let hash = block.block_hash();
        Ok((block, hash))
    }
    fn transaction(&self, _: Txid) -> Result<Transaction, Self::Error> {
        unreachable!()
    }
}

#[test]
fn a_batch_is_fetched_in_parallel_applied_in_order_and_checked_once_against_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.json");
    let reader = ChainReader::new(24);
    let (report, index) = index::sync(&reader, &path, 0, 10).unwrap();
    assert_eq!(report.scanned, 10);
    assert!(!report.complete_to_tip);
    assert_eq!(index.blocks.len(), 10);
    assert_eq!(reader.block_calls.load(std::sync::atomic::Ordering::Relaxed), 10);
    assert_eq!(reader.hash_calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    let persisted = Index::load(&path).unwrap();
    for (height, checkpoint) in persisted.blocks.iter().enumerate() {
        assert_eq!(checkpoint.height, u64::try_from(height).unwrap());
        assert_eq!(checkpoint.hash, reader.blocks[height].block_hash().to_string());
    }
    let (report, index) = index::sync(&reader, &path, 0, 100).unwrap();
    assert_eq!(report.scanned, 14);
    assert!(report.complete_to_tip);
    assert_eq!(index.blocks.len(), 24);
    assert_eq!(Index::load(&path).unwrap().blocks.len(), 24);
}

#[test]
fn a_failed_fetch_keeps_the_batch_out_of_the_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.json");
    let mut reader = ChainReader::new(12);
    reader.fail_at = Some(7);
    let failure = match index::sync(&reader, &path, 0, 12) {
        Ok(_) => panic!("batch with a failed block indexed"),
        Err(cause) => cause,
    };
    assert!(matches!(failure, SyncError::Source(_)));
    assert!(Index::load(&path).unwrap().blocks.is_empty());
    reader.fail_at = None;
    assert_eq!(index::sync(&reader, &path, 0, 12).unwrap().0.scanned, 12);
}

#[test]
fn a_source_that_moved_during_the_batch_is_refused_without_persisting() {
    let dir = dir_with_batch(6);
    let reader = ChainReader {
        lie_about_tip: true,
        ..ChainReader::new(12)
    };
    let failure = match index::sync(&reader, &dir.1, 0, 12) {
        Ok(_) => panic!("reorganized source indexed"),
        Err(cause) => cause,
    };
    assert!(matches!(failure, SyncError::Wire(Error::Invalid(_))));
    assert_eq!(Index::load(&dir.1).unwrap().blocks.len(), 6);
}

fn dir_with_batch(length: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("moved.json");
    let reader = ChainReader::new(length);
    assert_eq!(index::sync(&reader, &path, 0, length).unwrap().0.scanned, length);
    (dir, path)
}

#[test]
fn sync_takes_the_reader_verified_hash_and_refuses_an_unverified_pair() {
    use bitcoin::{Network, Witness, blockdata::constants::genesis_block};
    let dir = tempfile::tempdir().unwrap();
    let valid = genesis_block(Network::Regtest);
    let path = dir.path().join("valid.json");
    let reader = BlockReader {
        block: valid.clone(),
        claimed: valid.block_hash(),
    };
    assert_eq!(index::sync(&reader, &path, 0, 1).unwrap().0.scanned, 1);
    assert_eq!(
        Index::load(&path).unwrap().blocks[0].hash,
        valid.block_hash().to_string()
    );
    for witness in [false, true] {
        let mut block = valid.clone();
        if witness {
            block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
        } else {
            block.txdata[0].output[0].value = bitcoin::Amount::ZERO;
        }
        let claimed = block.block_hash();
        let path = dir.path().join(format!("invalid-{witness}.json"));
        let failure = match index::sync(&BlockReader { block, claimed }, &path, 0, 1) {
            Ok(_) => panic!("invalid block indexed"),
            Err(cause) => cause,
        };
        let SyncError::Source(source) = failure else {
            panic!("reader validation failure was reclassified");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
        assert!(Index::load(&path).unwrap().blocks.is_empty());
    }
    let path = dir.path().join("lying.json");
    let failure = match index::sync(&LyingReader(valid), &path, 0, 1) {
        Ok(_) => panic!("mismatched block and hash indexed"),
        Err(cause) => cause,
    };
    assert!(matches!(failure, SyncError::Wire(Error::Invalid(_))));
    assert!(Index::load(&path).unwrap().blocks.is_empty());
}
