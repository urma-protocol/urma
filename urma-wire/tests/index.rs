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

    fn block(&self, _height: u64) -> Result<Block, Self::Error> {
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

struct BlockReader(Block);
impl Reader for BlockReader {
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
    fn block(&self, _: u64) -> Result<Block, Self::Error> {
        Ok(self.0.clone())
    }
    fn transaction(&self, _: Txid) -> Result<Transaction, Self::Error> {
        unreachable!()
    }
}

#[test]
fn sync_checks_block_body_and_witness_before_checkpointing() {
    use bitcoin::{Network, Witness, blockdata::constants::genesis_block};
    use urma_chain::validation::BlockValidationError;
    let dir = tempfile::tempdir().unwrap();
    let valid = genesis_block(Network::Regtest);
    let path = dir.path().join("valid.json");
    assert_eq!(
        index::sync(&BlockReader(valid.clone()), &path, 0, 1)
            .unwrap()
            .scanned,
        1
    );
    for witness in [false, true] {
        let mut block = valid.clone();
        if witness {
            block.txdata[0].input[0].witness = Witness::from_slice(&[vec![0; 32]]);
        } else {
            block.txdata[0].output[0].value = bitcoin::Amount::ZERO;
        }
        let path = dir.path().join(format!("invalid-{witness}.json"));
        let failure = match index::sync(&BlockReader(block), &path, 0, 1) {
            Ok(_) => panic!("invalid block indexed"),
            Err(cause) => cause,
        };
        assert!(matches!(
            failure,
            SyncError::Wire(Error::Block(
                BlockValidationError::MerkleRootMismatch
                    | BlockValidationError::WitnessCommitmentMismatch
            ))
        ));
        assert!(Index::load(&path).unwrap().blocks.is_empty());
    }
}
