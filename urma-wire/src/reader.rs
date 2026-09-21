use bitcoin::{Block, BlockHash, Transaction, Txid};

pub trait Reader {
    type Error: std::error::Error + 'static;

    fn genesis(&self) -> Result<BlockHash, Self::Error>;
    fn tip_height(&self) -> Result<u64, Self::Error>;
    fn block_hash(&self, height: u64) -> Result<BlockHash, Self::Error>;
    fn block(&self, height: u64) -> Result<Block, Self::Error>;
    fn transaction(&self, txid: Txid) -> Result<Transaction, Self::Error>;
}
