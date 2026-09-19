use bitcoin::{Block, BlockHash, Transaction, Txid};
use urma::error::Error;

pub trait Reader {
    fn genesis(&self) -> Result<BlockHash, Error>;
    fn tip_height(&self) -> Result<u64, Error>;
    fn block_hash(&self, height: u64) -> Result<BlockHash, Error>;
    fn block(&self, height: u64) -> Result<Block, Error>;
    fn transaction(&self, txid: Txid) -> Result<Transaction, Error>;
}
