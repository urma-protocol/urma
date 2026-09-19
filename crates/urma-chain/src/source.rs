use crate::observation::{ChainId, Observation};
use bitcoin::{Transaction, Txid};
use std::{fmt, num::NonZeroUsize};

#[derive(Debug)]
pub enum SourceError {
    Unavailable { txid: Txid },
    WrongChain { expected: ChainId, actual: ChainId },
    Capacity { limit: NonZeroUsize },
    Transport(std::io::Error),
    InvalidTransaction(bitcoin::consensus::encode::Error),
    Unsupported,
}
impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chain source: {self:?}")
    }
}
impl std::error::Error for SourceError {}

pub struct ObservedTransaction {
    pub transaction: Transaction,
    pub observation: Observation,
}

pub trait TransactionSource {
    fn fetch(
        &mut self,
        chain: ChainId,
        txid: Txid,
        maximum_bytes: NonZeroUsize,
    ) -> Result<ObservedTransaction, SourceError>;
}
