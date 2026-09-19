use crate::funding::Funding;
use bitcoin::{Transaction, TxOut};
use std::{fmt, num::NonZeroU64};
use urma_chain::observation::ChainId;
use urma_identity::identity::IdentitySlot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate(pub NonZeroU64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeBudget {
    pub chain: ChainId,
    pub rate: FeeRate,
    pub maximum_base_units: u64,
}

impl FeeBudget {
    pub fn quote(&self, virtual_bytes: u64) -> Result<u64, WalletError> {
        let fee = virtual_bytes
            .checked_mul(self.rate.0.get())
            .ok_or(WalletError::Overflow)?;
        if fee > self.maximum_base_units {
            return Err(WalletError::BudgetExceeded);
        }
        Ok(fee)
    }
}

pub struct FundingRequest {
    pub budget: FeeBudget,
    pub required_output_units: u64,
}

pub struct SpendRequest<'a> {
    pub transaction: &'a Transaction,
    pub prevouts: &'a [TxOut],
    pub budget: FeeBudget,
}

#[derive(Debug)]
pub enum WalletError {
    AddressPrefix(bech32::primitives::hrp::Error),
    AddressEncoding(bech32::segwit::EncodeError),
    Identity(urma_identity::error::IdentityError),
    InvalidFunding,
    WrongIdentity,
    MissingKey(IdentitySlot),
    Locked,
    InsufficientFunds,
    BudgetExceeded,
    Overflow,
    Unsupported,
    Storage(std::io::Error),
    Protocol(urma_core::error::Error),
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wallet: {self:?}")
    }
}
impl std::error::Error for WalletError {}

pub trait FundingWallet {
    fn select_funding(
        &mut self,
        key: IdentitySlot,
        request: &FundingRequest,
    ) -> Result<Funding, WalletError>;
    fn sign_funding(
        &self,
        key: IdentitySlot,
        request: &SpendRequest<'_>,
    ) -> Result<Transaction, WalletError>;
}
