use bitcoin::{Transaction, TxOut};
use std::{fmt, num::NonZeroU64};
use urma_chain::observation::ChainId;

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
    InsufficientFunds,
    BudgetExceeded,
    Overflow,
    Protocol(urma_core::error::Error),
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wallet: {self:?}")
    }
}
impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddressPrefix(cause) => Some(cause),
            Self::AddressEncoding(cause) => Some(cause),
            Self::Identity(cause) => Some(cause),
            Self::Protocol(cause) => Some(cause),
            _ => None,
        }
    }
}
