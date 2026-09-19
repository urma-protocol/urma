use bitcoin::Txid;
use std::fmt;
use urma::{journal::Plan, litecoin::Plan as LitecoinPlan, publication::PublicPlan};
use urma_chain::observation::{ChainId, Observation, Placement};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanId(pub [u8; 16]);

pub enum PreparedPlan {
    BitcoinPrivate(Plan),
    LitecoinPrivate(LitecoinPlan),
    PublicRecord(PublicPlan),
}

pub struct StoredPlan {
    pub chain: ChainId,
    pub plan: PreparedPlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    RecheckMissing,
    WaitForConfirmation,
    ObservedInBlock,
    ReconcileReorg,
}

pub fn reconcile(
    chain: ChainId,
    transaction: Txid,
    observation: &Observation,
) -> Result<ResumeAction, JournalError> {
    if observation.chain != chain || observation.txid != transaction {
        return Err(JournalError::ObservationMismatch);
    }
    Ok(match observation.placement {
        Placement::Unknown => ResumeAction::RecheckMissing,
        Placement::Mempool => ResumeAction::WaitForConfirmation,
        Placement::Included(_) => ResumeAction::ObservedInBlock,
        Placement::Orphaned(_) => ResumeAction::ReconcileReorg,
    })
}

#[derive(Debug)]
pub enum JournalError {
    Missing(PlanId),
    AlreadyExists(PlanId),
    ObservationMismatch,
    Storage(std::io::Error),
    Invalid(urma::error::Error),
    Unsupported,
}
impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "publication journal: {self:?}")
    }
}
impl std::error::Error for JournalError {}

pub trait PlanStore {
    fn save_new(&mut self, id: PlanId, plan: &StoredPlan) -> Result<(), JournalError>;
    fn load(&self, id: PlanId) -> Result<StoredPlan, JournalError>;
}

pub fn prepare_public(
    record: &urma_core::format::PublicRecord,
    signer: &impl urma_identity::identity::IdentitySigner,
    funding: urma_wallet::funding::Funding,
    chain: urma_chain::observation::Chain,
    budget: urma_wallet::wallet::FeeBudget,
) -> Result<PublicPlan, urma::error::Error> {
    if budget.chain != chain.genesis()? {
        return Err(urma::error::Error::Invalid(
            "funding budget chain mismatch".into(),
        ));
    }
    let (_, previous) = funding.prevout()?;
    if previous.script_pubkey != urma_wallet::signing::script(signer)? {
        return Err(urma_wallet::wallet::WalletError::WrongIdentity.into());
    }
    let mut plan = urma::publication::prepare(record, signer, funding, chain, budget.rate.0.get())?;
    let commit = bitcoin::consensus::deserialize(&hex::decode(&plan.commit)?)?;
    let request = urma_wallet::wallet::SpendRequest {
        transaction: &commit,
        prevouts: std::slice::from_ref(&previous),
        budget,
    };
    let signed = urma_wallet::signing::sign(signer, &request)?;
    plan.commit = hex::encode(bitcoin::consensus::serialize(&signed));
    let reveal: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&plan.reveal)?)?;
    let spent = signed.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .ok_or(urma_wallet::wallet::WalletError::Overflow)
    })?;
    let commit_fee = previous
        .value
        .to_sat()
        .checked_sub(spent)
        .ok_or(urma_wallet::wallet::WalletError::InsufficientFunds)?;
    let reveal_output = reveal.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .ok_or(urma_wallet::wallet::WalletError::Overflow)
    })?;
    let reveal_fee = signed.output[0]
        .value
        .to_sat()
        .checked_sub(reveal_output)
        .ok_or(urma_wallet::wallet::WalletError::InsufficientFunds)?;
    if commit_fee
        .checked_add(reveal_fee)
        .ok_or(urma_wallet::wallet::WalletError::Overflow)?
        > budget.maximum_base_units
    {
        return Err(urma_wallet::wallet::WalletError::BudgetExceeded.into());
    }
    Ok(plan)
}
