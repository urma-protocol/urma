use crate::config;
use crate::error::{Context, Error, ensure};
use crate::publication::{PublicPlan, prepare_signed_bytes};
use crate::transaction::decode;
use crate::wallet::{Coin, FundingInput};
use crate::{
    node::Node,
    plan::{PlanLimits, PublicationPlan},
};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;
use urma_core::multipart::ChildReference;
use urma_identity::identity::IdentitySigner;
use urma_wallet::{
    account::{Account, KeyPath},
    funding::Funding,
    wallet::{FeeBudget, FeeRate},
};

pub(crate) struct Planner<'a, A> {
    author: &'a A,
    funder: &'a Account,
    inputs: Vec<FundingInput>,
    plan: PublicationPlan,
    limits: PlanLimits,
}

impl<'a, A: IdentitySigner> Planner<'a, A> {
    pub(crate) fn new(
        node: &Node,
        author: &'a A,
        funder: &'a Account,
        limits: PlanLimits,
        records: u32,
    ) -> Result<Self, Error> {
        ensure!(
            records <= PublicationPlan::MAX_RECORDS,
            "in-memory publication exceeds client capacity"
        );
        Self::streaming(node, author, funder, limits, records)
    }

    pub(crate) fn streaming(
        node: &Node,
        author: &'a A,
        funder: &'a Account,
        limits: PlanLimits,
        records: u32,
    ) -> Result<Self, Error> {
        let minimum = Self::minimum(node, &limits, records)?;
        let selection = node.select_coins(funder, minimum, 0)?;
        Self::funded(node, author, funder, limits, selection.inputs)
    }

    pub(crate) fn remembered(
        node: &Node,
        author: &'a A,
        funder: &'a Account,
        limits: PlanLimits,
        records: u32,
        coins: Vec<Coin>,
    ) -> Result<Self, Error> {
        let minimum = Self::minimum(node, &limits, records)?;
        let selection = node.select_from(funder, coins, minimum, 0)?;
        Self::funded(node, author, funder, limits, selection.inputs)
    }

    fn minimum(node: &Node, limits: &PlanLimits, records: u32) -> Result<u64, Error> {
        ensure!(
            records > 0 && records <= limits.max_records,
            "publication exceeds caller record budget"
        );
        ensure!(
            (1..=100).contains(&limits.fee_rate) && limits.max_fee > 0,
            "invalid publication fee limits"
        );
        limits
            .max_fee
            .checked_add((u64::from(records) + 1) * config::publication_return(node.chain()))
            .context("funding budget overflow")
    }

    fn funded(
        node: &Node,
        author: &'a A,
        funder: &'a Account,
        limits: PlanLimits,
        inputs: Vec<FundingInput>,
    ) -> Result<Self, Error> {
        Ok(Self {
            author,
            funder,
            inputs,
            limits,
            plan: PublicationPlan {
                version: 1,
                chain: node.chain(),
                author: author.public_key().inner.x_only_public_key().0.to_string(),
                return_script: hex::encode(funder.receive_script()?.as_bytes()),
                root_txid: String::new(),
                total_fee: 0,
                maximum_fee: limits.max_fee,
                records: Vec::new(),
            },
        })
    }

    pub(crate) fn append(&mut self, record: &[u8]) -> Result<ChildReference, Error> {
        let (reference, pair) = self.prepare_record(record)?;
        self.plan.records.push(pair);
        Ok(reference)
    }

    pub(crate) fn prepare_record(
        &mut self,
        record: &[u8],
    ) -> Result<(ChildReference, PublicPlan), Error> {
        let budget = FeeBudget {
            chain: self.plan.chain.genesis()?,
            rate: FeeRate(NonZeroU64::new(self.limits.fee_rate).context("zero fee rate")?),
            maximum_base_units: self.limits.max_fee,
        };
        let prepared =
            prepare_signed_bytes(record, self.author, self.funder, &self.inputs, budget)?;
        let pair = prepared.plan;
        let reveal = decode(
            &pair.reveal,
            usize::try_from(config::STANDARD_TX_WEIGHT)? * 2,
        )?;
        let total_fee = self
            .plan
            .total_fee
            .checked_add(prepared.fee)
            .context("fee sum overflow")?;
        ensure!(
            total_fee <= self.limits.max_fee,
            "publication exceeds approved maximum fee"
        );
        self.plan.total_fee = total_fee;
        self.inputs = vec![FundingInput {
            funding: Funding {
                raw_transaction: pair.commit.clone(),
                vout: 1,
            },
            path: KeyPath::RECEIVE,
        }];
        self.plan.root_txid = reveal.compute_txid().to_string();
        let reference = ChildReference {
            txid: reveal.compute_txid(),
            record_hash: Sha256::digest(record).into(),
        };
        Ok((reference, pair))
    }

    pub(crate) fn metadata(&self) -> &PublicationPlan {
        &self.plan
    }

    pub(crate) fn finish(self) -> Result<PublicationPlan, Error> {
        self.plan.validate()?;
        Ok(self.plan)
    }
}
