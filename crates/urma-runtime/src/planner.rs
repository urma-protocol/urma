use crate::{
    node::Node,
    plan::{PlanLimits, PublicationPlan},
};
use bitcoin::{
    Transaction,
    consensus::{deserialize, serialize},
};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;
use urma::{
    error::{Context, Error, ensure},
    publication::PublicPlan,
};
use urma_core::multipart::ChildReference;
use urma_identity::identity::IdentitySigner;
use urma_wallet::{
    funding::Funding,
    wallet::{FeeBudget, FeeRate, SpendRequest},
};

pub(crate) struct Planner<'a, S> {
    signer: &'a S,
    funding: Funding,
    plan: PublicationPlan,
    limits: PlanLimits,
}

impl<'a, S: IdentitySigner> Planner<'a, S> {
    pub(crate) fn new(
        node: &Node,
        signer: &'a S,
        limits: PlanLimits,
        records: u32,
    ) -> Result<Self, Error> {
        ensure!(
            records <= PublicationPlan::MAX_RECORDS,
            "in-memory publication exceeds client capacity"
        );
        Self::streaming(node, signer, limits, records)
    }

    pub(crate) fn streaming(
        node: &Node,
        signer: &'a S,
        limits: PlanLimits,
        records: u32,
    ) -> Result<Self, Error> {
        ensure!(
            records > 0 && records <= limits.max_records,
            "publication exceeds caller record budget"
        );
        ensure!(
            (1..=100).contains(&limits.fee_rate) && limits.max_fee > 0,
            "invalid publication fee limits"
        );
        let minimum = limits
            .max_fee
            .checked_add(u64::from(records) * 1000 + 1000)
            .context("funding budget overflow")?;
        let funding = node.select_funding(signer, minimum)?;
        Ok(Self {
            signer,
            funding,
            limits,
            plan: PublicationPlan {
                version: 1,
                chain: node.chain(),
                author: signer.public_key().inner.x_only_public_key().0.to_string(),
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
        let previous = self.funding.prevout()?.1;
        let mut pair = urma::publication::prepare_bytes(
            record,
            self.signer,
            self.funding.clone(),
            self.plan.chain,
            self.limits.fee_rate,
        )?;
        let commit: Transaction = deserialize(&hex::decode(&pair.commit)?)?;
        let budget = FeeBudget {
            chain: self.plan.chain.genesis()?,
            rate: FeeRate(NonZeroU64::new(self.limits.fee_rate).context("zero fee rate")?),
            maximum_base_units: self.limits.max_fee,
        };
        let signed = urma_wallet::signing::sign(
            self.signer,
            &SpendRequest {
                transaction: &commit,
                prevouts: std::slice::from_ref(&previous),
                budget,
            },
        )?;
        pair.commit = hex::encode(serialize(&signed));
        let reveal: Transaction = deserialize(&hex::decode(&pair.reveal)?)?;
        let outputs = signed.output[1]
            .value
            .to_sat()
            .checked_add(reveal.output[0].value.to_sat())
            .context("output sum overflow")?;
        let fee = previous
            .value
            .to_sat()
            .checked_sub(outputs)
            .context("publication value overflow")?;
        self.plan.total_fee = self
            .plan
            .total_fee
            .checked_add(fee)
            .context("fee sum overflow")?;
        ensure!(
            self.plan.total_fee <= self.limits.max_fee,
            "publication exceeds approved maximum fee"
        );
        self.funding = Funding {
            raw_transaction: pair.commit.clone(),
            vout: 1,
        };
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
