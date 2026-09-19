use crate::{
    descriptor::{self, Descriptor},
    error::Error,
    inventory::Limits,
};
use bitcoin::{Transaction, Txid, consensus::deserialize};
use std::{collections::BTreeMap, fs::File, path::Path};
use urma::{
    multipart::{
        FetchError, MultipartRecord, MultipartSource, RecordRequest, RecoveryLimits, VerifiedRecord,
    },
    publication::PublicPlan,
};
use urma_runtime::plan::PublicationPlan;

struct PlanSource<'a> {
    records: BTreeMap<Txid, &'a PublicPlan>,
}

fn record(pair: &PublicPlan) -> Result<VerifiedRecord, urma::error::Error> {
    let reveal: Transaction = deserialize(&hex::decode(&pair.reveal)?)?;
    let commit: Transaction = deserialize(&hex::decode(&pair.commit)?)?;
    Ok(VerifiedRecord::verify(
        reveal.compute_txid(),
        &reveal,
        &commit,
    )?)
}

impl MultipartSource for PlanSource<'_> {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        let pair = self.records.get(&request.reference.txid).ok_or_else(|| {
            FetchError::Source(urma::error::Error::Missing(
                "signed plan graph reference".into(),
            ))
        })?;
        record(pair).map_err(|cause| match cause {
            urma::error::Error::Protocol(error) => FetchError::Rejected(error),
            error => FetchError::Source(error),
        })
    }
}

pub fn verify(plan: &PublicationPlan, directory: &Path, limits: &Limits) -> Result<(), Error> {
    let mut records = BTreeMap::new();
    for pair in &plan.records {
        let verified = record(pair)?;
        verified.decode()?;
        records.insert(verified.txid(), pair);
    }
    if records.len() != plan.records.len() {
        return Err(Error::Invalid("duplicate plan reveal".into()));
    }
    let root = record(
        plan.records
            .last()
            .ok_or_else(|| Error::Invalid("empty plan".into()))?,
    )?;
    let MultipartRecord::Root(manifest) = root.decode()? else {
        return Err(Error::Invalid("Git plan root kind".into()));
    };
    if manifest.profile != Descriptor::PROFILE
        || usize::try_from(manifest.geometry()?.nodes())? != records.len()
    {
        return Err(Error::Invalid("Git plan graph inventory".into()));
    }
    let scratch = tempfile::tempdir_in(directory)?;
    let capacity = RecoveryLimits {
        max_payload_bytes: limits
            .max_pack_bytes
            .checked_add(Descriptor::MAX_PREFIX_BYTES)
            .ok_or_else(|| Error::Capacity("payload capacity overflow".into()))?,
        max_nodes: PublicationPlan::MAX_RECORDS,
    };
    let mut object =
        urma::multipart::reconstruct(&root, &mut PlanSource { records }, capacity, scratch.path())
            .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    if descriptor::digest(&mut object)?
        != descriptor::digest(&mut File::open(directory.join("object.bin"))?)?
    {
        return Err(Error::Invalid(
            "signed graph differs from reviewed Git artifact".into(),
        ));
    }
    Ok(())
}
