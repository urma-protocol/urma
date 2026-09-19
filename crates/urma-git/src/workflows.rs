use crate::{
    checkout,
    descriptor::{self, Descriptor},
    error::Error,
    inventory::Limits,
    plans::GitPlan,
    proofs, review,
    snapshot::{self, SnapshotReport},
};
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Seek, path::Path};
use urma::{multipart::RecoveryLimits, storage};
use urma_identity::identity::IdentitySigner;
use urma_runtime::{
    node::Node,
    plan::{self, PlanLimits, PublicationPlan},
    publish, recovery,
};

#[derive(Serialize)]
pub struct PreparedReport {
    pub plan_id: String,
    pub root_txid: String,
    pub author: String,
    pub transactions: usize,
    pub total_fee: u64,
    pub maximum_fee: u64,
    pub review_required: bool,
    pub broadcast: bool,
    pub snapshot: SnapshotReport,
}

pub fn prepare(
    node: &Node,
    signer: &impl IdentitySigner,
    repo: &Path,
    directory: &Path,
    limits: &Limits,
    budget: PlanLimits,
) -> Result<PreparedReport, Error> {
    let snapshot = snapshot::prepare(repo, directory, limits)?;
    let payload = storage::read_bounded(&directory.join("object.bin"), 64 * 1024 * 1024)?;
    let publication = plan::prepare_multipart(node, signer, &payload, Descriptor::PROFILE, budget)?;
    let hash = GitPlan::freeze(directory, &publication, limits)?;
    Ok(PreparedReport {
        plan_id: hash,
        root_txid: publication.root_txid,
        author: publication.author,
        transactions: publication.records.len() * 2,
        total_fee: publication.total_fee,
        maximum_fee: publication.maximum_fee,
        review_required: true,
        broadcast: false,
        snapshot,
    })
}

pub fn inspect_plan(directory: &Path) -> Result<PreparedReport, Error> {
    let (plan, hash) = GitPlan::load(directory)?;
    let publication = plan.publication(directory)?;
    let snapshot: SnapshotReport =
        serde_json::from_reader(File::open(directory.join("snapshot.json"))?)?;
    Ok(PreparedReport {
        plan_id: hash,
        root_txid: publication.root_txid,
        author: publication.author,
        transactions: publication.records.len() * 2,
        total_fee: publication.total_fee,
        maximum_fee: publication.maximum_fee,
        review_required: true,
        broadcast: false,
        snapshot,
    })
}

pub fn record_review(directory: &Path, classifications: &[String]) -> Result<String, Error> {
    let (plan, hash) = GitPlan::load(directory)?;
    let scratch = tempfile::tempdir_in(directory)?;
    let verified = snapshot::validate(&directory.join("object.bin"), scratch.path(), &plan.limits)?;
    let actual = review::scan(
        &verified.repository,
        &verified.inventory,
        &verified.descriptor.branch,
        scratch.path(),
    )?;
    let recorded: review::ScanReport =
        serde_json::from_reader(File::open(directory.join("scan.json"))?)?;
    if serde_json::to_vec(&actual)? != serde_json::to_vec(&recorded)? {
        return Err(Error::ReviewRequired(
            "frozen scanner report does not describe artifact".into(),
        ));
    }
    review::record(directory, &hash, classifications)?;
    Ok(hash)
}

pub fn publish(
    node: &Node,
    directory: &Path,
    approved: &str,
) -> Result<publish::PublishReport, Error> {
    let (plan, hash) = GitPlan::load(directory)?;
    if approved != hash {
        return Err(Error::ReviewRequired(
            "approval does not match exact Git plan".into(),
        ));
    }
    review::require(directory, &hash)?;
    let publication = plan.publication(directory)?;
    let journal = directory.join("progress.json");
    for artifact in &plan.artifacts {
        publish::ensure_journal_distinct(&directory.join(&artifact.name), &journal)?;
    }
    publish::ensure_journal_distinct(&directory.join("plan.json"), &journal)?;
    publish::ensure_journal_distinct(&directory.join("review.json"), &journal)?;
    Ok(publish::publish(
        node,
        &publication,
        &plan.publication_id,
        &journal,
    )?)
}

pub fn recovery_limits(limits: &Limits) -> Result<RecoveryLimits, Error> {
    Ok(RecoveryLimits {
        max_payload_bytes: limits
            .max_pack_bytes
            .checked_add(65_675)
            .ok_or_else(|| Error::Capacity("payload capacity overflow".into()))?,
        max_nodes: PublicationPlan::MAX_RECORDS,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredReport {
    pub locator: proofs::Locator,
    pub content: String,
    pub author_proof: String,
    pub author: String,
    pub git_profile: String,
    pub chain_inclusion: String,
    pub snapshot: SnapshotReport,
}

pub fn recover(
    node: &Node,
    root: Txid,
    output: &Path,
    limits: &Limits,
) -> Result<RecoveredReport, Error> {
    snapshot::create_private_directory(output)?;
    let scratch = tempfile::tempdir_in(output)?;
    let anchor = node.tip()?;
    let mut object = recovery::recover(node, root, recovery_limits(limits)?, scratch.path())?;
    if object.manifest().profile != Descriptor::PROFILE {
        return Err(Error::Invalid("unsupported Git profile".into()));
    }
    let path = output.join("object.bin");
    let mut payload = File::create(&path)?;
    std::io::copy(&mut object, &mut payload)?;
    payload.sync_all()?;
    let validated = snapshot::validate(&path, scratch.path(), limits)?;
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor.branch,
        scratch.path(),
    )?;
    let locator = proofs::export(node, &object, output)?;
    let mut retained = proofs::reconstruct(output, recovery_limits(limits)?, scratch.path())?;
    if descriptor::digest(&mut retained)? != object.manifest().payload_hash {
        return Err(Error::Invalid("exported proof payload differs".into()));
    }
    if node.block_hash(anchor.0)?.to_string() != anchor.1 {
        return Err(Error::Invalid(
            "chain changed during Git recovery; retry".into(),
        ));
    }
    std::fs::copy(
        scratch.path().join("verified.pack"),
        output.join("snapshot.pack"),
    )?;
    let snapshot = SnapshotReport {
        schema: 1,
        descriptor: validated.descriptor,
        inventory: validated.inventory,
        payload_sha256: hex::encode(descriptor::digest(&mut File::open(&path)?)?),
        scope: "current committed snapshot; earlier history is not included".into(),
        limits: limits.clone(),
        scan,
    };
    let report = RecoveredReport {
        locator,
        content: "complete".into(),
        author_proof: "verified".into(),
        git_profile: "verified".into(),
        author: object.author().to_string(),
        chain_inclusion: "confirmed_at_observation".into(),
        snapshot,
    };
    snapshot::write_json(&output.join("recovery.json"), &report)?;
    File::open(output)?.sync_all()?;
    Ok(report)
}

pub fn verify(directory: &Path, limits: &Limits) -> Result<RecoveredReport, Error> {
    let scratch = tempfile::tempdir_in(directory)?;
    let mut object = proofs::reconstruct(directory, recovery_limits(limits)?, scratch.path())?;
    let actual = descriptor::digest(&mut object)?;
    let cached = directory.join("object.bin");
    if cached.try_exists()? {
        proofs::regular_file(&cached)?;
        if descriptor::digest(&mut File::open(&cached)?)? != actual {
            return Err(Error::Invalid(
                "cached payload differs from verified transaction proofs".into(),
            ));
        }
    }
    object.rewind()?;
    let payload = scratch.path().join("reconstructed.bin");
    let mut file = File::create(&payload)?;
    std::io::copy(&mut object, &mut file)?;
    file.sync_all()?;
    let validated = snapshot::validate(&payload, scratch.path(), limits)?;
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor.branch,
        scratch.path(),
    )?;
    let locator: proofs::Locator =
        serde_json::from_reader(File::open(directory.join("locator.json"))?)?;
    let snapshot = SnapshotReport {
        schema: 1,
        descriptor: validated.descriptor,
        inventory: validated.inventory,
        payload_sha256: hex::encode(actual),
        scope: "current committed snapshot; earlier history is not included".into(),
        limits: limits.clone(),
        scan,
    };
    Ok(RecoveredReport {
        locator,
        content: "complete".into(),
        author_proof: "verified".into(),
        git_profile: "verified".into(),
        author: object.author().to_string(),
        chain_inclusion: "not_checked".into(),
        snapshot,
    })
}

pub fn clone_root(
    node: &Node,
    root: Txid,
    destination: &Path,
    limits: &Limits,
) -> Result<RecoveredReport, Error> {
    if destination.try_exists()? {
        return Err(Error::Invalid("clone destination already exists".into()));
    }
    let parent = storage_parent(destination);
    let scratch = tempfile::Builder::new()
        .prefix(".urma-fetch-")
        .tempdir_in(parent)?;
    let recovered = scratch.path().join("snapshot");
    let report = recover(node, root, &recovered, limits)?;
    checkout::install_with_evidence(
        &recovered.join("object.bin"),
        destination,
        limits,
        &recovered,
    )?;
    Ok(report)
}

fn storage_parent(path: &Path) -> &Path {
    urma::config::output_parent(path)
}

pub fn parse_root(node: &Node, text: &str) -> Result<Txid, Error> {
    let parts = text.split(':').collect::<Vec<_>>();
    let txid = match parts.as_slice() {
        [value] => *value,
        [chain, value] => {
            let expected = match node.chain() {
                urma_chain::observation::Chain::LitecoinMainnet => "litecoin-mainnet",
                urma_chain::observation::Chain::LitecoinTestnet => "litecoin-testnet",
                urma_chain::observation::Chain::BitcoinTestnet4 => "bitcoin-testnet4",
                urma_chain::observation::Chain::BitcoinRegtest => "bitcoin-regtest",
            };
            if *chain != expected {
                return Err(Error::Invalid("locator and selected chain disagree".into()));
            }
            *value
        }
        other => {
            return Err(Error::Invalid(format!(
                "invalid locator with {} parts",
                other.len()
            )));
        }
    };
    txid.parse()
        .map_err(urma::error::Error::from)
        .map_err(Error::from)
}
