use crate::{
    checkout, config,
    descriptor::{self, Descriptor},
    error::Error,
    inventory::Limits,
    plans::GitPlan,
    proofs, review,
    snapshot::{self, SnapshotReport},
};
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Seek,
    path::{Path, PathBuf},
};
use urma::multipart::RecoveryLimits;
use urma_identity::identity::IdentitySigner;
use urma_runtime::{
    disk_plan::DiskPlan, disk_publish, node::Node, plan::PlanLimits, publish, recovery,
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
    prepare_named(
        node,
        signer,
        repo,
        directory,
        limits,
        budget,
        &descriptor::source_name(repo)?,
    )
}

pub fn prepare_named(
    node: &Node,
    signer: &impl IdentitySigner,
    repo: &Path,
    directory: &Path,
    limits: &Limits,
    budget: PlanLimits,
    name: &str,
) -> Result<PreparedReport, Error> {
    snapshot::prepare_named(repo, directory, limits, name)?;
    prepare_snapshot(node, signer, directory, limits, budget)
}

pub fn prepare_snapshot(
    node: &Node,
    signer: &impl IdentitySigner,
    directory: &Path,
    limits: &Limits,
    budget: PlanLimits,
) -> Result<PreparedReport, Error> {
    let snapshot: SnapshotReport =
        serde_json::from_reader(File::open(directory.join("snapshot.json"))?)?;
    let mut payload = File::open(directory.join("object.bin"))?;
    let length = payload.metadata()?.len();
    let publication = DiskPlan::prepare_multipart(
        node,
        signer,
        &mut payload,
        length,
        Descriptor::PROFILE,
        budget,
        &directory.join("publication"),
    )?;
    let hash = GitPlan::freeze(directory, &publication, limits)?;
    Ok(PreparedReport {
        plan_id: hash,
        root_txid: publication.root_txid,
        author: publication.author,
        transactions: usize::try_from(publication.record_count)? * 2,
        total_fee: publication.total_fee,
        maximum_fee: publication.maximum_fee,
        review_required: true,
        broadcast: false,
        snapshot,
    })
}

pub fn inspect_plan(directory: &Path) -> Result<PreparedReport, Error> {
    let (_, hash, publication) = GitPlan::load_with_publication(directory)?;
    let snapshot: SnapshotReport =
        serde_json::from_reader(File::open(directory.join("snapshot.json"))?)?;
    Ok(PreparedReport {
        plan_id: hash,
        root_txid: publication.root_txid,
        author: publication.author,
        transactions: usize::try_from(publication.record_count)? * 2,
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
        &verified.descriptor,
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
    let (plan, hash, publication) = GitPlan::load_with_publication(directory)?;
    if approved != hash {
        return Err(Error::ReviewRequired(
            "approval does not match exact Git plan".into(),
        ));
    }
    review::require(directory, &hash)?;
    let journal = directory.join("progress.json");
    for mutable in [&journal, &journal.with_extension("observations.jsonl")] {
        for artifact in &plan.artifacts {
            publish::ensure_journal_distinct(&directory.join(&artifact.name), mutable)?;
        }
        publish::ensure_journal_distinct(&directory.join("plan.json"), mutable)?;
        publish::ensure_journal_distinct(&directory.join("review.json"), mutable)?;
    }
    Ok(disk_publish::publish(
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
            .checked_add(Descriptor::MAX_PREFIX_BYTES)
            .ok_or_else(|| Error::Capacity("payload capacity overflow".into()))?,
        max_nodes: DiskPlan::MAX_RECORDS,
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
    let mut object =
        recovery::recover_retained(node, root, recovery_limits(limits)?, scratch.path(), output)?;
    if ![Descriptor::PROFILE, Descriptor::UNNAMED_PROFILE].contains(&object.manifest().profile) {
        return Err(Error::Invalid("unsupported Git profile".into()));
    }
    let path = output.join("object.bin");
    let mut payload = File::create(&path)?;
    std::io::copy(&mut object, &mut payload)?;
    payload.sync_all()?;
    let validated = snapshot::validate(&path, scratch.path(), limits)?;
    validated
        .descriptor
        .require_profile(object.manifest().profile)?;
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor,
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
    validated
        .descriptor
        .require_profile(object.manifest().profile)?;
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor,
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
    Ok(clone_root_named(
        node,
        root,
        config::CloneDestination(Some(destination.to_path_buf())),
        limits,
    )?
    .0)
}

pub fn clone_root_named(
    node: &Node,
    root: Txid,
    requested: config::CloneDestination,
    limits: &Limits,
) -> Result<(RecoveredReport, PathBuf), Error> {
    let parent = config::staging_parent(&requested)?;
    let scratch = tempfile::Builder::new()
        .prefix(".urma-fetch-")
        .tempdir_in(parent)?;
    let recovered = scratch.path().join("snapshot");
    let report = recover(node, root, &recovered, limits)?;
    let destination = config::destination(requested, &report.snapshot.descriptor, root)?;
    checkout::install_with_evidence(
        &recovered.join("object.bin"),
        &destination,
        limits,
        &recovered,
    )?;
    Ok((report, destination))
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
