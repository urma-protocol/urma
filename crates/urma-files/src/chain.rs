use crate::{
    catalog::Catalog,
    config::{MAX_CATALOG_BYTES, MAX_SCAN_BLOCKS},
    recover::{self, ObjectSource},
};
use bitcoin::{Block, Transaction};
use std::collections::BTreeMap;
use urma_core::{envelope, format::RecordKind};
use urma_identity::keys::RecoverySecret;
use urma_runtime::node::Node;
use urma_runtime::{
    backend,
    container::PrivateObject,
    error::{Context, Error, ensure},
};

pub struct ChainRecovery {
    pub objects: BTreeMap<[u8; 32], PrivateObject>,
    pub start_height: u64,
    pub tip_height: u64,
    pub tip_hash: String,
    pub rejected_records: u64,
}

pub fn scan(
    node: &Node,
    secret: &RecoverySecret,
    start_height: u64,
    max_blocks: u64,
) -> Result<ChainRecovery, Error> {
    node.verify_network()?;
    node.require_txindex()?;
    let (tip_height, tip_hash) = node.tip()?;
    ensure!(
        start_height <= tip_height,
        "start height is beyond chain tip"
    );
    let count = tip_height
        .checked_sub(start_height)
        .and_then(|blocks| blocks.checked_add(1))
        .context("block range overflow")?;
    ensure!(
        max_blocks > 0 && max_blocks <= MAX_SCAN_BLOCKS && count <= max_blocks,
        "scan exceeds requested block limit"
    );
    let mut recovery = ChainRecovery {
        objects: BTreeMap::new(),
        start_height,
        tip_height,
        tip_hash,
        rejected_records: 0,
    };
    for height in start_height..=tip_height {
        let block = node.block(height)?;
        let rejected = collect_block(node, &block, secret, &mut recovery.objects)?;
        recovery.rejected_records = recovery
            .rejected_records
            .checked_add(rejected)
            .context("rejected record overflow")?;
    }
    ensure!(
        node.block_hash(tip_height)?.to_string() == recovery.tip_hash,
        "chain changed during private recovery; retry scan"
    );
    Ok(recovery)
}

fn collect_block(
    node: &Node,
    block: &Block,
    secret: &RecoverySecret,
    objects: &mut BTreeMap<[u8; 32], PrivateObject>,
) -> Result<u64, Error> {
    let mut rejected = 0u64;
    for transaction in &block.txdata {
        if !transaction
            .input
            .iter()
            .any(|input| envelope::is_candidate(&input.witness))
        {
            continue;
        }
        let parsed = match verified_record(node, transaction) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(%error, "private recovery skipped invalid candidate");
                rejected = rejected.checked_add(1).context("rejected count overflow")?;
                continue;
            }
        };
        if RecordKind::parse(&parsed.record)? == RecordKind::Private {
            rejected = rejected
                .checked_add(
                    secret
                        .with_bytes(|root| backend::accept_record(root, &parsed.record, objects))?,
                )
                .context("rejected count overflow")?;
        }
    }
    Ok(rejected)
}

fn verified_record(
    node: &Node,
    transaction: &Transaction,
) -> Result<envelope::ParsedEnvelope, Error> {
    envelope::extract_reveal(transaction)?;
    let parent = transaction
        .input
        .first()
        .context("reveal has no input")?
        .previous_output
        .txid;
    let commit = node.transaction(parent)?;
    Ok(envelope::verify_reveal(transaction, &commit)?)
}

pub fn catalogs(recovery: &ChainRecovery) -> Result<Vec<String>, Error> {
    let mut ids = Vec::new();
    for (id, object) in &recovery.objects {
        if !object.is_complete() || object.total > u64::try_from(MAX_CATALOG_BYTES)? {
            continue;
        }
        let bytes = object.finish()?;
        if !bytes.starts_with(b"{") {
            continue;
        }
        match Catalog::decode(&bytes) {
            Ok(_catalog) => ids.push(hex::encode(id)),
            Err(error) => {
                tracing::warn!(%error, "private object is not a supported profile catalog")
            }
        }
    }
    Ok(ids)
}

pub fn catalog(recovery: &ChainRecovery, id: &str) -> Result<Catalog, Error> {
    recover::catalog(
        ObjectSource::Authenticated {
            objects: &recovery.objects,
        },
        id,
    )
}
