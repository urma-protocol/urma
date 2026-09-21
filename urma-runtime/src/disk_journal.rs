use crate::error::{Error, ensure};
use crate::{
    disk_plan::DiskPlan,
    node::Node,
    publish::{PublishReport, ensure_journal_distinct},
};
use crate::{node::Presence, storage};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

pub(crate) fn history(journal: &Path, id: &str) -> Result<HashMap<String, Presence>, Error> {
    let mut history = HashMap::new();
    if journal.try_exists()? {
        let report: PublishReport =
            serde_json::from_slice(&storage::read_bounded(journal, 1024 * 1024)?)?;
        ensure!(report.plan_id == id, "journal belongs to another plan");
        for row in report.transactions {
            if !matches!(row.presence, Presence::Missing) {
                history.insert(row.txid, row.presence);
            }
        }
    }
    let observations = journal.with_extension("observations.jsonl");
    if observations.try_exists()? {
        let mut reader = BufReader::new(File::open(observations)?);
        loop {
            let mut line = Vec::new();
            let count = reader
                .by_ref()
                .take(1024 * 1024)
                .read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            ensure!(count < 1024 * 1024, "observation exceeds journal capacity");
            if !line.ends_with(b"\n") {
                break;
            }
            let value: serde_json::Value = serde_json::from_slice(&line)?;
            let report: PublishReport = serde_json::from_value(value["report"].clone())?;
            ensure!(report.plan_id == id, "observations belong to another plan");
            for row in report.transactions {
                history.insert(row.txid, row.presence);
            }
            ensure!(
                history.len() <= usize::try_from(DiskPlan::MAX_RECORDS)? * 2,
                "observation transaction capacity exceeded"
            );
        }
    }
    Ok(history)
}

pub(crate) fn guard(plan: &DiskPlan, journal: &Path) -> Result<(), Error> {
    let observations = journal.with_extension("observations.jsonl");
    for name in ["plan.json", "records.bin", "index.bin"] {
        let input = plan.directory().join(name);
        ensure_journal_distinct(&input, journal)?;
        ensure_journal_distinct(&input, &observations)?;
    }
    if journal.try_exists()? {
        ensure_journal_distinct(journal, &observations)?;
    } else {
        ensure!(
            journal != observations,
            "journal and observations log must differ"
        );
    }
    if observations.try_exists()? {
        ensure!(
            std::fs::symlink_metadata(&observations)?
                .file_type()
                .is_file(),
            "observations log must be a regular file"
        );
    }
    Ok(())
}

pub(crate) fn observe(node: &Node, journal: &Path, report: &PublishReport) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = journal.with_extension("observations.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    let mut bytes = serde_json::to_vec(
        &serde_json::json!({"source": node.inclusion_evidence(), "chain": node.chain(), "report": report}),
    )?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(urma_io::output_parent(&path))?.sync_all()?;
    Ok(())
}
