use crate::{
    disk_plan::DiskPlan,
    publish::{PublishReport, ensure_journal_distinct},
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
use urma::error::{Error, ensure};

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

pub(crate) fn observe(journal: &Path, report: &PublishReport) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = journal.with_extension("observations.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    let mut bytes = serde_json::to_vec(report)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(urma::config::output_parent(&path))?.sync_all()?;
    Ok(())
}
