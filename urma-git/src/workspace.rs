use crate::{
    descriptor,
    error::Error,
    git,
    inventory::Limits,
    review::ScanReport,
    snapshot::{self, SnapshotReport},
};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

pub fn lock(directory: &Path) -> Result<File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = std::path::absolute(directory)?;
    let name = directory
        .file_name()
        .ok_or_else(|| Error::Invalid("plan directory needs a name".into()))?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    let path = directory.with_file_name(lock_name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|cause| {
        Error::Io(std::io::Error::other(format!(
            "another operation is using this plan: {cause}"
        )))
    })?;
    Ok(file)
}

pub fn ensure_unpublished(directory: &Path) -> Result<(), Error> {
    if directory.join("progress.json").try_exists()?
        || directory.join("progress.observations.jsonl").try_exists()?
    {
        return Err(Error::Invalid(format!(
            "publication has already started in {}; use git resume --plan {} with the matching network; this plan will not be replaced",
            directory.display(),
            directory.display()
        )));
    }
    Ok(())
}

fn owned(directory: &Path) -> Result<(), Error> {
    if !std::fs::symlink_metadata(directory)?.is_dir() {
        return Err(Error::Invalid("plan path must be a real directory".into()));
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "publication" {
            owned_publication(&entry.path())?;
        } else if !entry.file_type()?.is_file() {
            return Err(Error::Invalid(
                "plan artifact must be a regular file".into(),
            ));
        }
        if ![
            "object.bin",
            "snapshot.pack",
            "snapshot.json",
            "scan.json",
            "plan.json",
            "publication",
            "review.json",
        ]
        .iter()
        .any(|allowed| name == *allowed)
        {
            return Err(Error::Invalid(
                "plan directory contains unrelated files; it will not be replaced".into(),
            ));
        }
    }
    Ok(())
}

fn owned_publication(directory: &Path) -> Result<(), Error> {
    if !std::fs::symlink_metadata(directory)?.is_dir() {
        return Err(Error::Invalid(
            "publication must be a real directory".into(),
        ));
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !["plan.json", "records.bin", "index.bin"]
                .iter()
                .any(|name| entry.file_name() == *name)
        {
            return Err(Error::Invalid(
                "publication contains unrelated files; preserving it".into(),
            ));
        }
    }
    Ok(())
}

pub fn snapshot(
    repo: &Path,
    directory: &Path,
    limits: &Limits,
    name: &str,
) -> Result<SnapshotReport, Error> {
    ensure_unpublished(directory)?;
    if directory.try_exists()? {
        owned(directory)?;
        if directory.join("snapshot.json").try_exists()? {
            let saved: SnapshotReport =
                serde_json::from_reader(File::open(directory.join("snapshot.json"))?)?;
            if reusable(repo, directory, limits, name, &saved)? {
                tracing::info!(target: "urma_progress", "Reusing verified PACK and scan from {}", directory.display());
                return Ok(saved);
            }
        }
    }
    let parent = urma_io::output_parent(directory);
    let staging = tempfile::Builder::new()
        .prefix(".urma-prepare-")
        .tempdir_in(parent)?;
    let fresh = staging.path().join("plan");
    let report = snapshot::prepare_named(repo, &fresh, limits, name)?;
    replace(&fresh, directory)?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}

fn reusable(
    repo: &Path,
    directory: &Path,
    limits: &Limits,
    name: &str,
    saved: &SnapshotReport,
) -> Result<bool, Error> {
    let branch = git::output(repo, &["symbolic-ref", "--quiet", "HEAD"], 65537)?;
    let branch = branch
        .strip_suffix(b"\n")
        .ok_or_else(|| Error::Invalid("Git branch response".into()))?;
    let head = git::branch_head(repo, branch)?;
    if branch != saved.descriptor.branch
        || head != hex::encode(&saved.descriptor.head)
        || name != saved.descriptor.repository_name
        || serde_json::to_vec(limits)? != serde_json::to_vec(&saved.limits)?
    {
        return Ok(false);
    }
    let object = directory.join("object.bin");
    let pack = directory.join("snapshot.pack");
    let scan: ScanReport = serde_json::from_reader(File::open(directory.join("scan.json"))?)?;
    Ok(saved.scan.reviewable()
        && serde_json::to_vec(&scan)? == serde_json::to_vec(&saved.scan)?
        && serde_json::to_vec(&snapshot::inspect(&object)?)?
            == serde_json::to_vec(&saved.descriptor)?
        && hex::encode(descriptor::digest(&mut File::open(object)?)?) == saved.payload_sha256
        && pack.metadata()?.len() == saved.descriptor.pack_length
        && descriptor::digest(&mut File::open(pack)?)? == saved.descriptor.pack_sha256)
}

pub fn replace(fresh: &Path, directory: &Path) -> Result<(), Error> {
    ensure_unpublished(directory)?;
    let flags = if directory.try_exists()? {
        owned(directory)?;
        rustix::fs::RenameFlags::EXCHANGE
    } else {
        rustix::fs::RenameFlags::NOREPLACE
    };
    rustix::fs::renameat_with(rustix::fs::CWD, fresh, rustix::fs::CWD, directory, flags)
        .map_err(std::io::Error::from)?;
    File::open(urma_io::output_parent(directory))?.sync_all()?;
    Ok(())
}

pub(crate) fn copy_snapshot(directory: &Path, destination: &Path) -> Result<(), Error> {
    snapshot::create_private_directory(destination)?;
    for name in ["object.bin", "snapshot.pack", "snapshot.json", "scan.json"] {
        let input = directory.join(name);
        if !std::fs::symlink_metadata(&input)?.is_file() {
            return Err(Error::Invalid(
                "snapshot artifact must be a regular file".into(),
            ));
        }
        std::fs::hard_link(input, destination.join(name))?;
    }
    Ok(())
}
