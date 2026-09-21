use crate::{
    descriptor,
    error::Error,
    git,
    inventory::{Entry, Limits},
    proofs, review,
    scan_batch::Batch,
    snapshot::{self, ValidatedSnapshot},
};
use std::{fs::File, io::Write, path::Path};

pub fn install(
    payload: &Path,
    destination: &Path,
    limits: &Limits,
) -> Result<snapshot::SnapshotReport, Error> {
    install_staged(payload, destination, limits, Evidence::Local)
}

pub fn install_with_evidence(
    payload: &Path,
    destination: &Path,
    limits: &Limits,
    directory: &Path,
) -> Result<snapshot::SnapshotReport, Error> {
    install_staged(payload, destination, limits, Evidence::Chain(directory))
}

enum Evidence<'a> {
    Local,
    Chain(&'a Path),
}

fn install_staged(
    payload: &Path,
    destination: &Path,
    limits: &Limits,
    evidence: Evidence<'_>,
) -> Result<snapshot::SnapshotReport, Error> {
    if destination.try_exists()? {
        return Err(Error::Invalid("clone destination already exists".into()));
    }
    let stage = tempfile::Builder::new()
        .prefix(".urma-clone-")
        .tempdir_in(urma_io::output_parent(destination))?;
    let validated = snapshot::validate(payload, stage.path(), limits)?;
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor,
        stage.path(),
    )?;
    let report = snapshot::SnapshotReport {
        schema: 1,
        descriptor: validated.descriptor.clone(),
        inventory: validated.inventory.clone(),
        payload_sha256: hex::encode(descriptor::digest(&mut File::open(payload)?)?),
        scope: "current committed snapshot; earlier history is not included".into(),
        limits: limits.clone(),
        scan,
    };
    finish_install(payload, destination, &validated, &report, evidence)?;
    Ok(report)
}

pub(crate) fn install_verified(
    payload: &Path,
    destination: &Path,
    validated: &ValidatedSnapshot,
    report: &snapshot::SnapshotReport,
    evidence: &Path,
) -> Result<(), Error> {
    finish_install(
        payload,
        destination,
        validated,
        report,
        Evidence::Chain(evidence),
    )
}

fn finish_install(
    payload: &Path,
    destination: &Path,
    validated: &ValidatedSnapshot,
    report: &snapshot::SnapshotReport,
    evidence: Evidence<'_>,
) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    if destination.try_exists()? {
        return Err(Error::Invalid("clone destination already exists".into()));
    }
    materialize(validated)?;
    let head = hex::encode(&validated.descriptor.head);
    git::output(&validated.repository, &["read-tree", &head], 4096)?;
    let status = git::output(
        &validated.repository,
        &[
            "-c",
            "core.preloadIndex=false",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        1024 * 1024,
    )?;
    if !status.is_empty() {
        return Err(Error::Invalid(
            "checkout index or worktree differs from HEAD".into(),
        ));
    }
    let retained = validated.repository.join(".git/urma");
    snapshot::create_private_directory(&retained)?;
    std::fs::copy(payload, retained.join("object.bin"))?;
    let retained_hash = hex::encode(descriptor::digest(&mut File::open(
        retained.join("object.bin"),
    )?)?);
    if retained_hash != report.payload_sha256 {
        return Err(Error::Invalid(
            "retained payload changed after validation".into(),
        ));
    }
    snapshot::write_json(&retained.join("snapshot.json"), report)?;
    std::fs::set_permissions(
        &validated.repository,
        std::fs::Permissions::from_mode(0o700),
    )?;
    retain_evidence(&retained, evidence)?;
    sync_directory(&validated.repository)?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &validated.repository,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| Error::Io(error.into()))?;
    File::open(urma_io::output_parent(destination))?.sync_all()?;
    Ok(())
}

fn materialize(snapshot: &ValidatedSnapshot) -> Result<(), Error> {
    Batch::with(&snapshot.repository, &snapshot.repository, |batch| {
        materialize_batch(snapshot, batch)
    })
}

fn materialize_batch(snapshot: &ValidatedSnapshot, batch: &mut Batch) -> Result<(), Error> {
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
    let mut links = Vec::new();
    let total = snapshot.inventory.entries.len();
    let mut done = 0u64;
    for entry in &snapshot.inventory.entries {
        let path = snapshot
            .repository
            .join(std::ffi::OsString::from_vec(hex::decode(&entry.path_hex)?));
        if entry.mode == 0o40000 {
            std::fs::create_dir(&path)?;
        } else if entry.mode == 0o120000 {
            links.push(entry);
            continue;
        } else {
            let mut output = File::create(&path)?;
            batch.copy_blob(&entry.oid, entry.size, &mut output)?;
            let mode = if entry.mode == 0o100755 { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            verify_file(&path, entry)?;
        }
        done += 1;
        tracing::info!(target: "urma_ui", phase = "Materializing checkout", done, total);
    }
    for entry in links {
        materialize_link(snapshot, entry, batch)?;
        done += 1;
        tracing::info!(target: "urma_ui", phase = "Materializing checkout", done, total);
    }
    Ok(())
}

fn materialize_link(
    snapshot: &ValidatedSnapshot,
    entry: &Entry,
    batch: &mut Batch,
) -> Result<(), Error> {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    if entry.size > 65536 {
        return Err(Error::Capacity("symlink target".into()));
    }
    let mut target = Vec::new();
    batch.copy_blob(&entry.oid, entry.size, &mut target)?;
    if target.contains(&0) {
        return Err(Error::Invalid("symlink target contains NUL".into()));
    }
    let path = snapshot
        .repository
        .join(std::ffi::OsString::from_vec(hex::decode(&entry.path_hex)?));
    symlink(std::ffi::OsString::from_vec(target.clone()), &path)?;
    let actual = std::fs::read_link(path)?;
    use std::os::unix::ffi::OsStrExt;
    if actual.as_os_str().as_bytes() != target {
        return Err(Error::Invalid("symlink fidelity".into()));
    }
    Ok(())
}

fn verify_file(path: &Path, entry: &Entry) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    let executable = metadata.permissions().mode() & 0o111 != 0;
    if !metadata.is_file() || metadata.len() != entry.size || executable != (entry.mode == 0o100755)
    {
        return Err(Error::Invalid(
            "filesystem cannot preserve published entry".into(),
        ));
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), Error> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_dir() {
            sync_directory(&entry.path())?;
        } else if metadata.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

pub fn retain_locator(repository: &Path, locator: &impl serde::Serialize) -> Result<(), Error> {
    let path = repository.join(".git/urma/locator.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(locator)?)?;
    file.sync_all()?;
    Ok(())
}

fn retain_evidence(destination: &Path, evidence: Evidence<'_>) -> Result<(), Error> {
    match evidence {
        Evidence::Local => Ok(()),
        Evidence::Chain(directory) => {
            proofs::regular_file(&directory.join("locator.json"))?;
            std::fs::copy(
                directory.join("locator.json"),
                destination.join("locator.json"),
            )?;
            if !std::fs::symlink_metadata(directory.join("tx"))?.is_dir() {
                return Err(Error::Invalid("proof transaction directory type".into()));
            }
            snapshot::create_private_directory(&destination.join("tx"))?;
            for entry in std::fs::read_dir(directory.join("tx"))? {
                let entry = entry?;
                proofs::regular_file(&entry.path())?;
                std::fs::copy(entry.path(), destination.join("tx").join(entry.file_name()))?;
            }
            Ok(())
        }
    }
}
