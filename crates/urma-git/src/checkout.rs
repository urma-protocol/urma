use crate::{
    descriptor,
    error::Error,
    git,
    inventory::{Entry, Limits},
    proofs, review,
    snapshot::{self, ValidatedSnapshot},
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

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
    use std::os::unix::fs::PermissionsExt;
    if destination.try_exists()? {
        return Err(Error::Invalid("clone destination already exists".into()));
    }
    let parent = urma_io::output_parent(destination);
    let stage = tempfile::Builder::new()
        .prefix(".urma-clone-")
        .tempdir_in(parent)?;
    let validated = snapshot::validate(payload, stage.path(), limits)?;
    materialize(&validated)?;
    let head = hex::encode(&validated.descriptor.head);
    git::output(&validated.repository, &["read-tree", &head], 4096)?;
    let status = git::output(
        &validated.repository,
        &["status", "--porcelain=v1", "--untracked-files=all"],
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
    let scan = review::scan(
        &validated.repository,
        &validated.inventory,
        &validated.descriptor,
        stage.path(),
    )?;
    let report = snapshot::SnapshotReport {
        schema: 1,
        descriptor: validated.descriptor,
        inventory: validated.inventory,
        payload_sha256: hex::encode(descriptor::digest(&mut File::open(payload)?)?),
        scope: "current committed snapshot; earlier history is not included".into(),
        limits: limits.clone(),
        scan,
    };
    snapshot::write_json(&retained.join("snapshot.json"), &report)?;
    std::fs::set_permissions(
        &validated.repository,
        std::fs::Permissions::from_mode(0o700),
    )?;
    retain_evidence(&retained, evidence)?;
    sync_directory(&validated.repository)?;
    if destination.try_exists()? {
        return Err(Error::Invalid(
            "clone destination appeared during staging".into(),
        ));
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &validated.repository,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| Error::Io(error.into()))?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}

fn materialize(snapshot: &ValidatedSnapshot) -> Result<(), Error> {
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
    let mut links = Vec::new();
    for entry in &snapshot.inventory.entries {
        let path = snapshot
            .repository
            .join(std::ffi::OsString::from_vec(hex::decode(&entry.path_hex)?));
        if entry.mode == 0o40000 {
            std::fs::create_dir(&path)?;
        } else if entry.mode == 0o120000 {
            links.push(entry);
        } else {
            git::run(
                &snapshot.repository,
                &["cat-file".as_ref(), "blob".as_ref(), entry.oid.as_ref()],
                Path::new("/dev/null"),
                &path,
            )?;
            let mode = if entry.mode == 0o100755 { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            verify_file(&snapshot.repository, &path, entry)?;
        }
    }
    for entry in links {
        materialize_link(snapshot, entry)?;
    }
    Ok(())
}

fn materialize_link(snapshot: &ValidatedSnapshot, entry: &Entry) -> Result<(), Error> {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    if entry.size > 65536 {
        return Err(Error::Capacity("symlink target".into()));
    }
    let target = git::output(
        &snapshot.repository,
        &["cat-file", "blob", &entry.oid],
        65536,
    )?;
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

fn verify_file(repo: &Path, path: &Path, entry: &Entry) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    let executable = metadata.permissions().mode() & 0o111 != 0;
    if !metadata.is_file() || metadata.len() != entry.size || executable != (entry.mode == 0o100755)
    {
        return Err(Error::Invalid(
            "filesystem cannot preserve published entry".into(),
        ));
    }
    let input = File::open(path)?;
    let mut output = tempfile::tempfile_in(repo)?;
    let status = git::command(repo)
        .args(["hash-object", "--stdin", "--no-filters"])
        .stdin(input)
        .stdout(output.try_clone()?)
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(Error::Git("checkout hash verification".into()));
    }
    use std::io::Seek;
    output.rewind()?;
    let mut oid = String::new();
    output.read_to_string(&mut oid)?;
    if oid.trim() != entry.oid {
        return Err(Error::Invalid("checkout file OID".into()));
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
