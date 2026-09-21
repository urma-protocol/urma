use crate::{
    descriptor::{self, Descriptor},
    error::Error,
    git,
    inventory::{self, Inventory, Limits},
    review,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReport {
    pub schema: u8,
    pub descriptor: Descriptor,
    pub inventory: Inventory,
    pub payload_sha256: String,
    pub scope: String,
    pub limits: Limits,
    pub scan: review::ScanReport,
}

pub struct ValidatedSnapshot {
    pub descriptor: Descriptor,
    pub inventory: Inventory,
    pub repository: PathBuf,
}

pub fn create_private_directory(path: &Path) -> Result<(), Error> {
    urma_io::create_private_directory(path)?;
    Ok(())
}

fn freeze(
    repo: &Path,
    destination: &Path,
    limits: &Limits,
    name: &str,
) -> Result<Descriptor, Error> {
    let repo = repo.canonicalize()?;
    let branch = git::output(&repo, &["symbolic-ref", "--quiet", "HEAD"], 65537)?;
    let branch = branch
        .strip_suffix(b"\n")
        .ok_or_else(|| Error::Invalid("branch response".into()))?
        .to_vec();
    git::raw_ref(&repo, &branch)?;
    if !branch.starts_with(b"refs/heads/") {
        return Err(Error::Invalid("HEAD must name a branch".into()));
    }
    let head = git::branch_head(&repo, &branch)?;
    let format = String::from_utf8(git::output(
        &repo,
        &["rev-parse", "--show-object-format"],
        32,
    )?)?
    .trim()
    .to_owned();
    let object_format = match format.as_str() {
        "sha1" => 1,
        "sha256" => 2,
        other => return Err(Error::Invalid(format!("Git object format {other}"))),
    };
    tracing::info!(target: "urma_progress", "Inspecting HEAD object inventory...");
    let inventory = inventory::inspect(&repo, &head, limits)?;
    create_private_directory(destination)?;
    let scratch = tempfile::tempdir_in(destination)?;
    let ids = scratch.path().join("objects");
    let mut list = File::create(&ids)?;
    for object in &inventory.objects {
        writeln!(list, "{}", object.oid)?;
    }
    list.sync_all()?;
    tracing::info!(target: "urma_progress", objects = inventory.objects.len(), "Creating native Git PACK...");
    let pack_path = destination.join("snapshot.pack");
    git::run(
        &repo,
        &[
            "pack-objects".as_ref(),
            "--stdout".as_ref(),
            "--no-reuse-delta".as_ref(),
            "--no-reuse-object".as_ref(),
            "--window=10".as_ref(),
            "--depth=50".as_ref(),
        ],
        &ids,
        &pack_path,
    )?;
    let mut pack = File::open(&pack_path)?;
    let pack_length = pack.metadata()?.len();
    tracing::info!(target: "urma_progress", bytes = pack_length, "Git PACK created");
    if pack_length > limits.max_pack_bytes {
        return Err(Error::Capacity("native PACK bytes".into()));
    }
    let descriptor = Descriptor {
        repository_name: name.to_owned(),
        object_format,
        head: hex::decode(&head)?,
        branch,
        pack_length,
        pack_sha256: descriptor::digest(&mut pack)?,
        first_root: [0; 32],
        previous_root: [0; 32],
    };
    pack.rewind()?;
    let payload_path = destination.join("object.bin");
    let mut payload = File::create(&payload_path)?;
    descriptor.encode(&mut payload)?;
    std::io::copy(&mut pack, &mut payload)?;
    payload.sync_all()?;
    Ok(descriptor)
}

pub fn prepare(repo: &Path, destination: &Path, limits: &Limits) -> Result<SnapshotReport, Error> {
    prepare_named(repo, destination, limits, &descriptor::source_name(repo)?)
}

pub fn prepare_named(
    repo: &Path,
    destination: &Path,
    limits: &Limits,
    name: &str,
) -> Result<SnapshotReport, Error> {
    descriptor::validate_name(name)?;
    let descriptor = freeze(repo, destination, limits, name)?;
    let scratch = tempfile::tempdir_in(destination)?;
    let payload_path = destination.join("object.bin");
    tracing::info!(target: "urma_progress", "Validating PACK and committed object closure...");
    let verified = validate(&payload_path, scratch.path(), limits)?;
    tracing::info!(target: "urma_progress", "Scanning public snapshot for possible secrets...");
    let scan = review::scan(
        &verified.repository,
        &verified.inventory,
        &descriptor,
        scratch.path(),
    )?;
    let report = SnapshotReport {
        schema: 1,
        descriptor,
        inventory: verified.inventory,
        payload_sha256: hex::encode(descriptor::digest(&mut File::open(payload_path)?)?),
        scope: "current committed snapshot; earlier history is not included".into(),
        limits: limits.clone(),
        scan,
    };
    write_json(&destination.join("scan.json"), &report.scan)?;
    write_json(&destination.join("snapshot.json"), &report)?;
    File::open(destination)?.sync_all()?;
    Ok(report)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.sync_all()?;
    Ok(())
}

pub fn inspect(payload: &Path) -> Result<Descriptor, Error> {
    Descriptor::decode(&mut File::open(payload)?)
}

pub fn validate(
    payload: &Path,
    scratch: &Path,
    limits: &Limits,
) -> Result<ValidatedSnapshot, Error> {
    let mut input = File::open(payload)?;
    let descriptor = Descriptor::decode(&mut input)?;
    if descriptor.pack_length > limits.max_pack_bytes {
        return Err(Error::Capacity("native PACK bytes".into()));
    }
    let pack_path = scratch.join("verified.pack");
    let mut pack = File::create(&pack_path)?;
    if std::io::copy(&mut input, &mut pack)? != descriptor.pack_length {
        return Err(Error::Invalid("native PACK length".into()));
    }
    pack.sync_all()?;
    let mut pack = File::open(&pack_path)?;
    if descriptor::digest(&mut pack)? != descriptor.pack_sha256 {
        return Err(Error::Invalid("native PACK SHA-256".into()));
    }
    pack.rewind()?;
    let count = pack_count(&mut pack, limits)?;
    let repository = scratch.join("repository");
    git::initialize(&repository, descriptor.object_format_name()?)?;
    git::raw_ref(&repository, &descriptor.branch)?;
    git::run(
        &repository,
        &["index-pack".as_ref(), "--stdin".as_ref()],
        &pack_path,
        &scratch.join("index-output"),
    )?;
    let head = hex::encode(&descriptor.head);
    let inventory = inventory::inspect(&repository, &head, limits)?;
    validate_closure(&repository, &inventory, count)?;
    if inventory.has_parents {
        std::fs::write(repository.join(".git/shallow"), format!("{head}\n"))?;
    }
    install_head(&repository, &descriptor)?;
    git::output(
        &repository,
        &["fsck", "--strict", "--full", "--no-reflogs"],
        1024 * 1024,
    )?;
    validate_blobs(&repository, &inventory, scratch)?;
    let expansion = descriptor
        .pack_length
        .checked_mul(32)
        .ok_or_else(|| Error::Capacity("expansion overflow".into()))?
        .max(64 * 1024 * 1024);
    if inventory.expanded_bytes > expansion || inventory.checkout_bytes > expansion {
        return Err(Error::Capacity(
            "PACK expansion ratio; explicit larger limits require a new candidate".into(),
        ));
    }
    Ok(ValidatedSnapshot {
        descriptor,
        inventory,
        repository,
    })
}

fn pack_count(pack: &mut File, limits: &Limits) -> Result<usize, Error> {
    let mut header = [0; 12];
    pack.read_exact(&mut header)?;
    if &header[..4] != b"PACK" || header[4..8] != [0, 0, 0, 2] {
        return Err(Error::Invalid("native PACK v2 header".into()));
    }
    let count = usize::try_from(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]))?;
    if count == 0 {
        return Err(Error::Invalid("empty Git PACK".into()));
    }
    if count > limits.max_objects {
        return Err(Error::Capacity("PACK object count".into()));
    }
    Ok(count)
}

fn validate_closure(repo: &Path, inventory: &Inventory, count: usize) -> Result<(), Error> {
    let output = git::output(
        repo,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
        128 * 1024 * 1024,
    )?;
    let objects = String::from_utf8(output)?
        .lines()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected = inventory
        .objects
        .iter()
        .map(|object| object.oid.clone())
        .collect::<BTreeSet<_>>();
    if objects != expected || objects.len() != count {
        return Err(Error::Invalid(
            "PACK duplicate, extra, missing or ancestor object".into(),
        ));
    }
    for entry in std::fs::read_dir(repo.join(".git/objects/pack"))? {
        let path = entry?.path();
        if path.extension().iter().any(|extension| *extension == "idx") {
            let index = path
                .to_str()
                .ok_or_else(|| Error::Capacity("non-UTF8 staging path".into()))?;
            let verified = String::from_utf8(git::output(
                repo,
                &["verify-pack", "-v", index],
                256 * 1024 * 1024,
            )?)?;
            for line in verified.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() == 7 && fields[0].len() >= 40 && fields[5].parse::<u32>()? > 50 {
                    return Err(Error::Capacity("PACK delta chain depth".into()));
                }
            }
        }
    }
    Ok(())
}

fn validate_blobs(repo: &Path, inventory: &Inventory, scratch: &Path) -> Result<(), Error> {
    for object in &inventory.objects {
        if object.kind != "blob" {
            continue;
        }
        let path = scratch.join("blob-check");
        git::run(
            repo,
            &["cat-file".as_ref(), "blob".as_ref(), object.oid.as_ref()],
            Path::new("/dev/null"),
            &path,
        )?;
        review::reject_lfs(&mut File::open(&path)?)?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn install_head(repo: &Path, descriptor: &Descriptor) -> Result<(), Error> {
    use std::os::unix::ffi::OsStringExt;
    let branch = std::ffi::OsString::from_vec(descriptor.branch.clone());
    let head = hex::encode(&descriptor.head);
    for args in [
        vec!["update-ref".as_ref(), branch.as_os_str(), head.as_ref()],
        vec!["symbolic-ref".as_ref(), "HEAD".as_ref(), branch.as_os_str()],
    ] {
        let status = git::command(repo)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            return Err(Error::Git("cannot install branch HEAD".into()));
        }
    }
    Ok(())
}
