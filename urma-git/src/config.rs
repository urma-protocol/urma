use crate::{
    descriptor::{self, Descriptor},
    error::Error,
};
use bitcoin::Txid;
use std::path::{Path, PathBuf};

pub struct CloneDestination(pub Option<PathBuf>);

pub fn destination(
    requested: CloneDestination,
    descriptor: &Descriptor,
    root: Txid,
) -> Result<PathBuf, Error> {
    let path = match requested.0 {
        Some(path) => path,
        None => {
            if descriptor.repository_name.is_empty() {
                PathBuf::from(format!("urma-{}", &root.to_string()[..12]))
            } else {
                descriptor::validate_name(&descriptor.repository_name)?;
                PathBuf::from(&descriptor.repository_name)
            }
        }
    };
    Ok(std::path::absolute(path)?)
}

pub fn staging_parent(requested: &CloneDestination) -> Result<PathBuf, Error> {
    match &requested.0 {
        Some(path) => {
            if path.try_exists()? || path.is_symlink() {
                return Err(Error::Invalid(
                    "clone destination already exists; choose another directory".into(),
                ));
            }
            Ok(urma_io::output_parent(path).to_path_buf())
        }
        None => Ok(std::env::current_dir()?),
    }
}

pub struct PublicationName(pub Option<String>);

pub fn publication_name(repo: &Path, requested: PublicationName) -> Result<String, Error> {
    match requested.0 {
        Some(name) => {
            descriptor::validate_name(&name)?;
            Ok(name)
        }
        None => descriptor::source_name(repo),
    }
}

pub fn pack_capacity() -> u64 {
    urma_core::multipart::Geometry::MAX_OBJECT_BYTES - Descriptor::MAX_PREFIX_BYTES
}

pub fn worker_file_capacity() -> u64 {
    urma_core::multipart::Geometry::MAX_OBJECT_BYTES
}

pub(crate) const SCAN_FINDINGS_LIMIT: usize = 65_536;

pub(crate) fn scan_workers(objects: usize) -> Result<usize, Error> {
    let processors = std::thread::available_parallelism()?.get();
    let requested = match std::env::var("URMA_GIT_SCAN_WORKERS") {
        Ok(value) => value.parse::<usize>()?,
        Err(cause @ std::env::VarError::NotPresent) => {
            tracing::warn!(%cause, "using automatic scanner worker count");
            (processors / 2).max(1)
        }
        Err(cause) => {
            return Err(Error::Invalid(format!(
                "scanner worker configuration: {cause}"
            )));
        }
    };
    if requested == 0 {
        return Err(Error::Invalid(
            "URMA_GIT_SCAN_WORKERS must be positive".into(),
        ));
    }
    let available = available_memory()?;
    let budget = (available / 4).min(4 * 1024 * 1024 * 1024);
    let worker_reserve = 520 * 1024 * 1024;
    let capacity = usize::try_from(budget / worker_reserve)?.max(1);
    Ok(requested.min(capacity).min(objects.max(1)))
}

fn available_memory() -> Result<u64, Error> {
    let text = std::fs::read_to_string("/proc/meminfo")?;
    let line = text
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))
        .ok_or_else(|| Error::Capacity("cannot determine available scanner memory".into()))?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::Capacity("invalid available memory report".into()))?
        .parse::<u64>()?;
    let host = kib
        .checked_mul(1024)
        .ok_or_else(|| Error::Capacity("memory size overflow".into()))?;
    let maximum = match std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        Ok(value) => value,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(%cause, "cgroup memory limit unavailable; using host memory budget");
            return Ok(host);
        }
        Err(cause) => return Err(cause.into()),
    };
    if maximum.trim() == "max" {
        return Ok(host);
    }
    let limit = maximum.trim().parse::<u64>()?;
    let used = std::fs::read_to_string("/sys/fs/cgroup/memory.current")?
        .trim()
        .parse::<u64>()?;
    Ok(host.min(
        limit
            .checked_sub(used)
            .ok_or_else(|| Error::Capacity("cgroup memory exhausted".into()))?,
    ))
}
pub fn legacy_secret_scan() -> bool {
    true
}

pub fn secret_scan_enabled(value: &bool) -> bool {
    *value
}
