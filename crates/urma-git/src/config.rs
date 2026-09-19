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
            Ok(urma::config::output_parent(path).to_path_buf())
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
