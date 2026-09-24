use crate::{
    config::mime_for_extension,
    error::WebError,
    package::{FileEntry, Package, PinnedEntry},
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub struct PackRequest<'a> {
    pub root: &'a Path,
    pub entry: &'a str,
    pub label: &'a str,
    pub mimes: &'a BTreeMap<String, String>,
    pub pinned: Vec<PinnedEntry>,
    pub max_file_bytes: usize,
}

fn mime_for(relative: &str, overrides: &BTreeMap<String, String>) -> Result<String, WebError> {
    let Some(explicit) = overrides.get(relative) else {
        let Some(name) = relative.rsplit('/').next() else {
            return Err(WebError::Invalid(format!("empty path {relative:?}")));
        };
        let Some(split) = name.rsplit_once('.') else {
            return Err(WebError::Missing(format!(
                "{relative:?} has no extension; pass --mime {relative}=type/subtype"
            )));
        };
        let extension = split.1;
        let Some(by_extension) = overrides.get(extension) else {
            return Ok(mime_for_extension(extension)?.to_owned());
        };
        return Ok(by_extension.clone());
    };
    Ok(explicit.clone())
}

fn collect(directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), WebError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        entries.push(entry?.path());
    }
    entries.sort();
    for path in entries {
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            collect(&path, found)?;
        } else if kind.is_file() {
            found.push(path);
        } else {
            return Err(WebError::Invalid(format!(
                "{} is neither a regular file nor a directory",
                path.display()
            )));
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String, WebError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|cause| WebError::Invalid(format!("{}: {cause}", path.display())))?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let Some(text) = component.as_os_str().to_str() else {
            return Err(WebError::Invalid(format!(
                "{} is not UTF-8",
                path.display()
            )));
        };
        segments.push(text.to_owned());
    }
    Ok(segments.join("/"))
}

pub fn pack_directory(request: PackRequest<'_>) -> Result<Package, WebError> {
    let mut paths = Vec::new();
    collect(request.root, &mut paths)?;
    let mut files = Vec::new();
    for path in paths {
        let relative = relative_path(request.root, &path)?;
        let mime = mime_for(&relative, request.mimes)?;
        let bytes = urma_io::read_bounded(&path, request.max_file_bytes)?;
        files.push(FileEntry::new(&relative, &mime, bytes));
    }
    Package::build(request.label, request.entry, files, request.pinned)
}
