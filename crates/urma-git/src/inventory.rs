use crate::{config, error::Error, git};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_pack_bytes: u64,
    pub max_objects: usize,
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_expanded_bytes: u64,
    pub max_checkout_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pack_bytes: config::pack_capacity(),
            max_objects: 1_000_000,
            max_paths: 1_000_000,
            max_depth: 256,
            max_expanded_bytes: 2 * 1024 * 1024 * 1024,
            max_checkout_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path_hex: String,
    pub display: String,
    pub mode: u32,
    pub oid: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub oid: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub objects: Vec<Object>,
    pub entries: Vec<Entry>,
    pub expanded_bytes: u64,
    pub checkout_bytes: u64,
    pub has_parents: bool,
}

pub fn safe_path(path: &[u8], limits: &Limits) -> Result<(), Error> {
    let parts = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    if parts.len() > limits.max_depth {
        return Err(Error::Capacity("tree nesting".into()));
    }
    for part in parts {
        let lower = part.to_ascii_lowercase();
        if part.is_empty()
            || part == b"."
            || part == b".."
            || part.contains(&0)
            || part.contains(&b'\\')
            || lower == b".git"
            || lower.starts_with(b".git:")
            || lower.starts_with(b"git~1")
            || lower.ends_with(b" ")
            || lower.ends_with(b".")
        {
            return Err(Error::Invalid("unsafe or unrepresentable tree path".into()));
        }
    }
    Ok(())
}

fn parse_entry(bytes: &[u8], limits: &Limits) -> Result<Entry, Error> {
    let separator = bytes
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| Error::Invalid("tree entry header".into()))?;
    let header = String::from_utf8(bytes[..separator].to_vec())?;
    let fields = header.split(' ').collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err(Error::Invalid("tree entry fields".into()));
    }
    let mode = u32::from_str_radix(fields[0], 8)?;
    if mode == 0o160000 {
        return Err(Error::Invalid(
            "Git submodule gitlink is unsupported".into(),
        ));
    }
    let expected = match mode {
        0o40000 => "tree",
        0o100644 | 0o100755 | 0o120000 => "blob",
        value => return Err(Error::Invalid(format!("tree mode {value:o}"))),
    };
    if fields[1] != expected {
        return Err(Error::Invalid("tree object type".into()));
    }
    let path = &bytes[separator + 1..];
    safe_path(path, limits)?;
    Ok(Entry {
        path_hex: hex::encode(path),
        display: escaped_path(path),
        mode,
        oid: fields[2].into(),
        size: 0,
    })
}

pub fn inspect(repo: &Path, head: &str, limits: &Limits) -> Result<Inventory, Error> {
    let commit = git::output(
        repo,
        &["cat-file", "commit", head],
        limits.max_expanded_bytes,
    )?;
    let tree = commit
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| line.strip_prefix(b"tree "))
        .ok_or_else(|| Error::Invalid("commit root tree".into()))?;
    let root = String::from_utf8(tree.to_vec())?;
    let has_parents = commit
        .split(|byte| *byte == b'\n')
        .take_while(|line| !line.is_empty())
        .any(|line| line.starts_with(b"parent "));
    let output = git::output(
        repo,
        &["ls-tree", "-r", "-t", "-z", "--full-tree", head],
        256 * 1024 * 1024,
    )?;
    let mut entries = Vec::new();
    let mut ids = BTreeSet::from([head.to_owned(), root]);
    for row in output
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
    {
        if entries.len() >= limits.max_paths {
            return Err(Error::Capacity("tree paths".into()));
        }
        let entry = parse_entry(row, limits)?;
        ids.insert(entry.oid.clone());
        entries.push(entry);
    }
    if ids.len() > limits.max_objects {
        return Err(Error::Capacity("Git objects".into()));
    }
    let objects = inspect_objects(repo, &ids, head, limits)?;
    let expanded_bytes = objects.iter().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.size)
            .ok_or_else(|| Error::Capacity("expanded bytes overflow".into()))
    })?;
    let sizes = objects
        .iter()
        .map(|object| (object.oid.clone(), object.size))
        .collect::<BTreeMap<_, _>>();
    let mut checkout_bytes = 0_u64;
    for entry in &mut entries {
        entry.size = *sizes
            .get(&entry.oid)
            .ok_or_else(|| Error::Invalid("missing object".into()))?;
        if entry.mode != 0o40000 {
            checkout_bytes = checkout_bytes
                .checked_add(entry.size)
                .ok_or_else(|| Error::Capacity("checkout bytes overflow".into()))?;
        }
    }
    if expanded_bytes > limits.max_expanded_bytes || checkout_bytes > limits.max_checkout_bytes {
        return Err(Error::Capacity("expanded object or checkout bytes".into()));
    }
    Ok(Inventory {
        objects,
        entries,
        expanded_bytes,
        checkout_bytes,
        has_parents,
    })
}

fn inspect_objects(
    repo: &Path,
    ids: &BTreeSet<String>,
    head: &str,
    limits: &Limits,
) -> Result<Vec<Object>, Error> {
    let mut objects = Vec::new();
    let mut total = 0_u64;
    for oid in ids {
        if objects.len().is_multiple_of(128) {
            tracing::debug!(target: "urma_progress", inspected = objects.len(), total = ids.len(), "Inspecting Git objects");
        }
        let kind = String::from_utf8(git::output(repo, &["cat-file", "-t", oid], 32)?)?
            .trim()
            .to_owned();
        if (oid == head && kind != "commit") || (oid != head && kind != "tree" && kind != "blob") {
            return Err(Error::Invalid("HEAD-only object closure".into()));
        }
        let size = String::from_utf8(git::output(repo, &["cat-file", "-s", oid], 32)?)?
            .trim()
            .parse::<u64>()?;
        total = total
            .checked_add(size)
            .ok_or_else(|| Error::Capacity("expanded bytes overflow".into()))?;
        if total > limits.max_expanded_bytes {
            return Err(Error::Capacity("expanded object bytes".into()));
        }
        objects.push(Object {
            oid: oid.clone(),
            kind,
            size,
        });
    }
    Ok(objects)
}

fn escaped_path(path: &[u8]) -> String {
    let mut output = String::new();
    for byte in path {
        for escaped in std::ascii::escape_default(*byte) {
            output.push(char::from(escaped));
        }
    }
    output
}
