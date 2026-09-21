use std::path::Path;

pub fn output_parent(path: &Path) -> &Path {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent,
        None => Path::new("."),
    }
}
