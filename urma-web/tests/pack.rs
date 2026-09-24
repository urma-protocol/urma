use anyhow::Result;
use std::{collections::BTreeMap, fs, path::Path};
use urma_web::{
    pack::{PackRequest, pack_directory},
    package::{Package, Resource},
};

#[test]
fn directories_pack_into_sorted_packages_with_declared_mimes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("site");
    fs::create_dir_all(root.join("sub"))?;
    fs::write(root.join("index.html"), "<!doctype html><p>hi</p>")?;
    fs::write(root.join("style.css"), "body{}")?;
    fs::write(root.join("sub/app.js"), "1")?;
    fs::write(root.join("sub/data.json"), "{}")?;
    fs::write(root.join("README"), "notes")?;
    let mut mimes = BTreeMap::new();
    fn request<'a>(root: &'a Path, mimes: &'a BTreeMap<String, String>) -> PackRequest<'a> {
        PackRequest {
            root,
            entry: "index.html",
            label: "packed",
            mimes,
            pinned: Vec::new(),
            max_file_bytes: 1 << 20,
        }
    }
    assert!(pack_directory(request(&root, &mimes)).is_err());
    mimes.insert("README".into(), "text/plain".into());
    let package = pack_directory(request(&root, &mimes))?;
    let listing: Vec<(&str, &str)> = package
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.mime.as_str()))
        .collect();
    assert_eq!(
        listing,
        [
            ("README", "text/plain"),
            ("index.html", "text/html"),
            ("style.css", "text/css"),
            ("sub/app.js", "text/javascript"),
            ("sub/data.json", "application/json"),
        ]
    );
    assert_eq!(package.entry()?.path, "index.html");
    let decoded = Package::decode(&package.encode()?)?;
    assert_eq!(decoded, package);
    let Resource::File(data) = decoded.resolve("/sub/data.json") else {
        panic!("data")
    };
    assert_eq!(data.bytes, b"{}");
    mimes.insert("js".into(), "application/javascript".into());
    let overridden = pack_directory(request(&root, &mimes))?;
    assert_eq!(overridden.files[3].mime, "application/javascript");
    fs::write(root.join("weird.xyz"), "?")?;
    assert!(pack_directory(request(&root, &mimes)).is_err());
    mimes.insert("xyz".into(), "application/octet-stream".into());
    pack_directory(request(&root, &mimes))?;
    std::os::unix::fs::symlink(root.join("index.html"), root.join("link.html"))?;
    assert!(pack_directory(request(&root, &mimes)).is_err());
    Ok(())
}
