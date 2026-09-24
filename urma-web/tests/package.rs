use anyhow::{Context, Result};
use bitcoin::{Txid, hashes::Hash};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use urma_web::{
    config::Limits,
    grammar::{is_entry_mime, validate_mime, validate_path},
    package::{FileEntry, Package, PinnedEntry, Resource},
};

fn vectors() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join("tests/vectors/web")
}

fn manifest() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        vectors().join("manifest.json"),
    )?)?)
}

fn artifact(case: &Value) -> Result<Vec<u8>> {
    let record = &case["record"];
    let bytes = fs::read(vectors().join(record["file"].as_str().context("file")?))?;
    assert_eq!(
        bytes.len() as u64,
        record["bytes"].as_u64().context("bytes")?
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        record["sha256"].as_str().context("sha256")?
    );
    Ok(bytes)
}

fn html() -> Vec<u8> {
    b"<!doctype html><meta charset=utf-8><title>Atelier</title><p>\xc8\x99tire</p>".to_vec()
}

#[test]
fn independent_corpus_decodes_valid_packages_and_re_encodes_them_exactly() -> Result<()> {
    let corpus = manifest()?;
    let mut valid = 0;
    let mut invalid = 0;
    let mut policy = 0;
    for case in corpus["cases"].as_array().context("cases")? {
        let bytes = artifact(case)?;
        let result = Package::decode(&bytes);
        match case["outcome"].as_str().context("outcome")? {
            "valid" => {
                let package = result.with_context(|| case["name"].to_string())?;
                assert_eq!(package.encode()?, bytes, "{}", case["name"]);
                assert!(is_entry_mime(&package.entry()?.mime));
                valid += 1;
            }
            "invalid" => {
                assert!(result.is_err(), "accepted {}", case["name"]);
                invalid += 1;
            }
            "policy" => {
                let package = result.with_context(|| case["name"].to_string())?;
                assert_eq!(package.encode()?, bytes, "{}", case["name"]);
                assert!(
                    Limits::DEFAULT.check(&package).is_err(),
                    "{} is within the default client policy",
                    case["name"]
                );
                policy += 1;
            }
            other => panic!("unknown outcome {other}"),
        }
    }
    assert_eq!((valid, invalid, policy), (7, 31, 5));
    Ok(())
}

#[test]
fn site_package_resolves_declared_paths_only() -> Result<()> {
    let corpus = manifest()?;
    let site = corpus["cases"]
        .as_array()
        .context("cases")?
        .iter()
        .find(|case| case["name"] == "site")
        .context("site case")?;
    let package = Package::decode(&artifact(site)?)?;
    assert_eq!(package.label, "Atelier demo");
    assert_eq!(package.entry()?.path, "index.html");
    assert_eq!(package.entry()?.mime, "text/html;charset=utf-8");
    assert_eq!(package.files.len(), 4);
    assert_eq!(package.pinned.len(), 1);
    let Resource::File(entry) = package.resolve("/") else {
        panic!("root")
    };
    assert_eq!(entry.bytes, html());
    let Resource::File(script) = package.resolve("/app.js") else {
        panic!("script")
    };
    assert_eq!(script.mime, "text/javascript");
    let Resource::Pinned(apk) = package.resolve("/downloads/wire.apk") else {
        panic!("pin")
    };
    assert_eq!(apk.mime, "application/vnd.android.package-archive");
    assert_eq!(
        apk.root_txid.to_string(),
        hex::encode((0x80u8..0xa0).rev().collect::<Vec<u8>>())
    );
    assert_eq!(
        apk.payload_sha256.to_vec(),
        (0xa0u8..0xc0).collect::<Vec<u8>>()
    );
    for undeclared in [
        "/assets/",
        "/missing",
        "index.html",
        "/../index.html",
        "/App.js",
        "/app.js/",
        "//app.js",
        "/app.js?x=1",
    ] {
        assert!(
            matches!(package.resolve(undeclared), Resource::Undeclared),
            "{undeclared}"
        );
    }
    let Resource::File(logo) = package.resolve("/assets/logo.png") else {
        panic!("logo")
    };
    assert_eq!(logo.mime, "image/png");
    Ok(())
}

#[test]
fn build_sorts_hashes_and_rejects_bad_input_and_grammar_is_strict() -> Result<()> {
    let files = vec![
        FileEntry::new("z/index.html", "text/html", b"<p>z</p>".to_vec()),
        FileEntry::new("index.html", "text/html", html()),
        FileEntry::new("a.js", "text/javascript", b"1".to_vec()),
    ];
    let pinned = vec![PinnedEntry {
        path: "dl/x.apk".into(),
        mime: "application/vnd.android.package-archive".into(),
        root_txid: Txid::from_byte_array([1; 32]),
        payload_sha256: [2; 32],
    }];
    let package = Package::build("demo", "index.html", files.clone(), pinned.clone())?;
    let paths: Vec<&str> = package
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, ["a.js", "index.html", "z/index.html"]);
    assert_eq!(package.entry, 1);
    let Resource::File(sub) = package.resolve("/z/") else {
        panic!("directory index")
    };
    assert_eq!(sub.bytes, b"<p>z</p>");
    let decoded = Package::decode(&package.encode()?)?;
    assert_eq!(decoded, package);
    assert!(Package::build("demo", "missing.html", files.clone(), Vec::new()).is_err());
    assert!(Package::build("demo", "a.js", files.clone(), Vec::new()).is_err());
    assert!(
        Package::build(
            "x".repeat(65).as_str(),
            "index.html",
            files.clone(),
            Vec::new()
        )
        .is_err()
    );
    let mut tampered = package.clone();
    tampered.files[0].sha256 = [0; 32];
    assert!(tampered.validate().is_err());
    assert!(tampered.encode().is_err());
    for path in [
        "a",
        "a/b.c",
        "A-Z_0.9~",
        "a/".repeat(31).trim_end_matches('/'),
        &format!("{0}/{0}/{0}/{0}", "x".repeat(255)),
        &"x".repeat(1025),
        "a/".repeat(40).trim_end_matches('/'),
    ] {
        validate_path(path).with_context(|| path.to_string())?;
    }
    for path in [
        "",
        "/a",
        "a/",
        "a//b",
        ".",
        "..",
        "a/../b",
        "a b",
        "a%20b",
        "ș",
        &"x".repeat(65536),
    ] {
        assert!(validate_path(path).is_err(), "{path:?}");
    }
    for mime in [
        "text/html",
        "text/html;charset=utf-8",
        "image/svg+xml",
        "application/vnd.android.package-archive",
        "font/woff2",
    ] {
        validate_mime(mime).with_context(|| mime.to_string())?;
    }
    for mime in [
        "",
        "html",
        "text/",
        "/html",
        "Text/html",
        "text/html; charset=utf-8",
        "text/html;charset=UTF-8",
        "text/html;x=1",
        "text html",
        &format!("{}/x", "a".repeat(254)),
    ] {
        assert!(validate_mime(mime).is_err(), "{mime:?}");
    }
    assert!(
        is_entry_mime("text/html")
            && is_entry_mime("text/html;charset=utf-8")
            && !is_entry_mime("text/plain")
    );
    Ok(())
}
