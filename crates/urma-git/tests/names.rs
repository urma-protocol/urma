use anyhow::{Result, ensure};
use std::{io::Cursor, path::PathBuf};
use urma_git::{
    config::{self, CloneDestination},
    descriptor::{self, Descriptor},
};

fn descriptor(name: &str) -> Descriptor {
    Descriptor {
        repository_name: name.into(),
        object_format: 1,
        head: vec![7; 20],
        branch: b"refs/heads/main".to_vec(),
        pack_length: 32,
        pack_sha256: [8; 32],
        first_root: [0; 32],
        previous_root: [0; 32],
    }
}

fn payload(value: &Descriptor) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes)?;
    bytes.extend_from_slice(&[0; 32]);
    Ok(bytes)
}

#[test]
fn named_descriptor_is_bounded_bound_and_distinct_from_unnamed_profile() -> Result<()> {
    let value = descriptor("hello-world");
    let bytes = payload(&value)?;
    ensure!(bytes[1] == 1);
    let offset = 108 + 20 + value.branch.len();
    ensure!(&bytes[offset..offset + 2] == 11_u16.to_le_bytes());
    let decoded = Descriptor::decode(&mut Cursor::new(&bytes))?;
    ensure!(decoded.repository_name == "hello-world");
    decoded.require_profile(*b"URMAGIT1")?;
    ensure!(decoded.require_profile(*b"URMAGIT0").is_err());
    let renamed = payload(&descriptor("hello-other"))?;
    ensure!(
        descriptor::digest(&mut bytes.as_slice())? != descriptor::digest(&mut renamed.as_slice())?
    );
    let mut oversized = bytes.clone();
    oversized[offset..offset + 2].copy_from_slice(&101_u16.to_le_bytes());
    ensure!(Descriptor::decode(&mut Cursor::new(oversized)).is_err());
    let mut unsafe_name = bytes.clone();
    unsafe_name[offset + 2] = b'/';
    ensure!(Descriptor::decode(&mut Cursor::new(unsafe_name)).is_err());
    let mut empty_name = bytes.clone();
    empty_name[offset..offset + 2].copy_from_slice(&0_u16.to_le_bytes());
    ensure!(Descriptor::decode(&mut Cursor::new(empty_name)).is_err());
    let mut unknown_revision = bytes.clone();
    unknown_revision[1] = 2;
    ensure!(Descriptor::decode(&mut Cursor::new(unknown_revision)).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    ensure!(Descriptor::decode(&mut Cursor::new(trailing)).is_err());
    ensure!(Descriptor::decode(&mut Cursor::new(&bytes[..offset + 1])).is_err());
    let legacy = Descriptor::decode(&mut Cursor::new(payload(&descriptor(""))?))?;
    ensure!(legacy.repository_name.is_empty());
    legacy.require_profile(*b"URMAGIT0")?;
    ensure!(legacy.require_profile(*b"URMAGIT1").is_err());
    Ok(())
}

#[test]
fn names_reject_paths_and_choose_safe_defaults_or_explicit_destination() -> Result<()> {
    for bad in [
        "",
        ".",
        "..",
        ".git",
        "../escape",
        "a/b",
        "a\\b",
        "C:drive",
        "a\n",
        "a\0",
        "a b",
        "-option",
        "name.",
        "CON",
        "nul.txt",
        "COM1.foo",
        "éclair",
    ] {
        ensure!(descriptor::validate_name(bad).is_err(), "accepted {bad:?}");
    }
    ensure!(descriptor::validate_name(&"a".repeat(101)).is_err());
    descriptor::validate_name(&"a".repeat(100))?;
    descriptor::validate_name("Hello_world.v1")?;
    let root = "a84ed0fe81ac9addead54fe04b3909165cdecd3b7f177251eeb416d4bcb4877f".parse()?;
    let named = descriptor("hello-world");
    ensure!(
        config::destination(CloneDestination(None), &named, root)?
            .file_name()
            .unwrap()
            == "hello-world"
    );
    ensure!(
        config::destination(
            CloneDestination(Some(PathBuf::from("custom"))),
            &named,
            root
        )?
        .file_name()
        .unwrap()
            == "custom"
    );
    ensure!(
        config::destination(CloneDestination(None), &descriptor(""), root)?
            .file_name()
            .unwrap()
            == "urma-a84ed0fe81ac"
    );
    let lab = tempfile::tempdir()?;
    ensure!(config::staging_parent(&CloneDestination(Some(lab.path().to_owned()))).is_err());
    std::os::unix::fs::symlink(lab.path().join("absent"), lab.path().join("link"))?;
    ensure!(config::staging_parent(&CloneDestination(Some(lab.path().join("link")))).is_err());
    Ok(())
}

#[test]
fn canonical_profiles_preserve_descriptor_bytes_and_locator_format() -> Result<()> {
    use urma_chain::observation::Chain;
    use urma_git::proofs::Locator;
    use urma_profiles::git::GitProfile;
    for (name, profile, revision) in [("", *b"URMAGIT0", 0), ("news", *b"URMAGIT1", 1)] {
        let value = descriptor(name);
        let bytes = payload(&value)?;
        ensure!(value.profile() == profile);
        ensure!(GitProfile::for_name(name).identifier() == profile);
        ensure!(bytes[1] == revision);
        let mut expected = vec![1, revision];
        expected.extend_from_slice(&15_u16.to_le_bytes());
        expected.extend_from_slice(&32_u64.to_le_bytes());
        expected.extend_from_slice(&[8; 32]);
        expected.extend_from_slice(&[0; 64]);
        expected.extend_from_slice(&[7; 20]);
        expected.extend_from_slice(b"refs/heads/main");
        if revision == 1 {
            expected.extend_from_slice(&4_u16.to_le_bytes());
            expected.extend_from_slice(b"news");
        }
        expected.extend_from_slice(&[0; 32]);
        ensure!(bytes == expected);
        ensure!(payload(&Descriptor::decode(&mut Cursor::new(bytes))?)? == expected);
    }
    let locator = Locator {
        schema: 1,
        chain: Chain::BitcoinRegtest,
        genesis: Chain::BitcoinRegtest.genesis()?.0.to_string(),
        root: "a84ed0fe81ac9addead54fe04b3909165cdecd3b7f177251eeb416d4bcb4877f".parse()?,
    };
    let encoded = serde_json::to_value(&locator)?;
    ensure!(encoded.as_object().unwrap().len() == 4);
    let decoded: Locator = serde_json::from_value(encoded)?;
    ensure!(decoded.snapshot()?.root == locator.root);
    ensure!(decoded.snapshot()?.chain == Chain::BitcoinRegtest.genesis()?);
    let mut invalid = decoded;
    invalid.genesis = "wrong".into();
    ensure!(invalid.snapshot().is_err());
    Ok(())
}
