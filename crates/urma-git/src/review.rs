use crate::{descriptor, error::Error, git, inventory::Inventory};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub object: String,
    pub rule: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanReport {
    pub scanner: String,
    pub complete: bool,
    pub objects: usize,
    pub bytes: u64,
    pub findings: Vec<Finding>,
}

fn rules() -> Result<Vec<(&'static str, Regex)>, Error> {
    Ok(vec![
        (
            "private-key",
            Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")?,
        ),
        (
            "github-token",
            Regex::new(r"(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})")?,
        ),
        ("aws-access-key", Regex::new(r"(?:AKIA|ASIA)[A-Z0-9]{16}")?),
        (
            "credential-assignment",
            Regex::new(
                r#"(?i)(?:password|secret|api_key|access_token)[\x20\t]{0,32}[:=][\x20\t]{0,32}[\"']?[A-Za-z0-9/+=_-]{16,255}"#,
            )?,
        ),
    ])
}

fn scan_reader(reader: &mut impl Read, object: &str, report: &mut ScanReport) -> Result<(), Error> {
    let rules = rules()?;
    let mut buffer = vec![0_u8; 65536 + 512];
    let mut carry = 0;
    let mut offset = 0_u64;
    let mut found = BTreeSet::new();
    loop {
        let count = reader.read(&mut buffer[carry..65536 + carry])?;
        if count == 0 {
            break;
        }
        let used = carry + count;
        for (name, regex) in &rules {
            for matched in regex.find_iter(&buffer[..used]) {
                let position = offset + u64::try_from(matched.start())?;
                if !found.insert((name.to_string(), position)) {
                    continue;
                }
                let id = hex::encode(Sha256::digest(format!("{object}:{name}:{position}")));
                report.findings.push(Finding {
                    id,
                    object: object.into(),
                    rule: (*name).into(),
                    offset: position,
                });
            }
        }
        report.bytes = report
            .bytes
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| Error::Capacity("scanner bytes".into()))?;
        let retained = used.min(512);
        buffer.copy_within(used - retained..used, 0);
        offset += u64::try_from(used - retained)?;
        carry = retained;
    }
    Ok(())
}

pub fn scan(
    repo: &Path,
    inventory: &Inventory,
    mut branch: &[u8],
    scratch: &Path,
) -> Result<ScanReport, Error> {
    let mut report = ScanReport {
        scanner: "urma-git-patterns-v1".into(),
        complete: false,
        objects: 0,
        bytes: 0,
        findings: Vec::new(),
    };
    scan_reader(&mut branch, "branch", &mut report)?;
    for object in &inventory.objects {
        let path = scratch.join("scan-object");
        git::run(
            repo,
            &[
                "cat-file".as_ref(),
                object.kind.as_ref(),
                object.oid.as_ref(),
            ],
            Path::new("/dev/null"),
            &path,
        )?;
        let mut file = File::open(&path)?;
        if file.metadata()?.len() != object.size {
            return Err(Error::Invalid("object changed while scanning".into()));
        }
        if object.kind == "blob" {
            reject_lfs(&mut file)?;
        }
        scan_reader(&mut file, &object.oid, &mut report)?;
        report.objects += 1;
        std::fs::remove_file(path)?;
    }
    report.complete = true;
    Ok(report)
}

pub fn reject_lfs(input: &mut (impl Read + std::io::Seek)) -> Result<(), Error> {
    let mut prefix = [0_u8; 256];
    let count = input.read(&mut prefix)?;
    input.rewind()?;
    for known in [
        b"version https://git-lfs.github.com/spec/".as_slice(),
        b"version https://hawser.github.com/spec/",
        b"version https://git-media.io/",
    ] {
        if prefix[..count].starts_with(known) {
            return Err(Error::Invalid(
                "Git LFS pointer or malformed known LFS header".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    plan_hash: String,
    artifact_sha256: String,
    scan_sha256: String,
    classified_public_test_material: BTreeSet<String>,
}

pub fn record(snapshot: &Path, plan_hash: &str, classifications: &[String]) -> Result<(), Error> {
    let scan_path = snapshot.join("scan.json");
    let scan: ScanReport = serde_json::from_reader(File::open(&scan_path)?)?;
    let classified = classifications.iter().cloned().collect::<BTreeSet<_>>();
    let findings = scan
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    if !scan.complete || classified != findings {
        return Err(Error::ReviewRequired("classify each finding explicitly as public test material, or prepare a new clean commit".into()));
    }
    let receipt = Receipt {
        schema: 1,
        plan_hash: plan_hash.into(),
        artifact_sha256: hex::encode(descriptor::digest(&mut File::open(
            snapshot.join("object.bin"),
        )?)?),
        scan_sha256: hex::encode(descriptor::digest(&mut File::open(scan_path)?)?),
        classified_public_test_material: classified,
    };
    let path = snapshot.join("review.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    file.sync_all()?;
    Ok(())
}

pub fn require(snapshot: &Path, plan_hash: &str) -> Result<(), Error> {
    let receipt: Receipt = serde_json::from_reader(File::open(snapshot.join("review.json"))?)?;
    let artifact = hex::encode(descriptor::digest(&mut File::open(
        snapshot.join("object.bin"),
    )?)?);
    let scan_hash = hex::encode(descriptor::digest(&mut File::open(
        snapshot.join("scan.json"),
    )?)?);
    let scan: ScanReport = serde_json::from_reader(File::open(snapshot.join("scan.json"))?)?;
    let findings = scan
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    if receipt.schema != 1
        || receipt.plan_hash != plan_hash
        || receipt.artifact_sha256 != artifact
        || receipt.scan_sha256 != scan_hash
        || !scan.complete
        || receipt.classified_public_test_material != findings
    {
        return Err(Error::ReviewRequired(
            "missing, incomplete or stale review".into(),
        ));
    }
    Ok(())
}
