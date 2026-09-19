use crate::{config, descriptor, error::Error, inventory::Inventory, scan_pool};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
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
    pub repository_name: String,
    pub scanner: String,
    pub complete: bool,
    pub objects: usize,
    pub bytes: u64,
    pub findings: Vec<Finding>,
}

pub(crate) fn rules() -> Result<Vec<(&'static str, Regex)>, Error> {
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

fn read_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut count = 0;
    while count < buffer.len() {
        let received = reader.read(&mut buffer[count..])?;
        if received == 0 {
            break;
        }
        count += received;
    }
    Ok(count)
}

pub(crate) fn scan_reader(
    reader: &mut impl Read,
    object: &str,
    report: &mut ScanReport,
    rules: &[(&str, Regex)],
    findings: &AtomicUsize,
) -> Result<(), Error> {
    let mut buffer = vec![0_u8; 65536 + 512];
    let mut carry = 0;
    let mut offset = 0_u64;
    let mut found = BTreeSet::new();
    loop {
        let count = read_chunk(reader, &mut buffer[carry..65536 + carry])?;
        if count == 0 {
            break;
        }
        let used = carry + count;
        for (name, regex) in rules {
            for matched in regex.find_iter(&buffer[..used]) {
                let position = offset + u64::try_from(matched.start())?;
                if !found.insert((name.to_string(), position)) {
                    continue;
                }
                if findings.fetch_add(1, Ordering::Relaxed) >= config::SCAN_FINDINGS_LIMIT {
                    return Err(Error::Capacity(
                        "scanner finding limit exceeded; review content before retrying".into(),
                    ));
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
    public: &descriptor::Descriptor,
    scratch: &Path,
) -> Result<ScanReport, Error> {
    let mut report = ScanReport {
        repository_name: public.repository_name.clone(),
        scanner: "urma-git-patterns-v2".into(),
        complete: false,
        objects: 0,
        bytes: 0,
        findings: Vec::new(),
    };
    let rules = rules()?;
    let findings = AtomicUsize::new(0);
    scan_reader(
        &mut public.branch.as_slice(),
        "branch",
        &mut report,
        &rules,
        &findings,
    )?;
    scan_reader(
        &mut public.repository_name.as_bytes(),
        "repository-name",
        &mut report,
        &rules,
        &findings,
    )?;
    scan_pool::scan(repo, inventory, scratch, &mut report, &findings)?;
    report.complete = true;
    Ok(report)
}

pub fn reject_lfs(input: &mut (impl Read + std::io::Seek)) -> Result<(), Error> {
    let mut prefix = [0_u8; 256];
    let count = input.read(&mut prefix)?;
    input.rewind()?;
    reject_lfs_prefix(&prefix[..count])
}

pub(crate) fn reject_lfs_prefix(prefix: &[u8]) -> Result<(), Error> {
    for known in [
        b"version https://git-lfs.github.com/spec/".as_slice(),
        b"version https://hawser.github.com/spec/",
        b"version https://git-media.io/",
    ] {
        if prefix.starts_with(known) {
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
