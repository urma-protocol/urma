use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
};
use urma_git::{checkout, inventory::Limits, review, snapshot};

fn git(path: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Public Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Public Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn head_only_both_formats_editable_safe_checkout_and_review() -> Result<()> {
    let lab = tempfile::tempdir()?;
    for format in ["sha1", "sha256"] {
        let source = lab.path().join(format);
        fs::create_dir(&source)?;
        git(
            &source,
            &[
                "init",
                &format!("--object-format={format}"),
                "--initial-branch=main",
            ],
        )?;
        fs::write(source.join("old.txt"), b"ancestor only\n")?;
        git(&source, &["add", "."])?;
        git(&source, &["commit", "-m", "original"])?;
        fs::remove_file(source.join("old.txt"))?;
        fs::create_dir(source.join("directory"))?;
        fs::write(source.join("directory/file.bin"), b"\0binary\xff\r\n")?;
        fs::write(source.join("run.sh"), b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(source.join("run.sh"), fs::Permissions::from_mode(0o755))?;
        fs::write(
            source.join(".gitattributes"),
            b"* text eol=crlf filter=hostile\n",
        )?;
        git(&source, &["config", "filter.hostile.smudge", "false"])?;
        symlink("directory/file.bin", source.join("link"))?;
        git(&source, &["add", "-A"])?;
        git(&source, &["commit", "-m", "current snapshot"])?;
        let head = git(&source, &["rev-parse", "HEAD"])?;
        fs::write(source.join("untracked.secret"), b"not collected")?;
        let artifact = lab.path().join(format!("{format}-snapshot"));
        let report = snapshot::prepare(&source, &artifact, &Limits::default())?;
        ensure!(
            report
                .inventory
                .objects
                .iter()
                .filter(|object| object.kind == "commit")
                .count()
                == 1
        );
        ensure!(report.scan.complete && report.scan.findings.is_empty());
        ensure!(report.descriptor.repository_name == format);
        ensure!(report.scan.repository_name == format);
        let named = snapshot::prepare_named(
            &source,
            &lab.path().join(format!("{format}-named")),
            &Limits::default(),
            "public-project",
        )?;
        ensure!(named.descriptor.repository_name == "public-project");
        ensure!(named.payload_sha256 != report.payload_sha256);
        let flagged = snapshot::prepare_named(
            &source,
            &lab.path().join(format!("{format}-scan-name")),
            &Limits::default(),
            "ghp_ABCDEFGHIJKLMNOPQRST",
        )?;
        ensure!(
            flagged
                .scan
                .findings
                .iter()
                .any(|finding| finding.object == "repository-name")
        );
        review::record(&artifact, "frozen-plan-hash", &[])?;
        review::require(&artifact, "frozen-plan-hash")?;
        ensure!(review::require(&artifact, "changed-plan").is_err());
        let clone = lab.path().join(format!("{format}-clone"));
        checkout::install(&artifact.join("object.bin"), &clone, &Limits::default())?;
        ensure!(git(&clone, &["rev-parse", "HEAD"])? == head);
        ensure!(
            checkout::install(&artifact.join("object.bin"), &clone, &Limits::default()).is_err()
        );
        ensure!(git(&clone, &["rev-list", "--count", "HEAD"])?.trim() == "1");
        ensure!(git(&clone, &["status", "--porcelain"])?.is_empty());
        ensure!(fs::read_link(clone.join("link"))? == Path::new("directory/file.bin"));
        ensure!(fs::read(clone.join("directory/file.bin"))? == b"\0binary\xff\n");
        ensure!(!clone.join("untracked.secret").exists());
        fs::write(clone.join("new.txt"), b"editable\n")?;
        git(&clone, &["add", "new.txt"])?;
        git(&clone, &["commit", "-m", "edit after recovery"])?;
        ensure!(git(&clone, &["rev-list", "--count", "HEAD"])?.trim() == "2");
        fs::write(
            source.join("lfs"),
            b"version https://git-lfs.github.com/spec/v1\nmalformed\n",
        )?;
        git(&source, &["add", "lfs"])?;
        git(&source, &["commit", "-m", "unsupported LFS"])?;
        ensure!(
            snapshot::prepare(
                &source,
                &lab.path().join(format!("{format}-lfs")),
                &Limits::default()
            )
            .is_err()
        );
    }
    Ok(())
}
