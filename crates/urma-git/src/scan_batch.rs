use crate::{
    error::Error,
    git,
    inventory::Object,
    review::{self, ScanReport},
};
use regex::bytes::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor, Read, Write},
    path::Path,
    process::{Child, ChildStdout, Stdio},
    sync::atomic::AtomicUsize,
};

pub(crate) struct Batch {
    child: Child,
    output: BufReader<ChildStdout>,
}

impl Batch {
    pub(crate) fn new(repo: &Path, scratch: &Path) -> Result<Self, Error> {
        let stderr: File = tempfile::tempfile_in(scratch)?;
        let mut child = git::command(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| Error::Git("missing batch output pipe".into()))?;
        tracing::trace!(target: "urma_progress", "Started persistent git cat-file --batch");
        Ok(Self {
            child,
            output: BufReader::new(output),
        })
    }

    pub(crate) fn scan(
        &mut self,
        object: &Object,
        rules: &[(&str, Regex)],
        findings: &AtomicUsize,
    ) -> Result<ScanReport, Error> {
        let input = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| Error::Git("closed batch input".into()))?;
        writeln!(input, "{}", object.oid)?;
        input.flush()?;
        let mut line = Vec::new();
        (&mut self.output).take(192).read_until(b'\n', &mut line)?;
        let expected = format!("{} {} {}\n", object.oid, object.kind, object.size);
        if line != expected.as_bytes() {
            return Err(Error::Invalid(
                "batch object identity, type or size differs from inventory".into(),
            ));
        }
        let mut payload = (&mut self.output).take(object.size);
        let mut prefix = vec![0u8; usize::try_from(object.size.min(256))?];
        payload.read_exact(&mut prefix)?;
        if object.kind == "blob" {
            review::reject_lfs_prefix(&prefix)?;
        }
        let mut report = ScanReport {
            repository_name: String::new(),
            scanner: String::new(),
            complete: false,
            objects: 0,
            bytes: 0,
            findings: Vec::new(),
        };
        review::scan_reader(
            &mut Cursor::new(prefix).chain(&mut payload),
            &object.oid,
            &mut report,
            rules,
            findings,
        )?;
        if payload.limit() != 0 || report.bytes != object.size {
            return Err(Error::Invalid("truncated batch object content".into()));
        }
        let mut end = [0u8; 1];
        self.output.read_exact(&mut end)?;
        if end != *b"\n" {
            return Err(Error::Invalid("invalid batch object delimiter".into()));
        }
        report.objects = 1;
        report.complete = true;
        Ok(report)
    }

    pub(crate) fn finish(mut self) -> Result<(), Error> {
        match self.complete() {
            Ok(()) => Ok(()),
            Err(cause) => {
                tracing::warn!(%cause, "closing failed Git batch");
                self.abort()?;
                Err(cause)
            }
        }
    }

    fn complete(&mut self) -> Result<(), Error> {
        let input = self
            .child
            .stdin
            .take()
            .ok_or_else(|| Error::Git("closed batch input".into()))?;
        drop(input);
        let mut extra = [0u8; 1];
        if self.output.read(&mut extra)? != 0 {
            return Err(Error::Invalid("unexpected trailing batch output".into()));
        }
        let status = self.child.wait()?;
        if !status.success() {
            return Err(Error::Git(format!(
                "persistent cat-file exited with {status}"
            )));
        }
        Ok(())
    }
    pub(crate) fn abort(mut self) -> Result<(), Error> {
        match self.child.kill() {
            Ok(()) => (),
            Err(cause) => tracing::warn!(%cause, "stopping failed Git batch worker"),
        }
        let status = self.child.wait()?;
        tracing::debug!(%status, "Git batch worker reaped");
        Ok(())
    }
}
