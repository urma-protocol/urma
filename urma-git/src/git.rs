use crate::{config, error::Error};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};

pub(crate) fn timed<T>(
    phase: &str,
    operation: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    tracing::info!(target: "urma_ui", phase);
    tracing::info!(target: "urma_progress", phase, "Stage started");
    let started = Instant::now();
    let result = operation();
    match result {
        Ok(value) => {
            tracing::info!(target: "urma_stage", "{phase}: {:.2}s (complete)", started.elapsed().as_secs_f64());
            Ok(value)
        }
        Err(cause) => {
            tracing::error!(target: "urma_stage", %cause, "{phase}: {:.2}s (failed)", started.elapsed().as_secs_f64());
            Err(cause)
        }
    }
}

pub fn command(repo: &Path) -> Command {
    let mut command = Command::new("/usr/bin/prlimit");
    command
        .args(["--as=536870912", "--cpu=1800"])
        .arg(format!("--fsize={}", config::worker_file_capacity()))
        .args(["--", "/usr/bin/git"]);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "pack.threads=1",
            "-c",
            "pack.windowMemory=64m",
            "-c",
            "core.deltaBaseCacheLimit=64m",
            "-c",
            "core.packedGitWindowSize=32m",
            "-c",
            "core.packedGitLimit=128m",
            "-c",
            "core.bigFileThreshold=16m",
        ]);
    command
}

pub fn run(repo: &Path, args: &[&OsStr], input: &Path, output: &Path) -> Result<(), Error> {
    let mut stderr = tempfile::tempfile_in(
        output
            .parent()
            .ok_or_else(|| Error::Invalid("worker output parent".into()))?,
    )?;
    trace_command(args)?;
    let status = command(repo)
        .args(args)
        .stdin(File::open(input)?)
        .stdout(File::create(output)?)
        .stderr(stderr.try_clone()?)
        .status()?;
    if !status.success() {
        let mut message = String::new();
        stderr.rewind()?;
        stderr.take(4096).read_to_string(&mut message)?;
        return Err(Error::Git(format!("{status}: {}", message.escape_debug())));
    }
    Ok(())
}

pub fn output(repo: &Path, args: &[&str], limit: u64) -> Result<Vec<u8>, Error> {
    let args = args.iter().map(OsStr::new).collect::<Vec<_>>();
    output_os(repo, &args, limit)
}

fn output_os(repo: &Path, args: &[&OsStr], limit: u64) -> Result<Vec<u8>, Error> {
    let mut stdout = tempfile::tempfile_in(repo)?;
    let mut stderr = tempfile::tempfile_in(repo)?;
    trace_command(args)?;
    let status = command(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .status()?;
    if !status.success() {
        let mut message = String::new();
        stderr.rewind()?;
        stderr.take(4096).read_to_string(&mut message)?;
        return Err(Error::Git(format!("{status}: {}", message.escape_debug())));
    }
    if stdout.metadata()?.len() > limit.min(64 * 1024 * 1024) {
        return Err(Error::Capacity("Git worker output".into()));
    }
    stdout.seek(SeekFrom::Start(0))?;
    let mut result = Vec::new();
    stdout.read_to_end(&mut result)?;
    Ok(result)
}

pub fn raw_ref(repo: &Path, reference: &[u8]) -> Result<(), Error> {
    use std::os::unix::ffi::OsStringExt;
    let name = OsString::from_vec(reference.to_vec());
    let status = command(repo)
        .args([OsStr::new("check-ref-format"), &name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(Error::Invalid("branch ref name".into()));
    }
    Ok(())
}

pub fn initialize(path: &Path, format: &str) -> Result<(), Error> {
    std::fs::create_dir(path)?;
    let argument = format!("--object-format={format}");
    output(path, &["init", "--template=", &argument, "."], 4096)?;
    for (key, value) in [
        ("core.autocrlf", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.protectHFS", "true"),
        ("core.protectNTFS", "true"),
    ] {
        output(path, &["config", "--local", key, value], 4096)?;
    }
    std::fs::create_dir_all(path.join(".git/info"))?;
    let mut attributes = File::create(path.join(".git/info/attributes"))?;
    attributes.write_all(b"* -text -eol -ident -filter -working-tree-encoding\n")?;
    Ok(())
}

pub fn branch_head(repo: &Path, branch: &[u8]) -> Result<String, Error> {
    use std::os::unix::ffi::OsStringExt;
    let mut revision = branch.to_vec();
    revision.extend_from_slice(b"^{commit}");
    let revision = OsString::from_vec(revision);
    let bytes = output_os(
        repo,
        &[
            "rev-parse".as_ref(),
            "--verify".as_ref(),
            revision.as_os_str(),
        ],
        128,
    )?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn trace_command(args: &[&OsStr]) -> Result<(), Error> {
    let operation = args
        .first()
        .ok_or_else(|| Error::Invalid("empty Git command".into()))?
        .to_str()
        .ok_or_else(|| Error::Invalid("non-UTF8 Git command name".into()))?;
    tracing::trace!(target: "urma_progress", "Running git {}", operation.escape_debug());
    Ok(())
}
