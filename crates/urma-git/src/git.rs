use crate::error::Error;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
};

pub fn command(repo: &Path) -> Command {
    let mut command = Command::new("/usr/bin/prlimit");
    command.args([
        "--as=536870912",
        "--cpu=1800",
        "--fsize=67108864",
        "--",
        "/usr/bin/git",
    ]);
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
        ]);
    command
}

pub fn run(repo: &Path, args: &[&OsStr], input: &Path, output: &Path) -> Result<(), Error> {
    let mut stderr = tempfile::tempfile_in(
        output
            .parent()
            .ok_or_else(|| Error::Invalid("worker output parent".into()))?,
    )?;
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
    let mut stdout = tempfile::tempfile_in(repo)?;
    let mut stderr = tempfile::tempfile_in(repo)?;
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
