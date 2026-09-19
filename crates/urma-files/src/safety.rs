use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
use unicode_normalization::UnicodeNormalization;
use urma::error::{Error, ensure};
use zeroize::Zeroizing;

pub fn validate_id(id: &str) -> Result<(), Error> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid object ID or digest"
    );
    Ok(())
}

pub fn validate_path(path: &str) -> Result<(), Error> {
    ensure!(
        !path.is_empty() && path.len() <= 1024 && path.split('/').count() <= 32,
        "path exceeds profile bounds"
    );
    ensure!(path.nfc().eq(path.chars()), "path must use NFC Unicode");
    for name in path.split('/') {
        ensure!(
            !name.is_empty() && name.len() <= 255 && name != "." && name != "..",
            "invalid path component"
        );
        ensure!(
            !name.ends_with(['.', ' ']),
            "nonportable trailing path character"
        );
        ensure!(
            !name
                .chars()
                .any(|ch| ch.is_control() || "\\:*?\"<>|".contains(ch)),
            "unsafe path character"
        );
        let stem = name
            .split('.')
            .next()
            .ok_or_else(|| Error::Invalid("empty name".into()))?
            .to_uppercase();
        ensure!(
            !matches!(
                stem.as_str(),
                "CON"
                    | "PRN"
                    | "AUX"
                    | "NUL"
                    | "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            ),
            "reserved platform filename"
        );
    }
    Ok(())
}

pub fn read_regular(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "only regular input files are supported"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds client capacity");
    Ok(bytes)
}

pub fn new_directory(path: &Path) -> Result<(), Error> {
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    File::open(path)?.sync_all()?;
    Ok(())
}
