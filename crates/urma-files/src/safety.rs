use std::{fs::File, path::Path};
use unicode_normalization::UnicodeNormalization;
use urma_runtime::error::{Error, ensure};
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
    urma_io::read_regular(path, limit).map_err(|cause| match cause {
        urma_io::Error::TooLarge { .. } => Error::Invalid("input exceeds client capacity".into()),
        urma_io::Error::Io(cause) if cause.kind() == std::io::ErrorKind::InvalidInput => {
            Error::Invalid(cause.to_string())
        }
        cause => cause.into(),
    })
}

pub fn new_directory(path: &Path) -> Result<(), Error> {
    urma_io::create_private_directory(path)?;
    File::open(path)?.sync_all()?;
    Ok(())
}
