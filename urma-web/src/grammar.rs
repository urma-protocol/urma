use crate::error::{WebError, ensure_web};

pub struct Grammar;

impl Grammar {
    pub const MAX_PATH_BYTES: usize = 65_535;
    pub const MAX_MIME_BYTES: usize = 255;
    pub const MAX_LABEL_BYTES: usize = 64;
    pub const CHARSET_PARAMETER: &'static str = "charset=utf-8";
    pub const ENTRY_MIME: &'static str = "text/html";
}

pub fn validate_path(path: &str) -> Result<(), WebError> {
    ensure_web!(
        (1..=Grammar::MAX_PATH_BYTES).contains(&path.len()),
        "path must be 1..65535 bytes (u16 path_len)"
    );
    for segment in path.split('/') {
        ensure_web!(
            !segment.is_empty(),
            "path segments cannot be empty: {path:?}"
        );
        ensure_web!(
            segment != "." && segment != "..",
            "path segments cannot be . or ..: {path:?}"
        );
        ensure_web!(
            segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)),
            "path bytes must be URL-unreserved ASCII: {path:?}"
        );
    }
    Ok(())
}

pub fn validate_mime(mime: &str) -> Result<(), WebError> {
    ensure_web!(
        (1..=Grammar::MAX_MIME_BYTES).contains(&mime.len()),
        "mime must be 1..255 bytes (u8 mime_len)"
    );
    let mut parts = mime.split(';');
    let Some(essence) = parts.next() else {
        return Err(WebError::Invalid("empty mime".into()));
    };
    let mut parameters = 0;
    for parameter in parts {
        parameters += 1;
        ensure_web!(
            parameter == Grammar::CHARSET_PARAMETER,
            "mime parameters are limited to ;charset=utf-8: {mime:?}"
        );
    }
    ensure_web!(parameters <= 1, "mime carries one parameter at most");
    let Some((kind, subtype)) = essence.split_once('/') else {
        return Err(WebError::Invalid(format!(
            "mime must be type/subtype: {mime:?}"
        )));
    };
    for token in [kind, subtype] {
        ensure_web!(
            !token.is_empty()
                && token.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || b"!#$&^_.+-".contains(&byte)
                }),
            "mime tokens are lowercase ASCII token characters: {mime:?}"
        );
    }
    Ok(())
}

pub fn is_entry_mime(mime: &str) -> bool {
    mime == Grammar::ENTRY_MIME
        || mime == format!("{};{}", Grammar::ENTRY_MIME, Grammar::CHARSET_PARAMETER)
}

pub enum Wanted {
    Entry,
    Path(String),
    Unresolvable,
}

pub fn wanted(url_path: &str) -> Wanted {
    let Some(relative) = url_path.strip_prefix('/') else {
        return Wanted::Unresolvable;
    };
    if relative.is_empty() {
        return Wanted::Entry;
    }
    if relative.ends_with('/') {
        return Wanted::Path(format!("{relative}index.html"));
    }
    Wanted::Path(relative.to_owned())
}

pub fn validate_label(label: &str) -> Result<(), WebError> {
    ensure_web!(
        label.len() <= Grammar::MAX_LABEL_BYTES,
        "label must be at most 64 bytes"
    );
    ensure_web!(
        label.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "label must be printable ASCII"
    );
    Ok(())
}
