use crate::gateway_host::{HostError, Portal, Suffix, is_txid};
use lol_html::{
    HtmlRewriter, MemorySettings, Settings, element, errors::RewritingError, html_content::Element,
};
use urma_names::name::Name;
use urma_runtime::error::{Error, ensure};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rewrite {
    Keep,
    To(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Transformed {
    Unchanged,
    Rewritten(Vec<u8>),
}

struct Edit {
    start: usize,
    end: usize,
    text: String,
}

struct Links;

impl Links {
    const SCHEME: &'static str = "urma://";
    const SELECTOR: &'static str = "a[href], area[href], form[action], meta[http-equiv][content]";
}

pub(crate) fn rewrite(value: &str, portal: &Portal) -> Rewrite {
    let Some(rest) = value.strip_prefix(Links::SCHEME) else {
        return Rewrite::Keep;
    };
    match destination(value, rest, portal) {
        Ok(url) => Rewrite::To(url),
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", link = value, reason = %cause, "non-canonical urma link left untouched");
            Rewrite::Keep
        }
    }
}

fn destination(original: &str, rest: &str, portal: &Portal) -> Result<String, HostError> {
    let (host, tail) = split_host(rest);
    canonical(host)?;
    let labels: Vec<&str> = host.split('.').collect();
    let Some((suffix, prefix)) = labels.split_last() else {
        return Err(HostError::Malformed("empty host".into()));
    };
    let suffix = Suffix::parse(suffix)?;
    match prefix {
        [label] if is_txid(label) => Ok(portal.unavailable(original)),
        [label] => {
            let name = parse_name(label)?;
            if portal.serves(suffix) {
                Ok(site_link(portal, &name, suffix, tail))
            } else {
                Ok(portal.unavailable(original))
            }
        }
        [genesis, label] if is_txid(genesis) => {
            let name = parse_name(label)?;
            if portal.is_registry(suffix, genesis) {
                Ok(site_link(portal, &name, suffix, tail))
            } else {
                Ok(portal.unavailable(original))
            }
        }
        other => Err(HostError::Malformed(format!(
            "{} labels before the suffix",
            other.len()
        ))),
    }
}

fn parse_name(label: &str) -> Result<Name, HostError> {
    Name::parse(label).map_err(|cause| HostError::Name(cause.to_string()))
}

fn site_link(portal: &Portal, name: &Name, suffix: Suffix, tail: &str) -> String {
    let origin = portal.site_origin(name, suffix);
    if tail.starts_with('/') {
        format!("{origin}{tail}")
    } else {
        format!("{origin}/{tail}")
    }
}

fn split_host(rest: &str) -> (&str, &str) {
    for (at, byte) in rest.bytes().enumerate() {
        if matches!(byte, b'/' | b'?' | b'#') {
            return rest.split_at(at);
        }
    }
    (rest, "")
}

fn canonical(host: &str) -> Result<(), HostError> {
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    }) {
        return Err(HostError::Malformed(format!(
            "{host:?} is not lowercase ASCII labels (userinfo, port, escapes and uppercase are not canonical)"
        )));
    }
    if host.split('.').any(str::is_empty) {
        return Err(HostError::Malformed(format!("{host:?} has an empty label")));
    }
    Ok(())
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn skip(bytes: &[u8], start: usize, accept: impl Fn(u8) -> bool) -> usize {
    let mut at = start;
    while at < bytes.len() && accept(bytes[at]) {
        at += 1;
    }
    at
}

fn has(bytes: &[u8], at: usize, wanted: &[u8]) -> bool {
    at < bytes.len() && wanted.contains(&bytes[at])
}

fn refresh_url(content: &str) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let time = skip(bytes, 0, is_space);
    let mut at = skip(bytes, time, |byte| byte.is_ascii_digit());
    if at == time && !has(bytes, at, b".") {
        return None;
    }
    at = skip(bytes, at, |byte| byte.is_ascii_digit() || byte == b'.');
    if at < bytes.len() {
        if !(has(bytes, at, b";,") || is_space(bytes[at])) {
            return None;
        }
        at = skip(bytes, at, is_space);
        if has(bytes, at, b";,") {
            at += 1;
        }
        at = skip(bytes, at, is_space);
    }
    if at >= bytes.len() {
        return None;
    }
    Some(url_span(bytes, at))
}

fn url_span(bytes: &[u8], start: usize) -> (usize, usize) {
    let whole = (start, bytes.len());
    if !has(bytes, start, b"Uu") {
        return quoted(bytes, start);
    }
    let mut at = start + 1;
    if !has(bytes, at, b"Rr") {
        return whole;
    }
    at += 1;
    if !has(bytes, at, b"Ll") {
        return whole;
    }
    at = skip(bytes, at + 1, is_space);
    if !has(bytes, at, b"=") {
        return whole;
    }
    quoted(bytes, skip(bytes, at + 1, is_space))
}

fn quoted(bytes: &[u8], at: usize) -> (usize, usize) {
    if !has(bytes, at, b"'\"") {
        return (at, bytes.len());
    }
    let quote = bytes[at];
    let start = at + 1;
    (start, skip(bytes, start, |byte| byte != quote))
}

fn is_refresh(element: &Element<'_, '_>) -> bool {
    let Some(value) = element.get_attribute("http-equiv") else {
        return false;
    };
    value.eq_ignore_ascii_case("refresh")
}

fn attribute_of(tag: &str) -> Option<&'static str> {
    match tag {
        "a" | "area" => Some("href"),
        "form" => Some("action"),
        "meta" => Some("content"),
        _ => None,
    }
}

fn collect(element: &Element<'_, '_>, html: &[u8], portal: &Portal, edits: &mut Vec<Edit>) {
    let tag = element.tag_name();
    let Some(wanted) = attribute_of(&tag) else {
        return;
    };
    if tag == "meta" && !is_refresh(element) {
        return;
    }
    let Some(found) = element
        .attributes()
        .iter()
        .find(|attribute| attribute.name() == wanted)
    else {
        return;
    };
    let Some(location) = found.value_source_location() else {
        return;
    };
    let range = location.bytes();
    let Some(raw) = html.get(range.clone()) else {
        return;
    };
    let text = match std::str::from_utf8(raw) {
        Ok(text) => text,
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", error = %cause, "navigation attribute is not UTF-8; left untouched");
            return;
        }
    };
    let (start, end) = if tag == "meta" {
        let Some(span) = refresh_url(text) else {
            return;
        };
        span
    } else {
        (0, text.len())
    };
    let Some(url) = text.get(start..end) else {
        return;
    };
    if url.contains(char::REPLACEMENT_CHARACTER) {
        return;
    }
    let Rewrite::To(replacement) = rewrite(url, portal) else {
        return;
    };
    edits.push(Edit {
        start: range.start + start,
        end: range.start + end,
        text: replacement,
    });
}

fn rewriting(cause: RewritingError) -> Error {
    Error::Invalid(format!("links-v1 transform: {cause}"))
}

pub(crate) fn transform(html: &[u8], portal: &Portal, memory: usize) -> Result<Transformed, Error> {
    let mut edits = Vec::new();
    let mut echoed = Vec::with_capacity(html.len());
    {
        let settings = Settings::new()
            .append_element_content_handler(element!(Links::SELECTOR, |found| {
                collect(found, html, portal, &mut edits);
                Ok(())
            }))
            .with_memory_settings(MemorySettings::new().with_max_allowed_memory_usage(memory));
        let mut rewriter =
            HtmlRewriter::new(settings, |chunk: &[u8]| echoed.extend_from_slice(chunk));
        rewriter.write(html).map_err(rewriting)?;
        rewriter.end().map_err(rewriting)?;
    }
    ensure!(
        echoed == html,
        "links-v1 transform: the HTML rewriter altered bytes it was not asked to change"
    );
    if edits.is_empty() {
        return Ok(Transformed::Unchanged);
    }
    Ok(Transformed::Rewritten(splice(html, &edits)?))
}

fn splice(html: &[u8], edits: &[Edit]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(html.len());
    let mut cursor = 0;
    for edit in edits {
        ensure!(
            cursor <= edit.start && edit.start <= edit.end,
            "links-v1 transform: overlapping attribute edits"
        );
        let Some(kept) = html.get(cursor..edit.start) else {
            return Err(Error::Invalid(
                "links-v1 transform: edit outside the document".into(),
            ));
        };
        output.extend_from_slice(kept);
        output.extend_from_slice(edit.text.as_bytes());
        cursor = edit.end;
    }
    let Some(rest) = html.get(cursor..) else {
        return Err(Error::Invalid(
            "links-v1 transform: edit outside the document".into(),
        ));
    };
    output.extend_from_slice(rest);
    Ok(output)
}
