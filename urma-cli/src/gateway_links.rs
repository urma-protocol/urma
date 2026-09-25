use crate::gateway_host::{HostError, Portal, Suffix, is_txid};
use std::ops::Range;
use urma_names::name::Name;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Transformed {
    Unchanged,
    Rewritten(Vec<u8>),
}

pub(crate) fn transform(html: &[u8], portal: &Portal) -> Transformed {
    let mut links = Links {
        html,
        portal,
        output: Vec::new(),
        cursor: 0,
    };
    let mut at = 0;
    while at < html.len() {
        at = links.markup(run(html, at, |byte| byte != b'<') + 1);
    }
    links.finish()
}

struct Links<'a> {
    html: &'a [u8],
    portal: &'a Portal,
    output: Vec<u8>,
    cursor: usize,
}

impl Links<'_> {
    const SCHEME: &'static [u8] = b"urma://";

    fn markup(&mut self, at: usize) -> usize {
        let html = self.html;
        let Some(&byte) = html.get(at) else {
            return html.len();
        };
        match byte {
            b'!' if html[at + 1..].starts_with(b"--") => comment(html, at + 3),
            b'!' | b'?' => past(html, at, b'>'),
            b'/' => end_tag(html, at + 1),
            letter if letter.is_ascii_alphabetic() => self.start_tag(at),
            _ => at,
        }
    }

    fn start_tag(&mut self, at: usize) -> usize {
        let html = self.html;
        let Scanned::Tag(tag) = tag(html, at) else {
            return html.len();
        };
        for slot in url_slot(html, &tag).iter() {
            self.link(slot);
        }
        match Text::after(&html[tag.name.clone()]) {
            Text::Data => tag.end,
            Text::Raw(name) => raw_end(html, tag.end, name),
            Text::Script => script_end(html, tag.end),
            Text::Plain => html.len(),
        }
    }

    fn link(&mut self, slot: &Range<usize>) {
        let value = &self.html[slot.clone()];
        let candidate = value.trim_ascii();
        let Rewrite::To(text) = rewrite(candidate, self.portal) else {
            return;
        };
        let start = slot.start + value.len() - value.trim_ascii_start().len();
        self.output
            .extend_from_slice(&self.html[self.cursor..start]);
        self.output.extend_from_slice(&text);
        self.cursor = start + candidate.len();
    }

    fn finish(mut self) -> Transformed {
        if self.cursor == 0 {
            return Transformed::Unchanged;
        }
        self.output.extend_from_slice(&self.html[self.cursor..]);
        Transformed::Rewritten(self.output)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Href,
    Action,
    HttpEquiv,
    Content,
}

impl Field {
    const ALL: [Self; 4] = [Self::Href, Self::Action, Self::HttpEquiv, Self::Content];

    fn name(self) -> &'static [u8] {
        match self {
            Self::Href => b"href",
            Self::Action => b"action",
            Self::HttpEquiv => b"http-equiv",
            Self::Content => b"content",
        }
    }
}

struct Tag {
    name: Range<usize>,
    end: usize,
    fields: Vec<(Field, Range<usize>)>,
}

impl Tag {
    fn keep(&mut self, name: &[u8], value: Range<usize>) {
        for field in Field::ALL {
            if name.eq_ignore_ascii_case(field.name())
                && !self.fields.iter().any(|kept| kept.0 == field)
            {
                self.fields.push((field, value.clone()));
            }
        }
    }

    fn field(&self, wanted: Field) -> Option<Range<usize>> {
        self.fields
            .iter()
            .find(|kept| kept.0 == wanted)
            .map(|kept| kept.1.clone())
    }
}

enum Scanned {
    Tag(Tag),
    Unterminated,
}

impl Scanned {
    fn end(&self, html: &[u8]) -> usize {
        match self {
            Self::Tag(tag) => tag.end,
            Self::Unterminated => html.len(),
        }
    }
}

enum Value {
    Span(Range<usize>, usize),
    Unterminated,
}

enum Text {
    Data,
    Raw(&'static [u8]),
    Script,
    Plain,
}

impl Text {
    const RAW: [&'static [u8]; 7] = [
        b"title",
        b"textarea",
        b"style",
        b"xmp",
        b"iframe",
        b"noembed",
        b"noframes",
    ];

    fn after(name: &[u8]) -> Self {
        for raw in Self::RAW {
            if name.eq_ignore_ascii_case(raw) {
                return Self::Raw(raw);
            }
        }
        if name.eq_ignore_ascii_case(b"script") {
            return Self::Script;
        }
        if name.eq_ignore_ascii_case(b"plaintext") {
            return Self::Plain;
        }
        Self::Data
    }
}

#[derive(Clone, Copy)]
enum Script {
    Data,
    Escaped(u8),
    Double(u8),
}

impl Script {
    fn after(self, byte: u8) -> Self {
        match (self, byte) {
            (Self::Data, ..) => Self::Data,
            (Self::Escaped(2) | Self::Double(2), b'>') => Self::Data,
            (Self::Escaped(dashes), b'-') => Self::Escaped((dashes + 1).min(2)),
            (Self::Escaped(..), ..) => Self::Escaped(0),
            (Self::Double(dashes), b'-') => Self::Double((dashes + 1).min(2)),
            (Self::Double(..), ..) => Self::Double(0),
        }
    }

    fn open(self, html: &[u8], at: usize) -> (Self, usize) {
        match self {
            Self::Data if html[at..].starts_with(b"<!--") => (Self::Escaped(2), at + 4),
            Self::Data => (Self::Data, at + 1),
            Self::Escaped(..) if named(html, at + 1, b"script") => (Self::Double(0), at + 8),
            Self::Escaped(..) => (Self::Escaped(0), at + 1),
            Self::Double(..) if closes(html, at, b"script") => (Self::Escaped(0), at + 9),
            Self::Double(..) => (Self::Double(0), at + 1),
        }
    }
}

fn tag(html: &[u8], start: usize) -> Scanned {
    let mut tag = Tag {
        name: start..run(html, start, |byte| !ends_name(byte)),
        end: html.len(),
        fields: Vec::new(),
    };
    let mut at = tag.name.end;
    loop {
        at = run(html, at, |byte| is_space(byte) || byte == b'/');
        let Some(&byte) = html.get(at) else {
            return Scanned::Unterminated;
        };
        if byte == b'>' {
            tag.end = at + 1;
            return Scanned::Tag(tag);
        }
        let name = at..run(html, at + 1, |byte| !ends_name(byte) && byte != b'=');
        at = run(html, name.end, is_space);
        let mut value = at..at;
        if is(html, at, b"=") {
            let Value::Span(span, next) = attribute_value(html, at + 1) else {
                return Scanned::Unterminated;
            };
            value = span;
            at = next;
        }
        tag.keep(&html[name], value);
    }
}

fn attribute_value(html: &[u8], from: usize) -> Value {
    let at = run(html, from, is_space);
    let Some(&quote) = html.get(at) else {
        return Value::Unterminated;
    };
    if quote != b'"' && quote != b'\'' {
        let end = run(html, at, |byte| !is_space(byte) && byte != b'>');
        return Value::Span(at..end, end);
    }
    let close = run(html, at + 1, |byte| byte != quote);
    if close == html.len() {
        return Value::Unterminated;
    }
    Value::Span(at + 1..close, close + 1)
}

fn end_tag(html: &[u8], at: usize) -> usize {
    let Some(&byte) = html.get(at) else {
        return html.len();
    };
    if byte == b'>' {
        return at + 1;
    }
    if !byte.is_ascii_alphabetic() {
        return past(html, at, b'>');
    }
    tag(html, at).end(html)
}

fn comment(html: &[u8], start: usize) -> usize {
    let mut close = start;
    loop {
        close = run(html, close, |byte| byte != b'>');
        let text = &html[start..close];
        if close == html.len()
            || matches!(text, [] | [b'-'])
            || text.ends_with(b"--")
            || text.ends_with(b"--!")
        {
            return (close + 1).min(html.len());
        }
        close += 1;
    }
}

fn past(html: &[u8], from: usize, byte: u8) -> usize {
    (run(html, from, |candidate| candidate != byte) + 1).min(html.len())
}

fn raw_end(html: &[u8], from: usize, name: &[u8]) -> usize {
    let mut at = from;
    while at < html.len() {
        let open = run(html, at, |byte| byte != b'<');
        if closes(html, open, name) {
            return tag(html, open + 2).end(html);
        }
        at = open + 1;
    }
    html.len()
}

fn script_end(html: &[u8], from: usize) -> usize {
    let mut state = Script::Data;
    let mut at = from;
    while at < html.len() {
        if html[at] != b'<' {
            state = state.after(html[at]);
            at += 1;
        } else if !matches!(state, Script::Double(..)) && closes(html, at, b"script") {
            return tag(html, at + 2).end(html);
        } else {
            (state, at) = state.open(html, at);
        }
    }
    html.len()
}

fn closes(html: &[u8], at: usize, name: &[u8]) -> bool {
    html[at..].starts_with(b"</") && named(html, at + 2, name)
}

fn named(html: &[u8], at: usize, name: &[u8]) -> bool {
    let end = at + name.len();
    end < html.len() && html[at..end].eq_ignore_ascii_case(name) && ends_name(html[end])
}

fn url_slot(html: &[u8], tag: &Tag) -> Option<Range<usize>> {
    let name = &html[tag.name.clone()];
    if name.eq_ignore_ascii_case(b"a") || name.eq_ignore_ascii_case(b"area") {
        return tag.field(Field::Href);
    }
    if name.eq_ignore_ascii_case(b"form") {
        return tag.field(Field::Action);
    }
    if !name.eq_ignore_ascii_case(b"meta") {
        return None;
    }
    let equiv = tag.field(Field::HttpEquiv)?;
    if !html[equiv].eq_ignore_ascii_case(b"refresh") {
        return None;
    }
    let content = tag.field(Field::Content)?;
    let url = refresh(&html[content.clone()])?;
    Some(content.start + url.start..content.start + url.end)
}

fn refresh(content: &[u8]) -> Option<Range<usize>> {
    let time = run(content, 0, is_space);
    let digits = run(content, time, |byte| byte.is_ascii_digit());
    if digits == time && !is(content, time, b".") {
        return None;
    }
    let mut at = run(content, digits, |byte| {
        byte.is_ascii_digit() || byte == b'.'
    });
    if at < content.len() {
        if !is(content, at, b";,\t\n\x0c\r ") {
            return None;
        }
        at = run(content, at, is_space);
        if is(content, at, b";,") {
            at += 1;
        }
        at = run(content, at, is_space);
    }
    if at == content.len() {
        return None;
    }
    Some(refresh_url(content, at))
}

fn refresh_url(content: &[u8], start: usize) -> Range<usize> {
    if !is(content, start, b"Uu") {
        return quoted(content, start);
    }
    if !is(content, start + 1, b"Rr") || !is(content, start + 2, b"Ll") {
        return start..content.len();
    }
    let equals = run(content, start + 3, is_space);
    if !is(content, equals, b"=") {
        return start..content.len();
    }
    quoted(content, run(content, equals + 1, is_space))
}

fn quoted(content: &[u8], at: usize) -> Range<usize> {
    if !is(content, at, b"'\"") {
        return at..content.len();
    }
    let quote = content[at];
    at + 1..run(content, at + 1, |byte| byte != quote)
}

enum Rewrite {
    Keep,
    To(Vec<u8>),
}

enum Target {
    Site(Name, Suffix),
    Unavailable,
}

fn rewrite(candidate: &[u8], portal: &Portal) -> Rewrite {
    let Some(rest) = candidate.strip_prefix(Links::SCHEME) else {
        return Rewrite::Keep;
    };
    let (host, tail) = rest.split_at(run(rest, 0, |byte| !b"/?#".contains(&byte)));
    if tail
        .iter()
        .any(|byte| *byte <= b' ' || *byte == b'\x7f' || *byte == b'\\')
    {
        return Rewrite::Keep;
    }
    match target(host, portal) {
        Ok(Target::Site(name, suffix)) => Rewrite::To(site_link(portal, &name, suffix, tail)),
        Ok(Target::Unavailable) => Rewrite::To(portal.unavailable(candidate).into_bytes()),
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", link = %candidate.escape_ascii(), reason = %cause, "non-canonical urma link left untouched");
            Rewrite::Keep
        }
    }
}

fn target(host: &[u8], portal: &Portal) -> Result<Target, HostError> {
    let host =
        std::str::from_utf8(host).map_err(|cause| HostError::Malformed(cause.to_string()))?;
    canonical(host)?;
    let labels: Vec<&str> = host.split('.').collect();
    let Some((suffix, prefix)) = labels.split_last() else {
        return Err(HostError::Malformed("empty host".into()));
    };
    let suffix = Suffix::parse(suffix)?;
    match prefix {
        [label] if is_txid(label) => Ok(Target::Unavailable),
        [label] => Ok(Target::Site(parse_name(label)?, suffix)),
        [genesis, label] if is_txid(genesis) => {
            let name = parse_name(label)?;
            if portal.is_registry(suffix, genesis) {
                return Ok(Target::Site(name, suffix));
            }
            Ok(Target::Unavailable)
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

fn site_link(portal: &Portal, name: &Name, suffix: Suffix, tail: &[u8]) -> Vec<u8> {
    let mut link = portal.site_origin(name, suffix).into_bytes();
    if !tail.starts_with(b"/") {
        link.push(b'/');
    }
    link.extend_from_slice(tail);
    link
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

fn ends_name(byte: u8) -> bool {
    is_space(byte) || byte == b'/' || byte == b'>'
}

fn run(bytes: &[u8], from: usize, accept: impl Fn(u8) -> bool) -> usize {
    let mut at = from;
    while at < bytes.len() && accept(bytes[at]) {
        at += 1;
    }
    at
}

fn is(bytes: &[u8], at: usize, wanted: &[u8]) -> bool {
    at < bytes.len() && wanted.contains(&bytes[at])
}
