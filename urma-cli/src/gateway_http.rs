use crate::gateway_pages::error_page;
use serde_json::Value;
use std::{
    fmt::{Display, Formatter},
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    time::{Duration, Instant},
};
use urma_runtime::error::{Error, ensure};

#[derive(Clone, Copy, Debug)]
pub(crate) struct HttpLimits {
    pub(crate) head_bytes: usize,
    pub(crate) max_headers: usize,
    pub(crate) target_bytes: usize,
    pub(crate) io_timeout: Duration,
    pub(crate) head_timeout: Duration,
    pub(crate) accept_backoff: Duration,
    pub(crate) linger: Duration,
    pub(crate) linger_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Head,
}

pub(crate) struct Request {
    pub(crate) method: Method,
    pub(crate) target: String,
    pub(crate) host: String,
    pub(crate) validators: Vec<String>,
}

impl Request {
    pub(crate) fn validates(&self, etag: &str) -> bool {
        self.validators
            .iter()
            .any(|candidate| entity_tag_matches(candidate, etag))
    }
}

fn entity_tag_matches(candidate: &str, etag: &str) -> bool {
    if candidate == "*" || candidate == etag {
        return true;
    }
    let Some(weak) = candidate.strip_prefix("W/") else {
        return false;
    };
    weak == etag
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    pub(crate) const NO_STORE: &'static str = "no-store";
    const CSP: &'static str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'";
    const PERMISSIONS: &'static str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), interest-cohort=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), usb=(), window-management=(), xr-spatial-tracking=()";

    pub(crate) fn new(status: u16, content_type: &str, cache: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type", content_type.to_owned()),
                ("Cache-Control", cache.to_owned()),
                ("Content-Security-Policy", Self::CSP.to_owned()),
                ("X-Content-Type-Options", "nosniff".to_owned()),
                ("Permissions-Policy", Self::PERMISSIONS.to_owned()),
                ("Referrer-Policy", "no-referrer".to_owned()),
                ("Cross-Origin-Opener-Policy", "same-origin".to_owned()),
                ("Cross-Origin-Resource-Policy", "same-origin".to_owned()),
            ],
            body,
        }
    }

    pub(crate) fn with(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    pub(crate) fn html(status: u16, page: String) -> Self {
        Self::new(
            status,
            "text/html; charset=utf-8",
            Self::NO_STORE,
            page.into_bytes(),
        )
    }

    pub(crate) fn text(status: u16, text: &str) -> Self {
        Self::new(
            status,
            "text/plain; charset=utf-8",
            Self::NO_STORE,
            text.as_bytes().to_vec(),
        )
    }

    pub(crate) fn json(status: u16, value: &Value) -> Result<Self, Error> {
        let mut body = serde_json::to_vec_pretty(value)?;
        body.push(b'\n');
        Ok(Self::new(status, "application/json", Self::NO_STORE, body))
    }

    pub(crate) fn not_modified(mut self) -> Self {
        self.status = 304;
        self.body.clear();
        self
    }

    fn encode(&self, method: Method) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.body.len() + 1024);
        write!(
            bytes,
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason(self.status)
        )?;
        for (name, value) in &self.headers {
            ensure!(
                !value.bytes().any(|byte| byte == b'\r' || byte == b'\n'),
                "response header {name} carries a line break"
            );
            write!(bytes, "{name}: {value}\r\n")?;
        }
        if self.status != 304 {
            write!(bytes, "Content-Length: {}\r\n", self.body.len())?;
        }
        bytes.extend_from_slice(b"Connection: close\r\n\r\n");
        if method == Method::Get {
            bytes.extend_from_slice(&self.body);
        }
        Ok(bytes)
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Content Too Large",
        414 => "URI Too Long",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) status: u16,
    pub(crate) title: &'static str,
    pub(crate) detail: String,
    pub(crate) headers: Vec<(&'static str, String)>,
}

impl Refusal {
    pub(crate) fn new(status: u16, title: &'static str, detail: String) -> Self {
        Self {
            status,
            title,
            detail,
            headers: Vec::new(),
        }
    }

    pub(crate) fn with(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    pub(crate) fn internal(detail: String) -> Self {
        Self::new(500, "Internal Server Error", detail)
    }

    pub(crate) fn reply(&self) -> Reply {
        let mut reply = Reply::html(
            self.status,
            error_page(self.status, self.title, &self.detail),
        );
        for (name, value) in &self.headers {
            reply = reply.with(name, value.clone());
        }
        reply
    }
}

impl Display for Refusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}: {}", self.status, self.title, self.detail)
    }
}

impl std::error::Error for Refusal {}

impl From<Error> for Refusal {
    fn from(cause: Error) -> Self {
        Self::internal(cause.to_string())
    }
}

enum Incoming {
    Request(Request),
    Refused(Refusal),
    Closed,
}

pub(crate) fn accept_loop(
    listener: &TcpListener,
    limits: &HttpLimits,
    respond: &impl Fn(&Request) -> Reply,
) {
    loop {
        match listener.accept() {
            Ok((stream, peer)) => match exchange(stream, limits, respond) {
                Ok(()) => {}
                Err(cause) => {
                    tracing::warn!(target: "urma_gateway", %peer, error = %cause, "connection ended with an error")
                }
            },
            Err(cause) => {
                tracing::warn!(target: "urma_gateway", error = %cause, "accepting a connection failed");
                std::thread::sleep(limits.accept_backoff);
            }
        }
    }
}

fn exchange(
    mut stream: TcpStream,
    limits: &HttpLimits,
    respond: &impl Fn(&Request) -> Reply,
) -> Result<(), Error> {
    stream.set_read_timeout(Some(limits.io_timeout))?;
    stream.set_write_timeout(Some(limits.io_timeout))?;
    let (reply, method) = match read_request(&mut stream, limits)? {
        Incoming::Closed => return Ok(()),
        Incoming::Refused(refusal) => {
            tracing::warn!(target: "urma_gateway", %refusal, "request refused before routing");
            (refusal.reply(), Method::Get)
        }
        Incoming::Request(request) => (respond(&request), request.method),
    };
    stream.write_all(&reply.encode(method)?)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    linger(&mut stream, limits)
}

fn linger(stream: &mut TcpStream, limits: &HttpLimits) -> Result<(), Error> {
    stream.set_read_timeout(Some(limits.linger))?;
    let started = Instant::now();
    let mut sink = [0u8; 2048];
    let mut drained = 0usize;
    while drained < limits.linger_bytes && started.elapsed() < limits.linger {
        let count = stream.read(&mut sink)?;
        if count == 0 {
            break;
        }
        drained += count;
    }
    Ok(())
}

fn read_request(stream: &mut TcpStream, limits: &HttpLimits) -> Result<Incoming, Error> {
    let started = Instant::now();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if started.elapsed() > limits.head_timeout {
            return Ok(Incoming::Refused(timeout()));
        }
        let count = match stream.read(&mut chunk) {
            Ok(count) => count,
            Err(cause) if matches!(cause.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                tracing::warn!(target: "urma_gateway", error = %cause, "request head timed out");
                return Ok(Incoming::Refused(timeout()));
            }
            Err(cause) => return Err(Error::Io(cause)),
        };
        if count == 0 {
            if buffer.is_empty() {
                return Ok(Incoming::Closed);
            }
            return Ok(Incoming::Refused(Refusal::new(
                400,
                "Bad Request",
                "connection closed inside the request head".into(),
            )));
        }
        let Some(fresh) = chunk.get(..count) else {
            return Err(Error::Invalid("read past the chunk buffer".into()));
        };
        buffer.extend_from_slice(fresh);
        if let Parsed::Done(incoming) = parse_head(&buffer, limits) {
            return Ok(incoming);
        }
        if buffer.len() >= limits.head_bytes {
            return Ok(Incoming::Refused(Refusal::new(
                431,
                "Request Header Fields Too Large",
                format!("request head exceeds {} bytes", limits.head_bytes),
            )));
        }
    }
}

fn timeout() -> Refusal {
    Refusal::new(
        408,
        "Request Timeout",
        "the request head did not arrive in time".into(),
    )
}

enum Parsed {
    Partial,
    Done(Incoming),
}

fn parse_head(buffer: &[u8], limits: &HttpLimits) -> Parsed {
    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_headers];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(buffer) {
        Ok(httparse::Status::Partial) => Parsed::Partial,
        Ok(httparse::Status::Complete(..)) => Parsed::Done(admit(&parsed, limits)),
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", error = %cause, "unparseable request head");
            let status = if cause == httparse::Error::TooManyHeaders {
                431
            } else {
                400
            };
            Parsed::Done(Incoming::Refused(Refusal::new(
                status,
                reason(status),
                format!("unparseable request head: {cause}"),
            )))
        }
    }
}

fn admit(parsed: &httparse::Request<'_, '_>, limits: &HttpLimits) -> Incoming {
    let (Some(method), Some(target)) = (parsed.method, parsed.path) else {
        return refused(400, "request line without method or target".into());
    };
    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        other => {
            return Incoming::Refused(
                Refusal::new(
                    405,
                    "Method Not Allowed",
                    format!("{other} is not served; the portal is read-only"),
                )
                .with("Allow", "GET, HEAD".into()),
            );
        }
    };
    if target.len() > limits.target_bytes {
        return refused(
            414,
            format!("request target exceeds {} bytes", limits.target_bytes),
        );
    }
    if !target.starts_with('/') {
        return refused(400, "request target must be an absolute path".into());
    }
    let mut hosts = Vec::new();
    let mut validators = Vec::new();
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            hosts.push(header.value);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding")
            || (header.name.eq_ignore_ascii_case("content-length")
                && header.value.trim_ascii() != b"0")
        {
            return refused(413, "request bodies are not accepted".into());
        } else if header.name.eq_ignore_ascii_case("if-none-match") {
            validators.extend(entity_tags(header.value));
        }
    }
    let [host] = hosts.as_slice() else {
        return refused(400, "exactly one Host header is required".into());
    };
    match std::str::from_utf8(host) {
        Ok(host) => Incoming::Request(Request {
            method,
            target: target.to_owned(),
            host: host.to_owned(),
            validators,
        }),
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", error = %cause, "Host header is not UTF-8");
            refused(400, format!("Host header is not UTF-8: {cause}"))
        }
    }
}

fn refused(status: u16, detail: String) -> Incoming {
    Incoming::Refused(Refusal::new(status, reason(status), detail))
}

fn entity_tags(value: &[u8]) -> Vec<String> {
    let mut tags = Vec::new();
    for part in value.split(|byte| *byte == b',') {
        let trimmed = part.trim_ascii();
        match std::str::from_utf8(trimmed) {
            Ok(tag) => tags.push(tag.to_owned()),
            Err(cause) => {
                tracing::warn!(target: "urma_gateway", error = %cause, "If-None-Match entry is not UTF-8; ignored");
            }
        }
    }
    tags
}
