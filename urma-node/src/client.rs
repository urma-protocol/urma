//! Optional, explicitly configured loopback client. No daemon is started and no
//! DNS, proxy, environment configuration or chain source is consulted.
//!
//! Responses are DATA supplied by a locally trusted operator, not independently
//! verified chain evidence. A receiver using a package from a peer must pass it
//! through `Engine::admit_record`, with its independently selected chain view.

use crate::{Error, model::ArchivedRecord};
use bitcoin::Txid;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 32 * 1024 * 1024;

/// An optional local service connection, trusting the configured local operator.
/// Construction performs no I/O. Each operation opens one bounded connection.
pub struct Client {
    address: SocketAddr,
    token: String,
}

impl Client {
    pub fn new(address: SocketAddr, token: String) -> Result<Self, Error> {
        if !address.ip().is_loopback()
            || token.len() != 64
            || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(
                "client requires loopback and a 64-hex bearer token",
            ));
        }
        Ok(Self { address, token })
    }

    /// Read status reported by the local operator, without verifying its claims.
    pub fn status(&self) -> Result<serde_json::Value, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.get("/v1/status", deadline)?;
        if code != 200 {
            return Err(invalid(format!("local status HTTP {code}")));
        }
        let value = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        Ok(value)
    }

    /// Read locally archived data. `None` means HTTP 404 (not locally available),
    /// not proof that a record does not exist. Authentication and other failures
    /// remain errors. Only the receipt's TXID is compared with the requested ID.
    ///
    /// The chain is unknown here: reveal decoding, TXID/witness recomputation,
    /// inclusion and URMA verification belong to independent admission through
    /// `Engine::admit_record`. Deserialization does not establish those claims.
    pub fn record(&self, txid: Txid) -> Result<Option<ArchivedRecord>, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.get(&format!("/v1/records/{txid}"), deadline)?;
        match code {
            200 => {
                let record: ArchivedRecord = serde_json::from_slice(&body)?;
                if record.receipt.txid != txid {
                    return Err(invalid("local record receipt TXID differs from request"));
                }
                remaining(deadline)?;
                Ok(Some(record))
            }
            404 => {
                // Even a missing result must be a complete framed JSON response.
                let _: serde_json::Value = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                Ok(None)
            }
            _ => Err(invalid(format!("local record HTTP {code}"))),
        }
    }

    fn get(&self, path: &str, deadline: Instant) -> Result<(u16, Vec<u8>), Error> {
        let mut stream =
            TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT.min(remaining(deadline)?))?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            self.address, self.token
        );
        let mut pending = request.as_bytes();
        while !pending.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            let count = match stream.write(pending) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            remaining(deadline)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            pending = &pending[count..];
        }
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() == MAX_HEADER {
                return Err(invalid("local HTTP header exceeds 8192 bytes"));
            }
            let mut byte = [0];
            read(&mut stream, &mut byte, deadline)?;
            header.push(byte[0]);
        }
        let (code, length) = parse_header(&header)?;
        let mut body = vec![0; length];
        let mut received = 0;
        while received < length {
            received += read(&mut stream, &mut body[received..], deadline)?;
        }
        remaining(deadline)?;
        Ok((code, body))
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "local HTTP operation deadline").into()
        })
}

fn read(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> Result<usize, Error> {
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let count = match stream.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        remaining(deadline)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated local HTTP response",
            )
            .into());
        }
        return Ok(count);
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    if !parts
        .next()
        .unwrap()
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return false;
    }
    if let Some(parameter) = parts.next() {
        let Some((name, charset)) = parameter.trim().split_once('=') else {
            return false;
        };
        let charset = charset.trim();
        let charset = charset
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(charset);
        if !name.trim().eq_ignore_ascii_case("charset")
            || charset.is_empty()
            || !charset.bytes().all(is_token)
        {
            return false;
        }
    }
    parts.next().is_none()
}

fn parse_header(bytes: &[u8]) -> Result<(u16, usize), Error> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("invalid local HTTP header encoding"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut status = lines.next().unwrap().splitn(3, ' ');
    if status.next() != Some("HTTP/1.1") {
        return Err(invalid("local response requires HTTP/1.1"));
    }
    let code = status.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("malformed local HTTP status"));
    }
    let reason = status
        .next()
        .ok_or_else(|| invalid("malformed local HTTP status"))?;
    if !reason
        .bytes()
        .all(|byte| byte == b'\t' || (32..=126).contains(&byte))
    {
        return Err(invalid("malformed local HTTP status"));
    }
    let code: u16 = code
        .parse()
        .map_err(|_| invalid("malformed local HTTP status"))?;
    if !(100..=599).contains(&code) {
        return Err(invalid("malformed local HTTP status"));
    }
    let mut length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed local HTTP header"))?;
        if name.is_empty()
            || !name.bytes().all(is_token)
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (32..=126).contains(&byte))
        {
            return Err(invalid("malformed local HTTP header"));
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("local HTTP transfer encoding is unsupported"));
        }
        if name.eq_ignore_ascii_case("content-encoding") && !value.eq_ignore_ascii_case("identity")
        {
            return Err(invalid("local HTTP content encoding is unsupported"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid(
                    "local HTTP requires a single decimal Content-Length",
                ));
            }
            let parsed: usize = value
                .parse()
                .map_err(|_| invalid("invalid local HTTP Content-Length"))?;
            if parsed > MAX_BODY {
                return Err(invalid("local HTTP body exceeds 32 MiB"));
            }
            length = Some(parsed);
        }
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() || !json_content_type(value) {
                return Err(invalid(
                    "local HTTP requires application/json with optional charset",
                ));
            }
            content_type = Some(());
        }
    }
    if content_type.is_none() {
        return Err(invalid("local HTTP Content-Type is missing"));
    }
    Ok((
        code,
        length.ok_or_else(|| invalid("local HTTP Content-Length is missing"))?,
    ))
}
