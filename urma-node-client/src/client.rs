//! Optional, explicitly configured loopback client. No daemon is started and no
//! DNS, proxy, environment configuration or chain source is consulted.
//!
//! Responses are DATA supplied by a locally trusted operator, not independently
//! verified chain evidence. A receiver using a package from a peer must pass it
//! through `Engine::admit_record`, with its independently selected chain view.

use crate::{
    Error,
    model::{ArchivedRecord, ChainPoint, ObjectStatus, PinReceipt, PruneReceipt},
    names::{NamesResolution, NamesStatus, NamesStep},
    projection::{MAX_WIRE_PAGE, WireCursor, WirePage},
};
use bitcoin::Txid;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
use urma_names::name::Name;

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
        let (code, body) = self.request("GET", "/v1/status", deadline)?;
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
        let (code, body) = self.request("GET", &format!("/v1/records/{txid}"), deadline)?;
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

    /// Read object availability reported by the configured local operator.
    /// These are operator data, not independently verified chain evidence.
    /// Selected member count is independent of local retention: either count
    /// may exceed the other, but both must be within a nonzero member total.
    /// `None` means only that no completed object is recorded locally (HTTP 404),
    /// not global absence. Root/count sanity checks establish no crypto claims.
    pub fn object_status(&self, root: Txid) -> Result<Option<ObjectStatus>, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.request("GET", &format!("/v1/objects/{root}"), deadline)?;
        match code {
            200 => {
                let status: ObjectStatus = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                if status.root != root {
                    return Err(invalid("local object status root differs from request"));
                }
                if status.members_total == 0
                    || status.members_local > status.members_total
                    || status.members_selected > status.members_total
                {
                    return Err(invalid("local object status has impossible member counts"));
                }
                Ok(Some(status))
            }
            404 => {
                let _: serde_json::Value = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                Ok(None)
            }
            _ => Err(invalid(format!("local object status HTTP {code}"))),
        }
    }

    /// Request a local pin or unpin and read the operator's acknowledgement at
    /// its commit point. This is not cryptographic evidence or a promise of
    /// future availability, chain selection or pin state. Only HTTP 200 with
    /// the requested root and pin value succeeds. No automatic retry occurs:
    /// the operation may already have committed before a socket failure.
    pub fn set_pin(&self, root: Txid, pin: bool) -> Result<PinReceipt, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let action = if pin { "pin" } else { "unpin" };
        let (code, body) =
            self.request("POST", &format!("/v1/objects/{root}/{action}"), deadline)?;
        if code != 200 {
            return Err(invalid(format!("local {action} HTTP {code}")));
        }
        let receipt: PinReceipt = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        if receipt.root != root || receipt.pinned != pin {
            return Err(invalid("local pin receipt differs from request"));
        }
        Ok(receipt)
    }

    /// Request explicit local cache pruning and read the operator's removal
    /// count. This acknowledgement is not cryptographic evidence or a promise
    /// of future cache contents. Only HTTP 200 succeeds. No automatic retry
    /// occurs, including when a socket failure leaves the commit outcome unknown.
    pub fn prune_cache(&self) -> Result<PruneReceipt, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.request("POST", "/v1/cache/prune", deadline)?;
        if code != 200 {
            return Err(invalid(format!("local cache prune HTTP {code}")));
        }
        let receipt = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        Ok(receipt)
    }

    /// Read one bounded page of Wire records from the configured local operator.
    /// Entry parsing checks data consistency, not authorship or chain inclusion.
    /// Selected records and scanned coverage remain separate; `next == None`
    /// ends only the local result set and does not establish chain completeness.
    /// A snapshot is opaque. HTTP 409 returns `Error::Busy`: discard the partial
    /// traversal and explicitly restart. No paging, retry or readback is automatic.
    pub fn wire_page(&self, cursor: Option<&WireCursor>, limit: u32) -> Result<WirePage, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        if !(1..=MAX_WIRE_PAGE).contains(&limit) {
            return Err(invalid("local Wire limit must be 1..128"));
        }
        let mut path = format!("/v1/wire?limit={limit}");
        if let Some(cursor) = cursor {
            validate_instance(&cursor.snapshot.instance)?;
            if cursor.height > i64::MAX as u64 {
                return Err(invalid("local Wire cursor height is out of range"));
            }
            let encoded = serde_json::to_vec(cursor)?;
            if encoded.len() > 512 {
                return Err(invalid("local Wire cursor exceeds 1024 hex characters"));
            }
            path.push_str("&cursor=");
            path.push_str(&hex::encode(encoded));
        }
        let (code, body) = self.request("GET", &path, deadline)?;
        if code == 409 {
            return Err(Error::Busy(
                "local Wire snapshot changed; discard traversal and restart".into(),
            ));
        }
        if code != 200 {
            return Err(invalid(format!("local Wire HTTP {code}")));
        }
        let page: WirePage = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        validate_wire_page(&page, cursor, limit, deadline)?;
        remaining(deadline)?;
        Ok(page)
    }

    /// Register one explicitly located Names genesis with the local operator.
    /// The acknowledgement describes a local index, not independently verified
    /// chain evidence or permanent registration/state. HTTP 409 is `Error::Busy`.
    /// Heights above `i64::MAX` are refused before any I/O.
    /// No retry occurs: registration may commit before a response is lost.
    pub fn register_names(&self, genesis: Txid, block: ChainPoint) -> Result<NamesStatus, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        if block.height > i64::MAX as u64 {
            return Err(invalid("local Names registration height is out of range"));
        }
        let path = format!(
            "/v1/names/{genesis}/register?height={}&hash={}",
            block.height, block.hash
        );
        let (code, body) = self.names_request("POST", &path, deadline)?;
        if code != 200 {
            return Err(invalid(format!("local Names registration HTTP {code}")));
        }
        let status: NamesStatus = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        validate_names_status(&status, genesis)?;
        if status.genesis_block != block {
            return Err(invalid(
                "local Names genesis block differs from registration",
            ));
        }
        remaining(deadline)?;
        Ok(status)
    }

    /// Request exactly one local Names projection step. Returned outcomes are
    /// operator data, not cryptographic proofs or a promise of future state.
    /// HTTP 409 is `Error::Busy`; no automatic stepping, retry or readback occurs,
    /// including when a lost response leaves the operation's commit unknown.
    pub fn names_step(&self, genesis: Txid) -> Result<NamesStep, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) =
            self.names_request("POST", &format!("/v1/names/{genesis}/step"), deadline)?;
        if code != 200 {
            return Err(invalid(format!("local Names step HTTP {code}")));
        }
        let step: NamesStep = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        validate_names_status(&step.status, genesis)?;
        if step
            .applied
            .is_some_and(|point| point != step.status.projected)
        {
            return Err(invalid("local Names applied block differs from projection"));
        }
        remaining(deadline)?;
        Ok(step)
    }

    /// Read the configured operator's local Names progress. HTTP 404 means only
    /// that this registry is not registered locally, not global absence. Typed
    /// progress and completion are not independent chain evidence. HTTP 409 is
    /// `Error::Busy`; no registration, stepping or retry is performed.
    pub fn names_status(&self, genesis: Txid) -> Result<Option<NamesStatus>, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.names_request("GET", &format!("/v1/names/{genesis}"), deadline)?;
        match code {
            200 => {
                let status: NamesStatus = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                validate_names_status(&status, genesis)?;
                remaining(deadline)?;
                Ok(Some(status))
            }
            404 => {
                let _: serde_json::Value = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                Ok(None)
            }
            _ => Err(invalid(format!("local Names status HTTP {code}"))),
        }
    }

    /// Read a canonical name's resolution from the local operator. This is
    /// index data, not independent proof of ownership, coverage or future state.
    /// The DTO carries no returned name to compare with the request. HTTP 409 is
    /// `Error::Busy`; resolution never automatically steps or retries.
    pub fn names_resolve(&self, genesis: Txid, name: &Name) -> Result<NamesResolution, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let path = format!("/v1/names/{genesis}/resolve/{}", name.as_str());
        let (code, body) = self.names_request("GET", &path, deadline)?;
        if code != 200 {
            return Err(invalid(format!("local Names resolution HTTP {code}")));
        }
        let resolution: NamesResolution = serde_json::from_slice(&body)?;
        remaining(deadline)?;
        validate_names_status(&resolution.status, genesis)?;
        remaining(deadline)?;
        Ok(resolution)
    }

    fn names_request(
        &self,
        method: &str,
        path: &str,
        deadline: Instant,
    ) -> Result<(u16, Vec<u8>), Error> {
        let response = self.request(method, path, deadline)?;
        if response.0 == 409 {
            return Err(Error::Busy(
                "local Names operation busy or selected state changed".into(),
            ));
        }
        Ok(response)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        deadline: Instant,
    ) -> Result<(u16, Vec<u8>), Error> {
        let mut stream =
            TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT.min(remaining(deadline)?))?;
        let body_length = if method == "POST" {
            "Content-Length: 0\r\n"
        } else {
            ""
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n{body_length}Connection: close\r\n\r\n",
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

fn validate_names_status(status: &NamesStatus, genesis: Txid) -> Result<(), Error> {
    if status.genesis != genesis {
        return Err(invalid("local Names genesis differs from request"));
    }
    let tip = status
        .selected_tip
        .ok_or_else(|| invalid("local Names projection has no selected tip"))?;
    if status.projected.height < status.genesis_block.height || tip.height < status.projected.height
    {
        return Err(invalid("local Names projection heights are inconsistent"));
    }
    for (left, right) in [
        (status.genesis_block, status.projected),
        (status.projected, tip),
        (status.genesis_block, tip),
    ] {
        if left.height == right.height && left.hash != right.hash {
            return Err(invalid("local Names equal-height block hashes differ"));
        }
    }
    if status.complete_to_tip != (status.projected == tip) {
        return Err(invalid(
            "local Names completion differs from projection and tip",
        ));
    }
    Ok(())
}

fn validate_instance(instance: &str) -> Result<(), Error> {
    if instance.len() != 32 || !instance.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "local Wire snapshot instance must be 32 hex characters",
        ));
    }
    Ok(())
}

fn validate_wire_page(
    page: &WirePage,
    cursor: Option<&WireCursor>,
    limit: u32,
    deadline: Instant,
) -> Result<(), Error> {
    validate_instance(&page.snapshot.instance)?;
    if page.archive.api_version != crate::model::API_VERSION || page.records.len() > limit as usize
    {
        return Err(invalid(
            "local Wire page version or record count is invalid",
        ));
    }
    if cursor.is_some_and(|cursor| cursor.snapshot != page.snapshot) {
        return Err(invalid("local Wire page snapshot differs from cursor"));
    }
    let mut previous_coordinate = cursor.map(|cursor| (cursor.height, cursor.position));
    let mut previous_block = None;
    for record in &page.records {
        remaining(deadline)?;
        let entry = &record.entry;
        let coordinate = (entry.height, entry.position);
        if previous_coordinate.is_some_and(|previous| coordinate <= previous) {
            return Err(invalid(
                "local Wire entries are not strictly after the cursor/in order",
            ));
        }
        let start = page.archive.application_start;
        let tip = page
            .archive
            .selected_tip
            .ok_or_else(|| invalid("local Wire records require a selected tip"))?;
        if entry.height < start.height || entry.height > tip.height {
            return Err(invalid(
                "local Wire entry lies outside the application/selected range",
            ));
        }
        if (entry.height == start.height && record.block_hash != start.hash)
            || (entry.height == tip.height && record.block_hash != tip.hash)
            || previous_block
                .is_some_and(|(height, hash)| height == entry.height && hash != record.block_hash)
        {
            return Err(invalid(
                "local Wire block hashes disagree at the same height",
            ));
        }
        let txid = entry
            .txid
            .parse::<Txid>()
            .map_err(|_| invalid("local Wire entry has an invalid TXID"))?;
        let author = entry
            .author
            .parse::<bitcoin::XOnlyPublicKey>()
            .map_err(|_| invalid("local Wire entry has an invalid author"))?;
        if entry.record.len() > urma_core::format::Urma::MAX_PUBLIC_BYTES * 2 {
            return Err(invalid("local Wire record exceeds the public byte bound"));
        }
        let raw = hex::decode(&entry.record)
            .map_err(|_| invalid("local Wire entry has invalid record hex"))?;
        let parsed =
            urma_wire::index::entry_from_record(&raw, txid, author, entry.height, entry.position)
                .map_err(|error| invalid(format!("invalid local Wire record: {error}")))?;
        if parsed.is_none() {
            return Err(invalid("local Wire entry is not a Wire record kind"));
        }
        previous_coordinate = Some(coordinate);
        previous_block = Some((entry.height, record.block_hash));
    }
    if let Some(next) = &page.next {
        let last = page
            .records
            .last()
            .ok_or_else(|| invalid("empty local Wire page has a continuation"))?;
        if next.snapshot != page.snapshot
            || (next.height, next.position) != (last.entry.height, last.entry.position)
        {
            return Err(invalid(
                "local Wire continuation differs from the last entry/snapshot",
            ));
        }
    }
    Ok(())
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
