//! Small authenticated loopback control surface. The archive engine remains
//! usable directly; HTTP is not a prerequisite for embedded applications.
use crate::{Error, engine::Engine};
use rand::RngCore;
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct Service {
    listener: TcpListener,
    token: String,
    engine: Arc<Engine>,
    stop: Arc<AtomicBool>,
    sync_error: Arc<Mutex<Option<String>>>,
    names_error: Arc<Mutex<Option<String>>>,
    retention_error: Arc<Mutex<Option<String>>>,
    retention: Option<(PathBuf, urma_runtime::multipart::RecoveryLimits)>,
    sources: Vec<Arc<dyn crate::retrieval::RecordSource + Send + Sync>>,
}

impl Service {
    pub fn bind(address: SocketAddr, token: String, engine: Arc<Engine>) -> Result<Self, Error> {
        if !address.ip().is_loopback()
            || token.len() != 64
            || !token.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::Invalid(
                "service requires loopback and a 32-byte hexadecimal bearer token".into(),
            ));
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            token,
            engine,
            stop: Arc::new(AtomicBool::new(false)),
            sync_error: Arc::new(Mutex::new(None)),
            names_error: Arc::new(Mutex::new(None)),
            retention_error: Arc::new(Mutex::new(None)),
            retention: None,
            sources: Vec::new(),
        })
    }

    pub fn address(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
    }

    /// Explicit optional candidates for background object recovery. Merely
    /// configuring handles does not dial, fetch, change headers or scan coverage.
    pub fn with_record_sources(
        mut self,
        sources: Vec<Arc<dyn crate::retrieval::RecordSource + Send + Sync>>,
    ) -> Result<Self, Error> {
        if sources.len() > 1024 {
            return Err(Error::Invalid("too many configured record sources".into()));
        }
        self.sources = sources;
        Ok(self)
    }

    /// Configure bounded background object acquisition. The caller supplies an
    /// owned scratch directory and explicit limits. Only run(true) schedules it;
    /// pruned archives perform no automatic content acquisition.
    pub fn with_retention(
        mut self,
        scratch: PathBuf,
        limits: urma_runtime::multipart::RecoveryLimits,
    ) -> Result<Self, Error> {
        if limits.max_payload_bytes == 0 || limits.max_nodes == 0 || limits.timeout.is_zero() {
            return Err(Error::Invalid(
                "object retention limits must be nonzero".into(),
            ));
        }
        self.retention = Some((scratch, limits));
        Ok(self)
    }

    /// Run foreground. Network acquisition is opt-in; status works offline.
    pub fn run(self, synchronize: bool) -> Result<(), Error> {
        std::thread::scope(|scope| {
            if synchronize {
                scope.spawn(|| {
                    while !self.stop.load(Ordering::Acquire) {
                        let result = self
                            .engine
                            .synchronize_headers_until(&self.stop)
                            .and_then(|_| self.engine.scan_next_until(&self.stop))
                            .and_then(|status| {
                                if !self.stop.load(Ordering::Acquire) {
                                    self.engine.resolve_cached_dependency()?;
                                }
                                Ok(status)
                            });
                        if let Ok(mut error) = self.sync_error.lock() {
                            *error = result.err().map(|e| e.to_string());
                        }
                        // Registered projections can use already scanned data
                        // even if this round's acquisition failed. They never
                        // create registrations or acquire missing history.
                        if !self.stop.load(Ordering::Acquire) {
                            let result = self.engine.maintain_next_names(&self.stop);
                            if let Ok(mut error) = self.names_error.lock() {
                                *error = result.err().map(|e| e.to_string());
                            }
                        }
                        // Full-block audit always gets its opportunity before
                        // one object attempt. A sync failure does not suppress
                        // independent recovery from the last selected view;
                        // its error remains separately visible in status.
                        if !self.stop.load(Ordering::Acquire) {
                            if let Some((scratch, limits)) = &self.retention {
                                let sources: Vec<&dyn crate::retrieval::RecordSource> = self
                                    .sources
                                    .iter()
                                    .map(|source| {
                                        source.as_ref() as &dyn crate::retrieval::RecordSource
                                    })
                                    .collect();
                                let result = self
                                    .engine
                                    .retain_next_object(&sources, *limits, scratch, &self.stop);
                                if let Ok(mut error) = self.retention_error.lock() {
                                    *error = result.err().map(|e| e.to_string());
                                }
                            }
                        }
                        for _ in 0..20 {
                            if self.stop.load(Ordering::Acquire) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                });
            }
            let outcome = self.accept_loop();
            self.stop.store(true, Ordering::Release);
            outcome
        })
    }

    fn accept_loop(&self) -> Result<(), Error> {
        while !self.stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    // A malformed or disconnected client never stops the service.
                    let _ = self.request(&mut stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn request(&self, stream: &mut TcpStream) -> Result<(), Error> {
        let mut raw = Vec::new();
        let began = std::time::Instant::now();
        loop {
            if raw.len() == 8192 || began.elapsed() > Duration::from_secs(3) {
                return respond(stream, 400, json!({"error":"request header limit"}));
            }
            let mut byte = [0];
            if stream.read(&mut byte)? == 0 {
                return Ok(());
            }
            raw.push(byte[0]);
            if began.elapsed() > Duration::from_secs(3) {
                return respond(stream, 400, json!({"error":"request header deadline"}));
            }
            if raw.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let Ok(request) = std::str::from_utf8(&raw) else {
            return respond(stream, 400, json!({"error":"invalid header encoding"}));
        };
        let mut lines = request.split("\r\n");
        let first = lines.next().unwrap_or("");
        let mut authorized = false;
        let mut authorization_seen = false;
        for line in lines.filter(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                return respond(stream, 400, json!({"error":"malformed header"}));
            };
            if name.eq_ignore_ascii_case("authorization") {
                if authorization_seen {
                    return respond(stream, 400, json!({"error":"duplicate authorization"}));
                }
                authorization_seen = true;
                authorized = value
                    .trim()
                    .strip_prefix("Bearer ")
                    .is_some_and(|value| equal_token(value, &self.token));
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
            {
                return respond(
                    stream,
                    400,
                    json!({"error":"this control endpoint accepts no request body"}),
                );
            }
        }
        if !authorized {
            return respond(stream, 401, json!({"error":"authentication required"}));
        }
        match first {
            line if (line.starts_with("GET /v1/names/") || line.starts_with("POST /v1/names/"))
                && line.ends_with(" HTTP/1.1") =>
            {
                let (method, path) = line[..line.len() - " HTTP/1.1".len()]
                    .split_once(' ')
                    .expect("matched HTTP method");
                let request = match names_request(method, path) {
                    Ok(Some(request)) => request,
                    Ok(None) => {
                        return respond(stream, 404, json!({"error":"unknown endpoint"}));
                    }
                    Err(_) => {
                        return respond(stream, 400, json!({"error":"invalid Names request"}));
                    }
                };
                // Reads never register or advance a registry. Mutations are
                // explicit one-shot commands under the Engine archive mutex.
                let result = match request {
                    NamesRequest::Status(genesis) => match self.engine.names_status(genesis) {
                        Ok(Some(status)) => serde_json::to_value(status).map_err(Error::from),
                        Ok(None) => {
                            return respond(
                                stream,
                                404,
                                json!({"error":"Names registry is not registered locally"}),
                            );
                        }
                        Err(error) => Err(error),
                    },
                    NamesRequest::Resolve(genesis, name) => self
                        .engine
                        .names_resolve(genesis, &name)
                        .and_then(|value| serde_json::to_value(value).map_err(Error::from)),
                    NamesRequest::Register(genesis, point) => self
                        .engine
                        .register_names(genesis, point)
                        .and_then(|value| serde_json::to_value(value).map_err(Error::from)),
                    NamesRequest::Step(genesis) => self
                        .engine
                        .names_step(genesis)
                        .and_then(|value| serde_json::to_value(value).map_err(Error::from)),
                    NamesRequest::View(genesis, limit, cursor) => self
                        .engine
                        .names_view(genesis, cursor.as_ref(), limit)
                        .and_then(|value| serde_json::to_value(value).map_err(Error::from)),
                };
                match result {
                    Ok(value) => respond(stream, 200, value),
                    Err(error) => control_error(stream, error),
                }
            }
            line if line.starts_with("GET /v1/wire?") && line.ends_with(" HTTP/1.1") => {
                let query = &line["GET /v1/wire?".len()..line.len() - " HTTP/1.1".len()];
                let (limit, cursor) = match wire_query(query) {
                    Ok(value) => value,
                    Err(_) => {
                        return respond(stream, 400, json!({"error":"invalid Wire page query"}));
                    }
                };
                match self.engine.wire_page(cursor.as_ref(), limit) {
                    Ok(page) => respond(stream, 200, serde_json::to_value(page)?),
                    Err(error) => control_error(stream, error),
                }
            }
            "POST /v1/cache/prune HTTP/1.1" => match self.engine.prune_cache() {
                Ok(records_removed) => respond(
                    stream,
                    200,
                    serde_json::to_value(crate::model::PruneReceipt { records_removed })?,
                ),
                Err(error) => control_error(stream, error),
            },
            line if line.starts_with("POST /v1/objects/") && line.ends_with(" HTTP/1.1") => {
                let path = &line["POST /v1/objects/".len()..line.len() - " HTTP/1.1".len()];
                let (id, pin) = match path.rsplit_once('/') {
                    Some((id, "pin")) => (id, true),
                    Some((id, "unpin")) => (id, false),
                    _ => return respond(stream, 404, json!({"error":"unknown endpoint"})),
                };
                if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return respond(stream, 400, json!({"error":"invalid root transaction ID"}));
                }
                let root = id
                    .parse()
                    .map_err(|e| Error::Invalid(format!("TXID: {e}")))?;
                // Engine serializes validation and mutation with pruning/reorg.
                // The acknowledgement describes this operation's commit point;
                // a lost response must not be treated as proof of no mutation.
                match self.engine.set_pin(root, pin) {
                    Ok(()) => respond(
                        stream,
                        200,
                        serde_json::to_value(crate::model::PinReceipt { root, pinned: pin })?,
                    ),
                    Err(error) => control_error(stream, error),
                }
            }
            line if line.starts_with("GET /v1/objects/") && line.ends_with(" HTTP/1.1") => {
                let id = &line["GET /v1/objects/".len()..line.len() - " HTTP/1.1".len()];
                if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return respond(stream, 400, json!({"error":"invalid root transaction ID"}));
                }
                let root = id
                    .parse()
                    .map_err(|e| Error::Invalid(format!("TXID: {e}")))?;
                match self.engine.object_status(root)? {
                    Some(status) => respond(stream, 200, serde_json::to_value(status)?),
                    None => respond(
                        stream,
                        404,
                        json!({"error":"no completed object recorded locally"}),
                    ),
                }
            }
            line if line.starts_with("GET /v1/records/") && line.ends_with(" HTTP/1.1") => {
                let id = &line["GET /v1/records/".len()..line.len() - " HTTP/1.1".len()];
                if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return respond(stream, 400, json!({"error":"invalid transaction ID"}));
                }
                let txid = id
                    .parse()
                    .map_err(|e| Error::Invalid(format!("TXID: {e}")))?;
                match self.engine.record(txid)? {
                    Some(record) => respond(stream, 200, serde_json::to_value(record)?),
                    None => respond(
                        stream,
                        404,
                        json!({"error":"record is not locally available in the selected view"}),
                    ),
                }
            }
            "GET /v1/status HTTP/1.1" => {
                let status = self.engine.status()?;
                let error = self
                    .sync_error
                    .lock()
                    .map_err(|_| Error::Invalid("sync status poisoned".into()))?
                    .clone();
                let retention_error = self
                    .retention_error
                    .lock()
                    .map_err(|_| Error::Invalid("retention status poisoned".into()))?
                    .clone();
                let names_error = self
                    .names_error
                    .lock()
                    .map_err(|_| Error::Invalid("Names status poisoned".into()))?
                    .clone();
                respond(
                    stream,
                    200,
                    json!({"archive":status,"last_sync_error":error,"last_retention_error":retention_error,
                        "last_names_error":names_error,
                        "retention_configured":self.retention.is_some(),
                        "record_sources_configured":self.sources.len(),
                        "capabilities":["status","header-sync","full-block-scan","record-read","object-status","object-pin","cache-prune","wire-index","names-index"]}),
                )
            }
            "POST /v1/shutdown HTTP/1.1" => {
                respond(stream, 200, json!({"stopping":true}))?;
                self.stop.store(true, Ordering::Release);
                Ok(())
            }
            _ => respond(stream, 404, json!({"error":"unknown endpoint"})),
        }
    }
}

enum NamesRequest {
    Status(bitcoin::Txid),
    Resolve(bitcoin::Txid, urma_names::name::Name),
    Register(bitcoin::Txid, crate::model::ChainPoint),
    Step(bitcoin::Txid),
    View(bitcoin::Txid, u32, Option<crate::names::NamesCursor>),
}

fn names_request(method: &str, path: &str) -> Result<Option<NamesRequest>, Error> {
    let invalid = || Error::Invalid("invalid Names request".into());
    let path = path.strip_prefix("/v1/names/").ok_or_else(invalid)?;
    let (id, operation) = path.split_once('/').unwrap_or((path, ""));
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let genesis = id.parse().map_err(|_| invalid())?;
    let request = match (method, operation) {
        ("GET", "") => NamesRequest::Status(genesis),
        ("GET", operation) if operation.starts_with("view?") => {
            let (limit, cursor) = names_view_query(&operation["view?".len()..])?;
            if cursor.as_ref().is_some_and(|c| c.genesis != genesis) {
                return Err(invalid());
            }
            NamesRequest::View(genesis, limit, cursor)
        }
        ("GET", operation) if operation.starts_with("resolve/") => {
            // Canonical Names V0 uses only ASCII letters, digits and hyphens;
            // do not normalize, percent-decode or accept alternate spellings.
            let name = urma_names::name::Name::parse(&operation["resolve/".len()..])
                .map_err(|_| invalid())?;
            NamesRequest::Resolve(genesis, name)
        }
        ("POST", "step") => NamesRequest::Step(genesis),
        ("POST", operation) if operation.starts_with("register?") => {
            let mut height = None;
            let mut hash = None;
            for field in operation["register?".len()..].split('&') {
                match field.split_once('=') {
                    Some(("height", value)) if height.is_none() => {
                        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                            return Err(invalid());
                        }
                        let value: u64 = value.parse().map_err(|_| invalid())?;
                        if value > i64::MAX as u64 {
                            return Err(invalid());
                        }
                        height = Some(value);
                    }
                    Some(("hash", value)) if hash.is_none() => {
                        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(invalid());
                        }
                        hash = Some(value.parse().map_err(|_| invalid())?);
                    }
                    _ => return Err(invalid()),
                }
            }
            NamesRequest::Register(
                genesis,
                crate::model::ChainPoint {
                    height: height.ok_or_else(invalid)?,
                    hash: hash.ok_or_else(invalid)?,
                },
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn names_view_query(query: &str) -> Result<(u32, Option<crate::names::NamesCursor>), Error> {
    let invalid = || Error::Invalid("invalid Names view query".into());
    let mut limit = None;
    let mut cursor = None;
    for field in query.split('&') {
        match field.split_once('=') {
            Some(("limit", value)) if limit.is_none() => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let value: u32 = value.parse().map_err(|_| invalid())?;
                if !(1..=crate::names::MAX_NAMES_PAGE).contains(&value) {
                    return Err(invalid());
                }
                limit = Some(value);
            }
            Some(("cursor", value)) if cursor.is_none() => {
                if value.len() > 1024 {
                    return Err(invalid());
                }
                let bytes = hex::decode(value).map_err(|_| invalid())?;
                let decoded: crate::names::NamesCursor = serde_json::from_slice(&bytes)?;
                if decoded.snapshot.instance.len() != 32
                    || !decoded
                        .snapshot
                        .instance
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                {
                    return Err(invalid());
                }
                cursor = Some(decoded);
            }
            _ => return Err(invalid()),
        }
    }
    Ok((limit.ok_or_else(invalid)?, cursor))
}

fn wire_query(query: &str) -> Result<(u32, Option<crate::projection::WireCursor>), Error> {
    let invalid = || Error::Invalid("invalid Wire page query".into());
    let mut limit = None;
    let mut cursor = None;
    for field in query.split('&') {
        match field.split_once('=') {
            Some(("limit", value)) if limit.is_none() => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let value: u32 = value.parse().map_err(|_| invalid())?;
                if !(1..=crate::projection::MAX_WIRE_PAGE).contains(&value) {
                    return Err(invalid());
                }
                limit = Some(value);
            }
            Some(("cursor", value)) if cursor.is_none() => {
                if value.len() > 1024 {
                    return Err(invalid());
                }
                let bytes = hex::decode(value).map_err(|_| invalid())?;
                let decoded: crate::projection::WireCursor = serde_json::from_slice(&bytes)?;
                if decoded.snapshot.instance.len() != 32
                    || !decoded
                        .snapshot
                        .instance
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                    || decoded.height > i64::MAX as u64
                {
                    return Err(invalid());
                }
                cursor = Some(decoded);
            }
            _ => return Err(invalid()),
        }
    }
    Ok((limit.ok_or_else(invalid)?, cursor))
}

fn control_error(stream: &mut TcpStream, error: Error) -> Result<(), Error> {
    match error {
        Error::Invalid(message) => respond(stream, 422, json!({"error":message})),
        error @ (Error::Busy(_) | Error::Stale) => {
            respond(stream, 409, json!({"error":error.to_string()}))
        }
        // Do not expose database internals or local filesystem paths over HTTP.
        _ => respond(
            stream,
            500,
            json!({"error":"local archive operation failed"}),
        ),
    }
}

fn equal_token(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |different, (a, b)| different | (a ^ b))
        == 0
}

fn respond(stream: &mut TcpStream, code: u16, body: serde_json::Value) -> Result<(), Error> {
    let body = serde_json::to_vec(&body)?;
    if body.len() > 32 * 1024 * 1024 {
        return respond(
            stream,
            413,
            json!({"error":"record exceeds local API response limit"}),
        );
    }
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        500 => "Internal Server Error",
        _ => "Not Found",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

/// New service token, never a wallet/signing/decryption key. Existing files
/// are not overwritten. Platform-specific private ACL support is required.
pub fn create_token(path: &Path) -> Result<(), Error> {
    #[cfg(not(unix))]
    return Err(Error::Invalid(
        "private token ACL creation is not implemented for this platform".into(),
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex::encode(bytes).as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}
