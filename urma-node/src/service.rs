//! Small authenticated loopback control surface. The archive engine remains
//! usable directly; HTTP is not a prerequisite for embedded applications.
use crate::{Error, engine::Engine};
use rand::RngCore;
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
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
        })
    }

    pub fn address(&self) -> Result<SocketAddr, Error> {
        Ok(self.listener.local_addr()?)
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
                respond(
                    stream,
                    200,
                    json!({"archive":status,"last_sync_error":error,"capabilities":["status","header-sync","full-block-scan","record-read"]}),
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
        413 => "Content Too Large",
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
