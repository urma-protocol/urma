use crate::config;
use crate::endpoints::{ElectrumTarget, PublicEndpoint, Wire};
use crate::error::{Context, Error, ensure};
use crate::pinning::{Pinned, Pins};
use crate::transport::{BlockEncoding, Evidence, Provider};
use bitcoin::{
    BlockHash, Txid,
    block::Header,
    consensus::deserialize,
    hashes::{Hash, sha256},
};
use rustls::{ClientConfig, ClientConnection, ServerName, StreamOwned};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use urma_chain::{decode as chain_decode, observation::Chain};

enum Stream {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Stream {
    fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(socket) => socket,
            Self::Tls(stream) => &stream.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(socket) => socket.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(socket) => socket.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(socket) => socket.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

struct Session {
    stream: BufReader<Stream>,
    next_id: u64,
    unspent: HashMap<String, (Instant, Vec<Value>)>,
}

impl Session {
    fn open(target: &ElectrumTarget, pins: &Arc<Pins>) -> Result<Self, Error> {
        let socket = connect(target)?;
        let stream = match target.wire {
            Wire::PlainTcp => {
                tracing::warn!(host = %target.host, port = target.port, "electrum endpoint explicitly configured without TLS");
                Stream::Plain(socket)
            }
            Wire::Tls => {
                let verifier = Pinned {
                    pins: pins.clone(),
                    key: format!("{}_{}", target.host, target.port),
                };
                let tls = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth();
                let name = ServerName::try_from(target.host.as_str())
                    .map_err(|cause| Error::Invalid(format!("electrum host name: {cause}")))?;
                let connection = ClientConnection::new(Arc::new(tls), name)?;
                Stream::Tls(StreamOwned::new(connection, socket))
            }
        };
        Ok(Self {
            stream: BufReader::new(stream),
            next_id: 1,
            unspent: HashMap::new(),
        })
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, Error> {
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .context("electrum request counter overflow")?;
        let socket = self.stream.get_ref().socket();
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        let mut line =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        line.push(b'\n');
        let stream = self.stream.get_mut();
        stream.write_all(&line)?;
        stream.flush()?;
        loop {
            let reply = self.read_line()?;
            if reply["id"] != json!(id) {
                tracing::debug!(method = %reply["method"], "skipping electrum notification");
                continue;
            }
            if !reply["error"].is_null() {
                return Err(server_error(method, &reply["error"]));
            }
            return Ok(reply
                .get("result")
                .context("electrum reply omitted result")?
                .clone());
        }
    }

    fn read_line(&mut self) -> Result<Value, Error> {
        let mut buffer = Vec::new();
        let limit = config::ELECTRUM_MAX_LINE_BYTES;
        let bound = u64::try_from(limit)?
            .checked_add(1)
            .context("line bound overflow")?;
        let count = (&mut self.stream)
            .take(bound)
            .read_until(b'\n', &mut buffer)?;
        if count == 0 {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "electrum server closed the connection",
            )));
        }
        ensure!(buffer.len() <= limit, "electrum reply exceeds capacity");
        ensure!(
            buffer.last() == Some(&b'\n'),
            "electrum reply was truncated"
        );
        Ok(serde_json::from_slice(&buffer)?)
    }
}

fn connect(target: &ElectrumTarget) -> Result<TcpStream, Error> {
    let mut last = Error::Missing(format!("{} resolved to no address", target.host));
    for address in (target.host.as_str(), target.port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, config::ELECTRUM_CONNECT_TIMEOUT) {
            Ok(socket) => {
                socket.set_nodelay(true)?;
                return Ok(socket);
            }
            Err(error) => {
                tracing::warn!(%address, %error, "electrum address unreachable");
                last = Error::Io(error);
            }
        }
    }
    Err(last)
}

fn server_error(method: &str, error: &Value) -> Error {
    let message = error["message"].to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("no such mempool or blockchain transaction")
        || lowered.contains("not found")
    {
        return Error::Missing(config::ABSENT_TRANSACTION.into());
    }
    Error::Unsupported(format!("electrum {method} failed: {message}"))
}

enum Link {
    Closed,
    Open(Session),
}

pub struct Electrum {
    endpoint: PublicEndpoint,
    target: ElectrumTarget,
    pins: Arc<Pins>,
    link: Mutex<Link>,
    seen: Mutex<HashMap<BlockHash, u64>>,
}

impl Electrum {
    pub fn new(endpoint: PublicEndpoint, pins: Arc<Pins>) -> Result<Self, Error> {
        let target = endpoint.electrum_target()?;
        Ok(Self {
            endpoint,
            target,
            pins,
            link: Mutex::new(Link::Closed),
            seen: Mutex::new(HashMap::new()),
        })
    }

    fn session<T>(
        &self,
        chain: Chain,
        work: impl Fn(&mut Session) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut link = match self.link.lock() {
            Ok(link) => link,
            Err(poisoned) => {
                tracing::error!(endpoint = %self.endpoint.url(), "electrum link lock poisoned");
                poisoned.into_inner()
            }
        };
        let mut fresh = false;
        loop {
            if matches!(*link, Link::Closed) {
                let mut session = Session::open(&self.target, &self.pins)?;
                match self.handshake(&mut session, chain) {
                    Ok(()) => *link = Link::Open(session),
                    Err(error) => {
                        tracing::warn!(endpoint = %self.endpoint.url(), %error, "electrum handshake failed");
                        return Err(error);
                    }
                }
                fresh = true;
            }
            let Link::Open(session) = &mut *link else {
                return Err(Error::Invalid("electrum link closed during request".into()));
            };
            match work(session) {
                Ok(value) => return Ok(value),
                Err(Error::Io(cause)) if fresh => {
                    tracing::warn!(endpoint = %self.endpoint.url(), error = %cause, "electrum connection dropped on a fresh session");
                    *link = Link::Closed;
                    return Err(Error::Io(cause));
                }
                Err(Error::Io(cause)) => {
                    tracing::warn!(endpoint = %self.endpoint.url(), error = %cause, "electrum connection dropped; reconnecting and retrying once");
                    *link = Link::Closed;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn handshake(&self, session: &mut Session, chain: Chain) -> Result<(), Error> {
        let timeout = config::method_timeout("getblockchaininfo");
        let version = session.request(
            "server.version",
            json!(["urma/0.2", config::ELECTRUM_PROTOCOL]),
            timeout,
        )?;
        ensure!(
            version[1] == json!(config::ELECTRUM_PROTOCOL),
            "electrum server negotiated protocol {} instead of {}",
            version[1],
            config::ELECTRUM_PROTOCOL
        );
        let genesis =
            header_hash(&session.request("blockchain.block.header", json!([0]), timeout)?)?;
        ensure!(
            genesis == chain.genesis()?.0,
            "electrum server genesis does not match {}",
            chain.label()
        );
        tracing::debug!(endpoint = %self.endpoint.url(), server = %version[0], "electrum session verified");
        Ok(())
    }

    fn remember(&self, hash: BlockHash, height: u64) {
        match self.seen.lock() {
            Ok(mut seen) => {
                seen.insert(hash, height);
            }
            Err(poisoned) => {
                tracing::error!(endpoint = %self.endpoint.url(), "electrum header table lock poisoned");
                poisoned.into_inner().insert(hash, height);
            }
        }
    }

    fn seen_height(&self, hash: BlockHash) -> Result<u64, Error> {
        let seen = match self.seen.lock() {
            Ok(seen) => seen,
            Err(poisoned) => {
                tracing::error!(endpoint = %self.endpoint.url(), "electrum header table lock poisoned");
                poisoned.into_inner()
            }
        };
        match seen.get(&hash) {
            Some(height) => Ok(*height),
            None => Err(Error::Unsupported(format!(
                "electrum server has not served block {hash} to this session"
            ))),
        }
    }

    fn tip(&self, session: &mut Session) -> Result<(u64, BlockHash), Error> {
        let timeout = config::method_timeout("getblockchaininfo");
        let tip = session.request("blockchain.headers.subscribe", json!([]), timeout)?;
        let height = tip["height"]
            .as_u64()
            .context("electrum tip height missing")?;
        let hash = header_hash(&tip["hex"])?;
        self.remember(hash, height);
        Ok((height, hash))
    }

    fn block_hash(&self, session: &mut Session, height: u64) -> Result<BlockHash, Error> {
        let timeout = config::method_timeout("getblockhash");
        let header = session.request("blockchain.block.header", json!([height]), timeout)?;
        let hash = header_hash(&header)?;
        self.remember(hash, height);
        Ok(hash)
    }

    fn raw_transaction(&self, session: &mut Session, txid: &Txid) -> Result<String, Error> {
        let timeout = config::method_timeout("getrawtransaction");
        let raw = session.request("blockchain.transaction.get", json!([txid]), timeout)?;
        Ok(raw
            .as_str()
            .context("electrum transaction bytes missing")?
            .to_owned())
    }

    fn verbose_transaction(&self, session: &mut Session, txid: &Txid) -> Result<Value, Error> {
        let timeout = config::method_timeout("getrawtransaction");
        let verbose =
            session.request("blockchain.transaction.get", json!([txid, true]), timeout)?;
        let confirmations = config::confirmations(&verbose)?;
        if confirmations <= 0 {
            return Ok(json!({"confirmations":0}));
        }
        let hash: BlockHash = verbose["blockhash"]
            .as_str()
            .context("electrum inclusion block missing")?
            .parse()?;
        let (tip, _) = self.tip(session)?;
        let depth = u64::try_from(confirmations)?;
        let height = tip
            .checked_add(1)
            .and_then(|next| next.checked_sub(depth))
            .context("electrum confirmations exceed tip height")?;
        ensure!(
            self.block_hash(session, height)? == hash,
            "electrum inclusion block disagrees with its header chain"
        );
        Ok(json!({"confirmations":confirmations,"blockhash":hash}))
    }

    fn listunspent(
        &self,
        session: &mut Session,
        script: &bitcoin::Script,
    ) -> Result<Vec<Value>, Error> {
        let key = scripthash(script);
        let now = Instant::now();
        let cached = session.unspent.get(&key);
        for (fetched, rows) in cached.iter() {
            if now.duration_since(*fetched) < config::ELECTRUM_UNSPENT_CACHE {
                tracing::debug!(endpoint = %self.endpoint.url(), rows = rows.len(), "unspent list served from the session cache");
                return Ok(rows.clone());
            }
        }
        let timeout = config::method_timeout("addressutxos");
        let rows = session.request("blockchain.scripthash.listunspent", json!([key]), timeout)?;
        let rows = rows.as_array().context("electrum unspent list missing")?;
        ensure!(
            rows.len() <= config::SOURCE_MAX_UTXOS,
            "UTXO client capacity exceeded"
        );
        session.unspent.insert(key, (now, rows.clone()));
        Ok(rows.clone())
    }

    fn address_utxos(
        &self,
        session: &mut Session,
        chain: Chain,
        address: &str,
    ) -> Result<Value, Error> {
        let script = urma_wallet::address::destination_script(address, chain)?;
        let mut outputs = Vec::new();
        for row in self.listunspent(session, &script)? {
            let height = row["height"]
                .as_u64()
                .context("electrum unspent height missing")?;
            outputs.push(json!({
                "txid": row["tx_hash"],
                "vout": row["tx_pos"],
                "value": row["value"],
                "status": {"confirmed": height > 0, "block_height": height},
            }));
        }
        Ok(Value::Array(outputs))
    }

    fn txout(&self, session: &mut Session, chain: Chain, args: &[Value]) -> Result<Value, Error> {
        let txid: Txid = args
            .first()
            .context("missing txid")?
            .as_str()
            .context("invalid txid")?
            .parse()?;
        let vout = args
            .get(1)
            .context("missing vout")?
            .as_u64()
            .context("invalid vout")?;
        let raw = self.raw_transaction(session, &txid)?;
        let transaction = chain_decode::transaction(&hex::decode(raw)?, chain)?;
        ensure!(
            transaction.compute_txid() == txid,
            "electrum transaction hash mismatch"
        );
        let output = transaction
            .output
            .get(usize::try_from(vout)?)
            .context("transaction output index out of range")?;
        let mut unspent = None;
        for row in self.listunspent(session, &output.script_pubkey)? {
            if row["tx_hash"] == json!(txid) && row["tx_pos"] == json!(vout) {
                unspent = Some(row);
            }
        }
        let Some(row) = unspent else {
            return Ok(Value::Null);
        };
        let height = row["height"]
            .as_u64()
            .context("electrum unspent height missing")?;
        let confirmations = if height > 0 {
            let (tip, _) = self.tip(session)?;
            tip.checked_sub(height)
                .and_then(|n| n.checked_add(1))
                .context("chain changed during output lookup")?
        } else {
            0
        };
        Ok(json!({
            "confirmations": confirmations,
            "coinbase": transaction.is_coinbase(),
            "value": serde_json::from_str::<Value>(&output.value.to_string_in(bitcoin::Denomination::Bitcoin))?,
            "scriptPubKey": {"hex": hex::encode(output.script_pubkey.as_bytes())},
        }))
    }

    fn dispatch(
        &self,
        session: &mut Session,
        chain: Chain,
        method: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        match method {
            "getblockchaininfo" => {
                let (height, hash) = self.tip(session)?;
                Ok(json!({"blocks":height,"bestblockhash":hash,"initialblockdownload":false}))
            }
            "getblockhash" => {
                let height = args
                    .first()
                    .context("missing block height")?
                    .as_u64()
                    .context("invalid block height")?;
                Ok(json!(self.block_hash(session, height)?))
            }
            "getblockheader" => {
                let hash: BlockHash = args
                    .first()
                    .context("missing block hash")?
                    .as_str()
                    .context("invalid block hash")?
                    .parse()?;
                let height = self.seen_height(hash)?;
                Ok(json!({"hash":hash,"height":height}))
            }
            "getrawtransaction" => {
                let txid: Txid = args
                    .first()
                    .context("missing txid")?
                    .as_str()
                    .context("invalid txid")?
                    .parse()?;
                if args.get(1).context("missing transaction verbosity")? == &json!(true) {
                    return self.verbose_transaction(session, &txid);
                }
                Ok(json!(self.raw_transaction(session, &txid)?))
            }
            "gettxout" => self.txout(session, chain, args),
            "addressutxos" => {
                let address = args
                    .first()
                    .context("missing address")?
                    .as_str()
                    .context("invalid address")?;
                self.address_utxos(session, chain, address)
            }
            "sendrawtransaction" => {
                let raw = args.first().context("missing broadcast transaction")?;
                let timeout = config::method_timeout(method);
                session.unspent.clear();
                session.request("blockchain.transaction.broadcast", json!([raw]), timeout)
            }
            other => Err(Error::Unsupported(format!(
                "electrum servers do not serve {other}"
            ))),
        }
    }
}

impl Electrum {
    pub fn probe(&self, chain: Chain, method: &str, params: Value) -> Result<Value, Error> {
        ensure!(
            config::ELECTRUM_PROBE_METHODS.contains(&method),
            "{method} is not a read-only electrum probe"
        );
        let timeout = config::method_timeout("addressutxos");
        self.session(chain, |session| {
            session.request(method, params.clone(), timeout)
        })
    }
}

impl Provider for Electrum {
    fn label(&self) -> String {
        self.endpoint.url().to_owned()
    }

    fn evidence(&self) -> Evidence {
        Evidence::PublicProviderObservation
    }

    fn block_encoding(&self) -> BlockEncoding {
        BlockEncoding::Core
    }

    fn supports(&self, method: &str) -> bool {
        !matches!(method, "getblock" | "getrawmempool" | "testmempoolaccept")
    }

    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        self.session(chain, |session| self.dispatch(session, chain, method, args))
    }
}

fn header_hash(value: &Value) -> Result<BlockHash, Error> {
    let bytes = hex::decode(value.as_str().context("electrum header bytes missing")?)?;
    ensure!(bytes.len() == 80, "electrum header is not 80 bytes");
    let header: Header = deserialize(&bytes)?;
    Ok(header.block_hash())
}

fn scripthash(script: &bitcoin::Script) -> String {
    let mut digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    digest.reverse();
    hex::encode(digest)
}
