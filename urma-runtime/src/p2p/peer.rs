use crate::config::{
    P2P_BLOCK_PEER_TIMEOUT_SECS, P2P_CONNECT_TIMEOUT_SECS, P2P_HANDSHAKE_TIMEOUT_SECS,
    P2P_HEADERS_TIMEOUT_SECS, P2P_HEIGHT_SLACK, P2P_PIPELINE_PER_PEER, P2P_POLL_MESSAGES,
    P2P_POLL_READ_TIMEOUT_MILLIS, P2P_PROTOCOL_VERSION, P2P_READ_TIMEOUT_SECS, P2P_USER_AGENT,
};
use crate::error::{Context, Error, ensure};
use crate::p2p::wire::{self, Message};
use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urma_chain::observation::Chain;

pub struct Peer {
    stream: TcpStream,
    magic: [u8; 4],
    pub address: SocketAddr,
    pub services: ServiceFlags,
    pub start_height: u64,
    pub learned: Vec<Gossiped>,
    pub version: Option<VersionMessage>,
    pub(super) proven_height: Option<u64>,
    pub(super) arrived: Vec<Vec<u8>>,
    pub(super) lacking: Vec<BlockHash>,
    requested: Vec<BlockHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gossiped {
    pub address: SocketAddr,
    pub time: u32,
}

enum Waited<T> {
    Done(T),
    Keep,
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub services: ServiceFlags,
    pub user_agent: String,
    pub relay: bool,
    pub negotiate: bool,
}

impl Hello {
    pub fn light() -> Self {
        Self {
            services: ServiceFlags::NONE,
            user_agent: P2P_USER_AGENT.to_owned(),
            relay: false,
            negotiate: false,
        }
    }
}

impl Peer {
    pub fn connect(chain: Chain, address: SocketAddr, our_height: u64) -> Result<Self, Error> {
        Self::connect_with(chain, address, our_height, &Hello::light())
    }

    pub fn connect_with(
        chain: Chain,
        address: SocketAddr,
        our_height: u64,
        hello: &Hello,
    ) -> Result<Self, Error> {
        let stream =
            TcpStream::connect_timeout(&address, Duration::from_secs(P2P_CONNECT_TIMEOUT_SECS))?;
        stream.set_read_timeout(Some(Duration::from_secs(P2P_READ_TIMEOUT_SECS)))?;
        stream.set_write_timeout(Some(Duration::from_secs(P2P_READ_TIMEOUT_SECS)))?;
        stream.set_nodelay(true)?;
        let mut peer = Self {
            stream,
            magic: chain.params().magic,
            address,
            services: ServiceFlags::NONE,
            start_height: 0,
            learned: Vec::new(),
            version: None,
            proven_height: None,
            arrived: Vec::new(),
            lacking: Vec::new(),
            requested: Vec::new(),
        };
        peer.handshake(our_height, hello)?;
        Ok(peer)
    }

    fn handshake(&mut self, our_height: u64, hello: &Hello) -> Result<(), Error> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                Error::Invalid(format!("system clock precedes the unix epoch: {error}"))
            })?;
        let now = i64::try_from(elapsed.as_secs())?;
        let mut version = VersionMessage::new(
            hello.services,
            now,
            Address::new(&self.address, ServiceFlags::NONE),
            Address::new(&"0.0.0.0:0".parse::<SocketAddr>()?, hello.services),
            rand::random(),
            hello.user_agent.clone(),
            i32::try_from(our_height)?,
        );
        version.version = P2P_PROTOCOL_VERSION;
        version.relay = hello.relay;
        self.send(NetworkMessage::Version(version))?;
        let deadline = Instant::now() + Duration::from_secs(P2P_HANDSHAKE_TIMEOUT_SECS);
        let mut versioned = false;
        let mut acknowledged = false;
        while !(versioned && acknowledged) {
            ensure!(Instant::now() < deadline, "peer handshake timed out");
            match self.receive()? {
                Message::Version(theirs) => {
                    ensure!(!versioned, "peer sent version twice");
                    ensure!(
                        theirs.services.has(ServiceFlags::WITNESS)
                            && (theirs.services.has(ServiceFlags::NETWORK)
                                || theirs.services.has(ServiceFlags::NETWORK_LIMITED)),
                        "peer {} lacks block and witness service bits",
                        self.address
                    );
                    self.services = theirs.services;
                    self.start_height = u64::try_from(theirs.start_height.max(0))?;
                    self.version = Some(theirs);
                    if hello.negotiate {
                        self.send(NetworkMessage::WtxidRelay)?;
                        self.send(NetworkMessage::SendAddrV2)?;
                    }
                    self.send(NetworkMessage::Verack)?;
                    versioned = true;
                }
                Message::Verack => acknowledged = true,
                other => self.absorb(other)?,
            }
        }
        if hello.negotiate {
            self.send(NetworkMessage::SendHeaders)?;
        }
        self.send(NetworkMessage::GetAddr)?;
        Ok(())
    }

    pub(super) fn height_hint(&self, tip: u64) -> u64 {
        match self.proven_height {
            None => self.start_height.min(tip + P2P_HEIGHT_SLACK),
            Some(proven) => proven.max(self.start_height.min(tip)),
        }
    }

    pub(super) fn limited(&self) -> bool {
        !self.services.has(ServiceFlags::NETWORK)
    }

    fn send(&mut self, payload: NetworkMessage) -> Result<(), Error> {
        tracing::trace!(peer = %self.address, command = payload.cmd(), "p2p send");
        wire::send(&mut self.stream, self.magic, payload)
    }

    pub fn receive(&mut self) -> Result<Message, Error> {
        let received = wire::receive(&mut self.stream, self.magic);
        match &received {
            Ok(message) => {
                tracing::trace!(peer = %self.address, command = %message.command(), "p2p receive")
            }
            Err(error) => tracing::trace!(peer = %self.address, %error, "p2p receive failed"),
        }
        received
    }

    pub(super) fn poll(&mut self) -> Result<(), Error> {
        let mut byte = [0u8; 1];
        for _round in 0..P2P_POLL_MESSAGES {
            self.stream.set_nonblocking(true)?;
            let peeked = self.stream.peek(&mut byte);
            self.stream.set_nonblocking(false)?;
            match peeked {
                Ok(0) => return Err(Error::Io(ErrorKind::UnexpectedEof.into())),
                Ok(_waiting) => {
                    self.stream.set_read_timeout(Some(Duration::from_millis(
                        P2P_POLL_READ_TIMEOUT_MILLIS,
                    )))?;
                    let message = self.receive();
                    self.stream
                        .set_read_timeout(Some(Duration::from_secs(P2P_READ_TIMEOUT_SECS)))?;
                    self.absorb(message?)?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn absorb_next(&mut self) -> Result<(), Error> {
        let message = self.receive()?;
        self.absorb(message)
    }

    pub fn absorb(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::Ping(nonce) => self.send(NetworkMessage::Pong(nonce)),
            Message::Addr(rows) => {
                for (time, address) in rows {
                    self.learn(address.socket_addr(), address.services, time);
                }
                Ok(())
            }
            Message::AddrV2(rows) => {
                for row in rows {
                    self.learn(row.socket_addr(), row.services, row.time);
                }
                Ok(())
            }
            Message::Version(_version) => Err(Error::Invalid("peer repeated its version".into())),
            Message::Headers(rows) => {
                tracing::debug!(peer = %self.address, count = rows.len(), "unsolicited headers ignored");
                Ok(())
            }
            Message::Block(raw) => {
                let hash = block_hash(&raw)?;
                match self.requested.contains(&hash) {
                    true => {
                        self.requested.retain(|asked| *asked != hash);
                        self.arrived.push(raw);
                    }
                    false => {
                        tracing::debug!(peer = %self.address, bytes = raw.len(), "unsolicited block dropped")
                    }
                }
                Ok(())
            }
            Message::Pong(nonce) => {
                tracing::trace!(peer = %self.address, nonce, "pong");
                Ok(())
            }
            Message::Inv(items) => {
                tracing::trace!(peer = %self.address, count = items.len(), "inventory announcement ignored");
                Ok(())
            }
            Message::NotFound(items) => {
                for item in items {
                    if let Inventory::WitnessBlock(hash) | Inventory::Block(hash) = item {
                        if self.requested.contains(&hash) {
                            self.requested.retain(|asked| *asked != hash);
                            self.lacking.push(hash);
                        }
                    }
                }
                Ok(())
            }
            Message::Verack => Ok(()),
            Message::Other(command) => {
                tracing::trace!(peer = %self.address, %command, "ignored peer message");
                Ok(())
            }
        }
    }

    fn learn(
        &mut self,
        address: Result<SocketAddr, bitcoin::io::Error>,
        services: ServiceFlags,
        time: u32,
    ) {
        match address {
            Ok(address) => {
                if services.has(ServiceFlags::WITNESS)
                    && (services.has(ServiceFlags::NETWORK)
                        || services.has(ServiceFlags::NETWORK_LIMITED))
                {
                    self.learned.push(Gossiped { address, time });
                }
            }
            Err(error) => tracing::debug!(%error, "gossiped address is not reachable by socket"),
        }
    }

    fn wait<T>(
        &mut self,
        deadline: Instant,
        mut matcher: impl FnMut(&mut Self, Message) -> Result<Waited<T>, Error>,
    ) -> Result<T, Error> {
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Io(io::Error::new(
                    ErrorKind::TimedOut,
                    format!("peer {} did not answer in time", self.address),
                )));
            }
            let message = self.receive()?;
            match matcher(self, message)? {
                Waited::Done(value) => return Ok(value),
                Waited::Keep => (),
            }
        }
    }

    pub(super) fn request_headers(
        &mut self,
        locator: Vec<BlockHash>,
    ) -> Result<Vec<Header>, Error> {
        let mut request = GetHeadersMessage::new(locator, BlockHash::all_zeros());
        request.version = P2P_PROTOCOL_VERSION;
        self.send(NetworkMessage::GetHeaders(request))?;
        let patience = Duration::from_secs(P2P_HEADERS_TIMEOUT_SECS);
        self.stream.set_read_timeout(Some(patience))?;
        let answered = self.wait(Instant::now() + patience, |peer, message| match message {
            Message::Headers(rows) => Ok(Waited::Done(rows)),
            other => {
                peer.absorb(other)?;
                Ok(Waited::Keep)
            }
        });
        self.stream
            .set_read_timeout(Some(Duration::from_secs(P2P_READ_TIMEOUT_SECS)))?;
        answered
    }

    pub(super) fn outstanding(&self) -> usize {
        self.requested.len()
    }

    pub(super) fn ask_blocks(&mut self, hashes: &[BlockHash]) -> Result<(), Error> {
        ensure!(
            self.requested.len() + hashes.len() <= P2P_PIPELINE_PER_PEER + 1,
            "peer {} already holds its block request window",
            self.address
        );
        let items = hashes
            .iter()
            .copied()
            .map(Inventory::WitnessBlock)
            .collect();
        self.send(NetworkMessage::GetData(items))?;
        self.requested.extend_from_slice(hashes);
        Ok(())
    }

    pub(super) fn await_block(&mut self, hash: BlockHash) -> Result<Vec<u8>, Error> {
        if self.lacking.contains(&hash) {
            self.lacking.retain(|missing| *missing != hash);
            return Err(self.missing(hash));
        }
        for (position, raw) in self.arrived.iter().enumerate() {
            if block_hash(raw)? == hash {
                return Ok(self.arrived.remove(position));
            }
        }
        let patience = Duration::from_secs(P2P_BLOCK_PEER_TIMEOUT_SECS);
        self.stream.set_read_timeout(Some(patience))?;
        let answered = self.wait(Instant::now() + patience, |peer, message| match message {
            Message::Block(raw) if block_hash(&raw)? == hash => {
                peer.requested.retain(|asked| *asked != hash);
                Ok(Waited::Done(raw))
            }
            Message::NotFound(rows)
                if rows.iter().any(|item| {
                    matches!(item, Inventory::WitnessBlock(missing) | Inventory::Block(missing) if *missing == hash)
                }) =>
            {
                peer.requested.retain(|asked| *asked != hash);
                Err(peer.missing(hash))
            }
            other => {
                peer.absorb(other)?;
                Ok(Waited::Keep)
            }
        });
        self.stream
            .set_read_timeout(Some(Duration::from_secs(P2P_READ_TIMEOUT_SECS)))?;
        answered
    }

    fn missing(&self, hash: BlockHash) -> Error {
        Error::Missing(format!("peer {} does not have block {hash}", self.address))
    }
}

pub(super) fn block_hash(raw: &[u8]) -> Result<BlockHash, Error> {
    let header: Header = deserialize(
        raw.get(..Header::SIZE)
            .context("block shorter than a header")?,
    )?;
    Ok(header.block_hash())
}
