use crate::config::{
    P2P_BLOCK_TIMEOUT_SECS, P2P_CONNECT_TIMEOUT_SECS, P2P_HANDSHAKE_TIMEOUT_SECS,
    P2P_PROTOCOL_VERSION, P2P_READ_TIMEOUT_SECS, P2P_USER_AGENT,
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
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urma_chain::observation::Chain;

pub(super) struct Peer {
    stream: TcpStream,
    magic: [u8; 4],
    pub(super) address: SocketAddr,
    pub(super) services: ServiceFlags,
    pub(super) start_height: u64,
    pub(super) learned: Vec<SocketAddr>,
}

enum Waited<T> {
    Done(T),
    Keep,
}

impl Peer {
    pub(super) fn connect(
        chain: Chain,
        address: SocketAddr,
        our_height: u64,
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
        };
        peer.handshake(our_height)?;
        Ok(peer)
    }

    fn handshake(&mut self, our_height: u64) -> Result<(), Error> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                Error::Invalid(format!("system clock precedes the unix epoch: {error}"))
            })?;
        let now = i64::try_from(elapsed.as_secs())?;
        let mut version = VersionMessage::new(
            ServiceFlags::NONE,
            now,
            Address::new(&self.address, ServiceFlags::NONE),
            Address::new(&"0.0.0.0:0".parse::<SocketAddr>()?, ServiceFlags::NONE),
            rand::random(),
            P2P_USER_AGENT.to_owned(),
            i32::try_from(our_height)?,
        );
        version.version = P2P_PROTOCOL_VERSION;
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
                    self.send(NetworkMessage::Verack)?;
                    versioned = true;
                }
                Message::Verack => acknowledged = true,
                other => self.absorb(other)?,
            }
        }
        self.send(NetworkMessage::GetAddr)?;
        Ok(())
    }

    pub(super) fn limited(&self) -> bool {
        !self.services.has(ServiceFlags::NETWORK)
    }

    fn send(&mut self, payload: NetworkMessage) -> Result<(), Error> {
        wire::send(&mut self.stream, self.magic, payload)
    }

    fn receive(&mut self) -> Result<Message, Error> {
        wire::receive(&mut self.stream, self.magic)
    }

    fn absorb(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::Ping(nonce) => self.send(NetworkMessage::Pong(nonce)),
            Message::Addr(rows) => {
                for (_time, address) in rows {
                    self.learn(address.socket_addr(), address.services);
                }
                Ok(())
            }
            Message::AddrV2(rows) => {
                for row in rows {
                    self.learn(row.socket_addr(), row.services);
                }
                Ok(())
            }
            Message::Version(_version) => Err(Error::Invalid("peer repeated its version".into())),
            Message::Headers(rows) => {
                tracing::debug!(peer = %self.address, count = rows.len(), "unsolicited headers ignored");
                Ok(())
            }
            Message::Block(raw) => {
                tracing::debug!(peer = %self.address, bytes = raw.len(), "unsolicited block ignored");
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
                tracing::trace!(peer = %self.address, count = items.len(), "notfound outside a request");
                Ok(())
            }
            Message::Verack => Ok(()),
            Message::Other(command) => {
                tracing::trace!(peer = %self.address, %command, "ignored peer message");
                Ok(())
            }
        }
    }

    fn learn(&mut self, address: Result<SocketAddr, bitcoin::io::Error>, services: ServiceFlags) {
        match address {
            Ok(address) => {
                if services.has(ServiceFlags::WITNESS)
                    && (services.has(ServiceFlags::NETWORK)
                        || services.has(ServiceFlags::NETWORK_LIMITED))
                {
                    self.learned.push(address);
                }
            }
            Err(error) => tracing::warn!(%error, "gossiped address is not reachable by socket"),
        }
    }

    fn wait<T>(
        &mut self,
        deadline: Instant,
        mut matcher: impl FnMut(&mut Self, Message) -> Result<Waited<T>, Error>,
    ) -> Result<T, Error> {
        loop {
            ensure!(
                Instant::now() < deadline,
                "peer {} did not answer in time",
                self.address
            );
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
        let deadline = Instant::now() + Duration::from_secs(P2P_READ_TIMEOUT_SECS);
        self.wait(deadline, |peer, message| match message {
            Message::Headers(rows) => Ok(Waited::Done(rows)),
            other => {
                peer.absorb(other)?;
                Ok(Waited::Keep)
            }
        })
    }

    pub(super) fn request_block(&mut self, hash: BlockHash) -> Result<Vec<u8>, Error> {
        self.ask_block(hash)?;
        self.await_block(hash)
    }

    pub(super) fn ask_block(&mut self, hash: BlockHash) -> Result<(), Error> {
        self.send(NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]))
    }

    pub(super) fn await_block(&mut self, hash: BlockHash) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now() + Duration::from_secs(P2P_BLOCK_TIMEOUT_SECS);
        self.wait(deadline, |peer, message| match message {
            Message::Block(raw) => {
                let header: Header = deserialize(raw.get(..Header::SIZE).context("block shorter than a header")?)?;
                match header.block_hash() == hash {
                    true => Ok(Waited::Done(raw)),
                    false => {
                        tracing::debug!(peer = %peer.address, "block for another request ignored");
                        Ok(Waited::Keep)
                    }
                }
            }
            Message::NotFound(rows) => {
                let absent = rows.iter().any(|item| {
                    matches!(item, Inventory::WitnessBlock(missing) | Inventory::Block(missing) if *missing == hash)
                });
                match absent {
                    true => Err(Error::Missing(format!("peer {} does not have block {hash}", peer.address))),
                    false => Ok(Waited::Keep),
                }
            }
            other => {
                peer.absorb(other)?;
                Ok(Waited::Keep)
            }
        })
    }
}
