//! Explicitly started URMA peer transport. Noise authenticates the remote
//! transport identity; packages still need independent Engine admission.
//! There are no built-in seeds, DNS lookups, wallet keys or implicit listeners.
use crate::{
    Error,
    engine::Engine,
    model::RecordPackage,
    peer_codec::Codec,
    peer_protocol::{PROTOCOL, RESPONSE_LIMIT, Reply, Request, Response, VERSION},
    peerbook::PeerAddress,
    retrieval::RecordSource,
};
use bitcoin::{BlockHash, Txid};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    multiaddr::Protocol,
    noise,
    request_response::{self, Message, OutboundRequestId, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU8, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::mpsc as async_mpsc;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING: usize = 8;

#[derive(NetworkBehaviour)]
struct Behaviour {
    // Admission must precede request-response connection side effects.
    limits: crate::peer_limits::Limits,
    records: request_response::Behaviour<Codec>,
}

/// Owns one network thread and one bounded archive-reader thread. Drop requests
/// shutdown and joins both. An archive operation already running is not forcibly
/// interrupted. Source handles do not keep the network alive after this owner.
pub struct PeerNetwork {
    peer: PeerId,
    listen: Option<Multiaddr>,
    commands: async_mpsc::Sender<Command>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), Error>>>,
}

/// A configured untrusted package source. Metadata is matched to the request;
/// proof verification and independent chain selection belong to the caller.
/// Cloning a source never dials; fetch performs the bounded request.
#[derive(Clone)]
pub struct PeerSource {
    address: PeerAddress,
    commands: async_mpsc::Sender<Command>,
    stop: Arc<AtomicBool>,
}

struct Command {
    address: PeerAddress,
    txid: Txid,
    deadline: Instant,
    answer: mpsc::SyncSender<Result<Option<RecordPackage>, Error>>,
}

struct Pending {
    peer: PeerId,
    txid: Txid,
    deadline: Instant,
    answer: mpsc::SyncSender<Result<Option<RecordPackage>, Error>>,
}

type Startup = mpsc::SyncSender<Result<Option<Multiaddr>, Error>>;
struct ServeJob {
    deadline: Instant,
    request: Request,
    channel: ResponseChannel<Response>,
}
struct Served {
    response: Response,
    channel: ResponseChannel<Response>,
    bytes: usize,
}

impl PeerNetwork {
    /// Listen only when an explicit IP/TCP address is supplied. Port zero is
    /// allowed for an ephemeral listener; returned address includes this PeerId.
    /// Merely constructing source handles never dials. No peer is a seed by default.
    pub fn start(
        engine: Arc<Engine>,
        identity: Keypair,
        listen: Option<Multiaddr>,
    ) -> Result<Self, Error> {
        if let Some(address) = &listen {
            validate_listener(address)?;
        }
        engine.status()?;
        let peer = identity.public().to_peer_id();
        let (commands, receiver) = async_mpsc::channel(MAX_PENDING);
        let (startup, ready) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::Builder::new()
            .name("urma-peer".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(run(engine, identity, listen, receiver, flag, startup))
            })?;
        let actual = match ready.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(address)) => address,
            result => {
                stop.store(true, Ordering::Release);
                let joined = worker.join();
                return Err(match result {
                    Ok(Err(error)) => error,
                    _ => match joined {
                        Ok(Err(error)) => error,
                        _ => Error::Busy("peer listener startup failed or expired".into()),
                    },
                });
            }
        };
        Ok(Self {
            peer,
            listen: actual,
            commands,
            stop,
            worker: Some(worker),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }
    pub fn listen_address(&self) -> Option<Multiaddr> {
        self.listen.clone()
    }

    pub fn source(&self, address: PeerAddress) -> PeerSource {
        PeerSource {
            address,
            commands: self.commands.clone(),
            stop: self.stop.clone(),
        }
    }

    pub fn shutdown(mut self) -> Result<(), Error> {
        self.stop.store(true, Ordering::Release);
        match self.worker.take().expect("network owner has worker").join() {
            Ok(result) => result,
            Err(_) => Err(Error::Invalid("peer worker panicked".into())),
        }
    }
}

impl Drop for PeerNetwork {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl RecordSource for PeerSource {
    fn fetch(&self, txid: Txid) -> Result<Option<RecordPackage>, Error> {
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Busy("peer network stopped".into()));
        }
        let deadline = Instant::now() + CALL_TIMEOUT;
        let (answer, receiver) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command {
                address: self.address.clone(),
                txid,
                deadline,
                answer,
            })
            .map_err(|_| Error::Busy("peer command queue unavailable".into()))?;
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::Busy("peer record acquisition deadline or shutdown".into()))?
    }
}

fn validate_listener(address: &Multiaddr) -> Result<(), Error> {
    let mut parts = address.iter();
    let ip = matches!(
        parts.next(),
        Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
    );
    if !ip || !matches!(parts.next(), Some(Protocol::Tcp(_))) || parts.next().is_some() {
        return Err(Error::Invalid(
            "peer listener requires only IP and TCP".into(),
        ));
    }
    Ok(())
}

fn swarm(identity: Keypair) -> Result<Swarm<Behaviour>, Error> {
    let records = request_response::Behaviour::with_codec(
        Codec,
        [(
            StreamProtocol::new(PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(2),
    );
    let limits = crate::peer_limits::Limits::default();
    Ok(SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                // These setters select libp2p-yamux's bounded 0.12 backend.
                config.set_max_num_streams(4);
                config.set_max_buffer_size(256 * 1024);
                config.set_receive_window_size(256 * 1024);
                config
            },
        )
        .map_err(|e| Error::Invalid(format!("peer transport: {e}")))?
        .with_behaviour(|_| Behaviour { limits, records })
        .map_err(|e| Error::Invalid(format!("peer behaviour: {e}")))?
        .with_swarm_config(|config| {
            config
                .with_notify_handler_buffer_size(NonZeroUsize::new(2).unwrap())
                .with_per_connection_event_buffer_size(2)
                .with_max_negotiating_inbound_streams(2)
                .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap())
                .with_idle_connection_timeout(Duration::from_secs(20))
        })
        .with_connection_timeout(Duration::from_secs(5))
        .build())
}

async fn run(
    engine: Arc<Engine>,
    identity: Keypair,
    listen: Option<Multiaddr>,
    mut commands: async_mpsc::Receiver<Command>,
    stop: Arc<AtomicBool>,
    startup: Startup,
) -> Result<(), Error> {
    let genesis = engine.status()?.chain_genesis;
    let mut swarm = swarm(identity)?;
    let mut ready = Some(startup);
    let listening = listen.is_some();
    if let Some(address) = listen {
        swarm
            .listen_on(address)
            .map_err(|e| Error::Invalid(format!("peer listen: {e}")))?;
    }
    let (jobs, input) = mpsc::sync_channel::<ServeJob>(2);
    let (served, mut responses) = async_mpsc::channel::<Served>(2);
    let serving_stop = stop.clone();
    let serving = std::thread::Builder::new()
        .name("urma-peer-read".into())
        .spawn(move || {
            while let Ok(job) = input.recv() {
                if serving_stop.load(Ordering::Acquire) {
                    break;
                }
                if !job.channel.is_open() || Instant::now() >= job.deadline {
                    continue;
                }
                let result = match engine.record(job.request.txid) {
                    Ok(Some(record)) => Reply::Record(Box::new(record.package)),
                    Ok(None) => Reply::Missing,
                    Err(_) => Reply::Busy,
                };
                if serving_stop.load(Ordering::Acquire)
                    || !job.channel.is_open()
                    || Instant::now() >= job.deadline
                {
                    continue;
                }
                let mut response = Response {
                    version: VERSION,
                    chain_genesis: genesis,
                    txid: job.request.txid,
                    result,
                };
                let mut count = Count(0);
                if serde_json::to_writer(&mut count, &response).is_err() {
                    response.result = Reply::TooLarge;
                    count.0 = 256;
                }
                if served
                    .blocking_send(Served {
                        channel: job.channel,
                        response,
                        bytes: count.0,
                    })
                    .is_err()
                {
                    break;
                }
            }
        })?;
    if !listening {
        let _ = ready.take().unwrap().send(Ok(None));
    }
    let mut pending = HashMap::<OutboundRequestId, Pending>::new();
    let mut inbound = HashSet::new();
    let mut rates = HashMap::<PeerId, Bucket>::new();
    let mut requests = Bucket::new(16, 16);
    let mut bytes = Bucket::new(64 * 1024 * 1024, 4 * 1024 * 1024);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    let started = Instant::now();
    let result = loop {
        if stop.load(Ordering::Acquire) {
            break Ok(());
        }
        if ready.is_some() && started.elapsed() > Duration::from_secs(4) {
            break Err(Error::Busy("peer listener startup deadline".into()));
        }
        tokio::select! {
            _ = tick.tick() => {
                // Keep the request tracked until libp2p reports completion. This
                // bounds its internal pending queue even if a caller times out.
                for value in pending.values_mut() {
                    if Instant::now() >= value.deadline {
                        let _ = value.answer.try_send(Err(Error::Busy("peer acquisition deadline".into())));
                        let _ = swarm.disconnect_peer_id(value.peer);
                    }
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { break Ok(()); };
                if Instant::now() >= command.deadline || pending.len() >= MAX_PENDING
                    || pending.values().any(|p| p.peer == command.address.peer_id()) {
                    let _ = command.answer.send(Err(Error::Busy("peer acquisition capacity or deadline".into())));
                    continue;
                }
                let peer = command.address.peer_id();
                let request = Request { version: VERSION, chain_genesis: genesis, txid: command.txid };
                let id = swarm.behaviour_mut().records.send_request_with_addresses(
                    &peer, request, vec![command.address.address().clone()]);
                pending.insert(id, Pending { peer, txid: command.txid, deadline: command.deadline, answer: command.answer });
            }
            response = responses.recv() => {
                let Some(mut response) = response else { break Err(Error::Invalid("peer archive reader stopped".into())); };
                if response.channel.is_open() {
                    if !bytes.take(response.bytes.saturating_sub(256) as u64) { response.response.result = Reply::Busy; }
                    let _ = swarm.behaviour_mut().records.send_response(response.channel, response.response);
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { mut address, .. } => {
                    address.push(Protocol::P2p(*swarm.local_peer_id()));
                    if let Some(ready) = ready.take() { let _ = ready.send(Ok(Some(address))); }
                }
                SwarmEvent::ListenerError { error, .. } if ready.is_some() => break Err(Error::Io(error)),
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => { rates.remove(&peer_id); }
                SwarmEvent::Behaviour(BehaviourEvent::Records(event)) => match event {
                    request_response::Event::Message { peer, message: Message::Request { request_id, request, channel }, .. } => {
                        // Every request, including refusals, consumes rate and
                        // response allowance. Exhaustion drops the channel;
                        // it cannot amplify traffic with unlimited Busy replies.
                        if !requests.take(1) || !peer_rate(&mut rates, peer) || !bytes.take(256) {
                            continue;
                        }
                        let refusal = if request.version != VERSION { Some(Reply::UnsupportedVersion) }
                            else if request.chain_genesis != genesis { Some(Reply::WrongNetwork) }
                            else if inbound.len() >= 2 || inbound.iter().any(|(p, _)| *p == peer)
                                { Some(Reply::Busy) }
                            else { None };
                        if let Some(result) = refusal {
                            let _ = swarm.behaviour_mut().records.send_response(channel, Response { version: VERSION, chain_genesis: genesis, txid: request.txid, result });
                        } else {
                            match jobs.try_send(ServeJob { deadline: Instant::now() + REQUEST_TIMEOUT, request, channel }) {
                                Ok(()) => { inbound.insert((peer, request_id)); }
                                Err(_) => { /* Dropped response channel refuses the request. */ }
                            }
                        }
                    }
                    request_response::Event::Message { peer, message: Message::Response { request_id, response }, .. } => {
                        if let Some(value) = pending.remove(&request_id) {
                            let result = validate_response(genesis, peer, &value, response);
                            let _ = value.answer.try_send(result);
                        }
                    }
                    request_response::Event::OutboundFailure { request_id, error, .. } => {
                        if let Some(value) = pending.remove(&request_id) {
                            let _ = value.answer.try_send(Err(Error::Invalid(format!("peer request: {error}"))));
                        }
                    }
                    request_response::Event::InboundFailure { peer, request_id, .. }
                    | request_response::Event::ResponseSent { peer, request_id, .. } => { inbound.remove(&(peer, request_id)); }
                },
                _ => (),
            }
        }
    };
    stop.store(true, Ordering::Release);
    for (_, value) in pending {
        let _ = value
            .answer
            .try_send(Err(Error::Busy("peer network stopped".into())));
    }
    // Drop channels before joining: the archive reader must not wait for a
    // consumer which is already shutting down. No socket belongs to that reader.
    drop(swarm);
    drop(jobs);
    drop(responses);
    if serving.join().is_err() {
        return Err(Error::Invalid("peer archive reader panicked".into()));
    }
    result
}

fn validate_response(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: Response,
) -> Result<Option<RecordPackage>, Error> {
    if Instant::now() >= pending.deadline {
        return Err(Error::Busy("peer acquisition deadline".into()));
    }
    if peer != pending.peer
        || response.version != VERSION
        || response.chain_genesis != genesis
        || response.txid != pending.txid
    {
        return Err(Error::Invalid(
            "peer response identity, network or version mismatch".into(),
        ));
    }
    match response.result {
        Reply::Record(package) if package.chain_genesis == genesis => Ok(Some(*package)),
        Reply::Missing => Ok(None),
        Reply::Busy => Err(Error::Busy("remote peer capacity".into())),
        _ => Err(Error::Invalid(
            "peer refused record or returned wrong network".into(),
        )),
    }
}

struct Count(usize);
impl std::io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= RESPONSE_LIMIT)
            .ok_or_else(|| std::io::Error::other("peer response size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Bucket {
    available: u64,
    capacity: u64,
    per_second: u64,
    updated: Instant,
}
impl Bucket {
    fn new(capacity: u64, per_second: u64) -> Self {
        Self {
            available: capacity,
            capacity,
            per_second,
            updated: Instant::now(),
        }
    }
    fn take(&mut self, amount: u64) -> bool {
        let now = Instant::now();
        let added = (now.duration_since(self.updated).as_nanos() * u128::from(self.per_second)
            / 1_000_000_000)
            .min(u128::from(self.capacity)) as u64;
        if added > 0 {
            self.available = self.available.saturating_add(added).min(self.capacity);
            self.updated = now;
        }
        if self.available < amount {
            return false;
        }
        self.available -= amount;
        true
    }
}

fn peer_rate(rates: &mut HashMap<PeerId, Bucket>, peer: PeerId) -> bool {
    if !rates.contains_key(&peer) && rates.len() >= 8 {
        return false;
    }
    rates
        .entry(peer)
        .or_insert_with(|| Bucket::new(4, 4))
        .take(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use std::io::Write;

    #[test]
    fn public_response_metadata_is_bound_but_is_not_record_verification() {
        let genesis = BlockHash::all_zeros();
        let txid = Txid::all_zeros();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let (answer, _receiver) = mpsc::sync_channel(1);
        let pending = Pending {
            peer,
            txid,
            deadline: Instant::now() + CALL_TIMEOUT,
            answer,
        };
        let response = Response {
            version: VERSION,
            chain_genesis: genesis,
            txid,
            result: Reply::Missing,
        };
        assert!(
            validate_response(genesis, peer, &pending, response.clone())
                .unwrap()
                .is_none()
        );
        assert!(validate_response(genesis, other, &pending, response.clone()).is_err());
        let mut bad = response.clone();
        bad.version += 1;
        assert!(validate_response(genesis, peer, &pending, bad).is_err());
        let mut bad = response.clone();
        bad.chain_genesis = BlockHash::from_byte_array([1; 32]);
        assert!(validate_response(genesis, peer, &pending, bad).is_err());
        let mut bad = response.clone();
        bad.txid = Txid::from_byte_array([1; 32]);
        assert!(validate_response(genesis, peer, &pending, bad).is_err());
        let expired = Pending {
            deadline: Instant::now(),
            ..pending
        };
        assert!(matches!(
            validate_response(genesis, peer, &expired, response),
            Err(Error::Busy(_))
        ));
    }

    #[test]
    fn request_rate_history_and_response_serialization_are_bounded() {
        let mut rates = HashMap::new();
        let mut peers = Vec::new();
        for _ in 0..8 {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            assert!(peer_rate(&mut rates, peer));
            peers.push(peer);
        }
        assert!(!peer_rate(
            &mut rates,
            Keypair::generate_ed25519().public().to_peer_id()
        ));
        assert_eq!(rates.len(), 8);
        rates.get_mut(&peers[0]).unwrap().per_second = 0;
        for _ in 0..3 {
            assert!(peer_rate(&mut rates, peers[0]));
        }
        assert!(!peer_rate(&mut rates, peers[0]));
        let mut count = Count(RESPONSE_LIMIT - 1);
        count.write_all(&[0]).unwrap();
        assert!(count.write_all(&[0]).is_err());
        assert_eq!(count.0, RESPONSE_LIMIT);
        let mut bytes = Bucket::new(1024, 0);
        assert!(bytes.take(1024));
        assert!(!bytes.take(1));
    }

    #[test]
    fn listener_accepts_only_explicit_ip_tcp_without_implicit_resolution() {
        for value in [
            "/ip4/127.0.0.1/tcp/0",
            "/ip6/::1/tcp/0",
            "/ip4/0.0.0.0/tcp/28332",
        ] {
            validate_listener(&value.parse().unwrap()).unwrap();
        }
        for value in [
            "/dns4/localhost/tcp/1",
            "/ip4/127.0.0.1/udp/1",
            "/ip4/127.0.0.1/tcp/1/ws",
        ] {
            assert!(validate_listener(&value.parse().unwrap()).is_err());
        }
    }
}
