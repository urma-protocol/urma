//! Explicitly started URMA peer transport. Noise authenticates the remote
//! transport identity; packages still need independent Engine admission.
//! There are no built-in seeds, DNS lookups, wallet keys or implicit listeners.
pub use crate::peer_parent::OverlayCommitSource;
use crate::{
    Error,
    engine::Engine,
    model::RecordPackage,
    peer_codec::Codec,
    peer_inventory::{lookup, validate_inventory},
    peer_limits::LimitDenied,
    peer_parent::{Parent, validate_parent},
    peer_protocol::{
        InventoryPage, Kind, PROTOCOL, RESPONSE_LIMIT, Reply, Request, Response, VERSION,
    },
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
    swarm::{DialError, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU8, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::mpsc as async_mpsc;
use urma_chain::observation::Chain;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(10);
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
    connected: Arc<AtomicU64>,
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

enum Command {
    Fetch(Fetch),
    /// Fire and forget: frees the slot held by a peer whose reply was rejected.
    Disconnect(PeerId),
}

struct Fetch {
    address: PeerAddress,
    kind: Kind,
    deadline: Instant,
    answer: Answer,
}

pub(crate) struct Pending {
    peer: PeerId,
    kind: Kind,
    deadline: Instant,
    answer: Answer,
}

/// Reply channel typed by request kind; a cross-kind reply is a peer error.
pub(crate) enum Answer {
    Record(mpsc::SyncSender<Result<Option<RecordPackage>, Error>>),
    Parent(mpsc::SyncSender<Result<Parent, Error>>),
    Inventory(mpsc::SyncSender<Result<Option<InventoryPage>, Error>>),
}

impl Answer {
    fn fail(&self, error: Error) {
        match self {
            Answer::Record(sender) => {
                let _ = sender.try_send(Err(error));
            }
            Answer::Parent(sender) => {
                let _ = sender.try_send(Err(error));
            }
            Answer::Inventory(sender) => {
                let _ = sender.try_send(Err(error));
            }
        }
    }

    fn deliver(&self, genesis: BlockHash, peer: PeerId, pending: &Pending, response: Response) {
        match self {
            Answer::Record(sender) => {
                let _ = sender.try_send(validate_response(genesis, peer, pending, response));
            }
            Answer::Parent(sender) => {
                let _ = sender.try_send(validate_parent(genesis, peer, pending, response));
            }
            Answer::Inventory(sender) => {
                let _ = sender.try_send(validate_inventory(genesis, peer, pending, response));
            }
        }
    }
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
        let connected = Arc::new(AtomicU64::new(0));
        let (flag, count) = (stop.clone(), connected.clone());
        let worker = std::thread::Builder::new()
            .name("urma-peer".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let control = (receiver, flag, count, startup);
                runtime.block_on(run(engine, identity, listen, control))
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
            connected,
            worker: Some(worker),
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }
    /// Distinct peers with at least one established connection right now.
    pub fn connected_peers(&self) -> u64 {
        self.connected.load(Ordering::Relaxed)
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

    pub fn commit_source(&self, chain: Chain, peers: Vec<PeerAddress>) -> OverlayCommitSource {
        OverlayCommitSource::new(
            chain,
            peers
                .into_iter()
                .map(|address| self.source(address))
                .collect(),
        )
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

impl PeerSource {
    /// Bounded by CALL_TIMEOUT and by the caller's own deadline, if earlier.
    pub(crate) fn request<T>(
        &self,
        kind: Kind,
        limit: Instant,
        answer: fn(mpsc::SyncSender<Result<T, Error>>) -> Answer,
    ) -> Result<T, Error> {
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Busy("peer network stopped".into()));
        }
        let deadline = limit.min(Instant::now() + CALL_TIMEOUT);
        let (sender, receiver) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command::Fetch(Fetch {
                address: self.address.clone(),
                kind,
                deadline,
                answer: answer(sender),
            }))
            .map_err(|_| Error::Busy("peer command queue unavailable".into()))?;
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::Busy("peer acquisition deadline or shutdown".into()))?
    }
}

impl PeerSource {
    pub(crate) fn parent(&self, txid: Txid, deadline: Instant) -> Result<Parent, Error> {
        self.request(Kind::Parent { txid }, deadline, Answer::Parent)
    }

    /// Fire and forget; a full queue only delays the idle-connection timeout.
    pub(crate) fn disconnect(&self) {
        let _ = self
            .commands
            .try_send(Command::Disconnect(self.address.peer_id()));
    }
}

impl RecordSource for PeerSource {
    fn fetch(&self, txid: Txid) -> Result<Option<RecordPackage>, Error> {
        let kind = Kind::Record { txid };
        self.request(kind, Instant::now() + CALL_TIMEOUT, Answer::Record)
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

type Control = (
    async_mpsc::Receiver<Command>,
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    Startup,
);

async fn run(
    engine: Arc<Engine>,
    identity: Keypair,
    listen: Option<Multiaddr>,
    control: Control,
) -> Result<(), Error> {
    let (mut commands, stop, connected, startup) = control;
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
                let result = lookup(&engine, &job.request);
                if serving_stop.load(Ordering::Acquire)
                    || !job.channel.is_open()
                    || Instant::now() >= job.deadline
                {
                    continue;
                }
                let mut response = Response {
                    version: VERSION,
                    chain_genesis: genesis,
                    kind: job.request.kind,
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
                        value.answer.fail(Error::Busy("peer acquisition deadline".into()));
                        let _ = swarm.disconnect_peer_id(value.peer);
                    }
                }
            }
            command = commands.recv() => {
                let command = match command {
                    Some(Command::Fetch(fetch)) => fetch,
                    // A Fetch queued for this peer since the rejection keeps its connection.
                    Some(Command::Disconnect(peer)) => {
                        if !pending.values().any(|p| p.peer == peer) { let _ = swarm.disconnect_peer_id(peer); }
                        continue;
                    }
                    None => break Ok(()),
                };
                if Instant::now() >= command.deadline || pending.len() >= MAX_PENDING
                    || pending.values().any(|p| p.peer == command.address.peer_id()) {
                    command.answer.fail(Error::Busy("peer acquisition capacity or deadline".into()));
                    continue;
                }
                let peer = command.address.peer_id();
                let request = Request { version: VERSION, chain_genesis: genesis, kind: command.kind };
                let id = swarm.behaviour_mut().records.send_request_with_addresses(
                    &peer, request, vec![command.address.address().clone()]);
                pending.insert(id, Pending { peer, kind: command.kind, deadline: command.deadline, answer: command.answer });
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
                SwarmEvent::ConnectionEstablished { num_established, .. } if num_established.get() == 1 => { connected.fetch_add(1, Ordering::Relaxed); }
                SwarmEvent::ConnectionClosed { num_established: 0, .. } => { connected.fetch_sub(1, Ordering::Relaxed); }
                // Queued before request-response reports the same DialFailure.
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), error: DialError::Denied { cause }, .. }
                    if cause.downcast_ref::<LimitDenied>().is_some() => release_denied(&mut pending, peer),
                SwarmEvent::Behaviour(BehaviourEvent::Records(event)) => match event {
                    request_response::Event::Message { peer, message: Message::Request { request_id, request, channel }, .. } => {
                        // Every request, including refusals, consumes rate and
                        // response allowance. Over-rate requests get an explicit
                        // Busy; only an exhausted byte allowance drops the channel.
                        let over_rate = !requests.take(1) || !peer_rate(&mut rates, peer);
                        if !bytes.take(256) {
                            continue;
                        }
                        let refusal = if over_rate { Some(Reply::Busy) }
                            else if request.version != VERSION { Some(Reply::UnsupportedVersion) }
                            else if request.chain_genesis != genesis { Some(Reply::WrongNetwork) }
                            else if inbound.len() >= 2 || inbound.iter().any(|(p, _)| *p == peer)
                                { Some(Reply::Busy) }
                            else { None };
                        if let Some(result) = refusal {
                            let _ = swarm.behaviour_mut().records.send_response(channel, Response { version: VERSION, chain_genesis: genesis, kind: request.kind, result });
                        } else {
                            match jobs.try_send(ServeJob { deadline: Instant::now() + REQUEST_TIMEOUT, request, channel }) {
                                Ok(()) => { inbound.insert((peer, request_id)); }
                                Err(_) => { /* Dropped response channel refuses the request. */ }
                            }
                        }
                    }
                    request_response::Event::Message { peer, message: Message::Response { request_id, response }, .. } => {
                        if let Some(value) = pending.remove(&request_id) {
                            value.answer.deliver(genesis, peer, &value, response);
                        }
                    }
                    request_response::Event::OutboundFailure { request_id, error, .. } => {
                        if let Some(value) = pending.remove(&request_id) {
                            value.answer.fail(Error::Invalid(format!("peer request: {error}")));
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
        value
            .answer
            .fail(Error::Busy("peer network stopped".into()));
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

/// A dial refused by our own limits is local capacity, answered as Busy.
fn release_denied(pending: &mut HashMap<OutboundRequestId, Pending>, peer: PeerId) {
    pending.retain(|_, value| {
        if value.peer != peer {
            return true;
        }
        value.answer.fail(Error::Busy(
            "peer dial denied by local connection limit".into(),
        ));
        false
    });
}

pub(crate) fn bind_response(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: &Response,
) -> Result<(), Error> {
    if Instant::now() >= pending.deadline {
        return Err(Error::Busy("peer acquisition deadline".into()));
    }
    if peer != pending.peer
        || response.version != VERSION
        || response.chain_genesis != genesis
        || response.kind != pending.kind
    {
        return Err(Error::Invalid(
            "peer response identity, network or version mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_response(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: Response,
) -> Result<Option<RecordPackage>, Error> {
    bind_response(genesis, peer, pending, &response)?;
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
        self.take_at(amount, Instant::now())
    }
    fn refill(&mut self, now: Instant) {
        let added = (now.duration_since(self.updated).as_nanos() * u128::from(self.per_second)
            / 1_000_000_000)
            .min(u128::from(self.capacity)) as u64;
        if added > 0 {
            self.available = self.available.saturating_add(added).min(self.capacity);
            self.updated = now;
        }
    }
    fn take_at(&mut self, amount: u64, now: Instant) -> bool {
        self.refill(now);
        if self.available < amount {
            return false;
        }
        self.available -= amount;
        true
    }
}

fn peer_rate(rates: &mut HashMap<PeerId, Bucket>, peer: PeerId) -> bool {
    peer_rate_at(rates, peer, Instant::now())
}

fn peer_rate_at(rates: &mut HashMap<PeerId, Bucket>, peer: PeerId, now: Instant) -> bool {
    // Retain spent allowance across disconnects. Only fully replenished
    // identities may be forgotten: recreating those buckets changes no budget.
    // History is bounded independently of connection churn; at capacity a new
    // identity is refused instead of evicting another identity's spent budget.
    rates.retain(|_, bucket| {
        bucket.refill(now);
        bucket.available < bucket.capacity
    });
    if !rates.contains_key(&peer) && rates.len() >= 256 {
        return false;
    }
    rates
        .entry(peer)
        .or_insert_with(|| Bucket {
            available: 4,
            capacity: 4,
            per_second: 4,
            updated: now,
        })
        .take_at(1, now)
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
            kind: Kind::Record { txid },
            deadline: Instant::now() + CALL_TIMEOUT,
            answer: Answer::Record(answer),
        };
        let response = Response {
            version: VERSION,
            chain_genesis: genesis,
            kind: Kind::Record { txid },
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
        bad.kind = Kind::Record {
            txid: Txid::from_byte_array([1; 32]),
        };
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
        let now = Instant::now();
        for _ in 0..256 {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            assert!(peer_rate_at(&mut rates, peer, now));
            peers.push(peer);
        }
        assert!(!peer_rate_at(
            &mut rates,
            Keypair::generate_ed25519().public().to_peer_id(),
            now
        ));
        assert_eq!(rates.len(), 256);
        rates.get_mut(&peers[0]).unwrap().per_second = 0;
        for _ in 0..3 {
            assert!(peer_rate_at(&mut rates, peers[0], now));
        }
        assert!(!peer_rate_at(&mut rates, peers[0], now));
        let mut count = Count(RESPONSE_LIMIT - 1);
        count.write_all(&[0]).unwrap();
        assert!(count.write_all(&[0]).is_err());
        assert_eq!(count.0, RESPONSE_LIMIT);
        let mut bytes = Bucket::new(1024, 0);
        assert!(bytes.take(1024));
        assert!(!bytes.take(1));
    }

    #[test]
    fn identity_rate_survives_reconnect_until_allowance_replenishes() {
        let mut rates = HashMap::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let now = Instant::now();
        for _ in 0..4 {
            assert!(peer_rate_at(&mut rates, peer, now));
        }
        // Connection lifetime has no effect on the identity accounting.
        assert!(!peer_rate_at(&mut rates, peer, now));
        let later = now + Duration::from_millis(250);
        assert!(peer_rate_at(&mut rates, peer, later));
        assert!(!peer_rate_at(&mut rates, peer, later));
        let replenished = later + Duration::from_secs(1);
        for _ in 0..4 {
            assert!(peer_rate_at(&mut rates, peer, replenished));
        }
        assert!(!peer_rate_at(&mut rates, peer, replenished));
        let other = Keypair::generate_ed25519().public().to_peer_id();
        assert!(peer_rate_at(
            &mut rates,
            other,
            replenished + Duration::from_secs(1)
        ));
        assert_eq!(rates.len(), 1);
        assert!(!rates.contains_key(&peer));
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
