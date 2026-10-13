//! Explicitly started URMA peer transport. Noise authenticates the remote
//! transport identity; packages still need independent Engine admission.
//! There are no built-in seeds, wallet keys or implicit listeners. Names in
//! explicitly dialed `/dns*` addresses resolve through the system resolver.
pub use crate::peer_parent::OverlayCommitSource;
use crate::{
    DialLimit, Error,
    engine::Engine,
    model::RecordPackage,
    peer_codec::Codec,
    peer_gossip::{Dial, Dials, Shared, is_loopback, validate_announce, validate_peers},
    peer_inventory::{lookup, validate_inventory},
    peer_limits::{LimitDenied, Limits},
    peer_parent::{Parent, validate_parent},
    peer_protocol::{GossipPeer, InventoryPage, Kind, PROTOCOL, Reply, Request, Response, VERSION},
    peer_rate::{Bucket, Count, peer_rate},
    peerbook::PeerAddress,
    retrieval::RecordSource,
};
use bitcoin::{BlockHash, Txid};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identify,
    identity::Keypair,
    multiaddr::Protocol,
    noise,
    request_response::{self, Message, OutboundRequestId, ResponseChannel},
    swarm::{ConnectionId, DialError, NetworkBehaviour, SwarmEvent},
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
const IDENTIFY_PROTOCOL: &str = "/urma/node/4";

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    // Admission must precede request-response connection side effects.
    limits: Limits,
    records: request_response::Behaviour<Codec>,
    identify: identify::Behaviour,
}

/// Owns one network thread and one bounded archive-reader thread. Drop requests
/// shutdown and joins both. An archive operation already running is not forcibly
/// interrupted. Source handles do not keep the network alive after this owner.
pub struct PeerNetwork {
    peer: PeerId,
    listen: Option<Multiaddr>,
    pub(crate) commands: async_mpsc::Sender<Command>,
    pub(crate) stop: Arc<AtomicBool>,
    connected: Arc<AtomicU64>,
    pub(crate) shared: Arc<Shared>,
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
    shared: Arc<Shared>,
}

pub(crate) enum Command {
    Fetch(Fetch),
    /// Fire and forget: frees the slot held by a peer whose reply was rejected.
    Disconnect(PeerId),
    Dial(Dial),
}

/// A request to one peer, over its existing connection or the given addresses.
pub(crate) struct Fetch {
    peer: PeerId,
    addresses: Vec<Multiaddr>,
    kind: Kind,
    deadline: Instant,
    answer: Answer,
}

pub(crate) struct Pending {
    peer: PeerId,
    pub(crate) kind: Kind,
    deadline: Instant,
    answer: Answer,
}

/// Reply channel typed by request kind; a cross-kind reply is a peer error.
pub(crate) enum Answer {
    Record(mpsc::SyncSender<Result<Option<RecordPackage>, Error>>),
    Parent(mpsc::SyncSender<Result<Parent, Error>>),
    Inventory(mpsc::SyncSender<Result<Option<InventoryPage>, Error>>),
    Peers(mpsc::SyncSender<Result<Vec<GossipPeer>, Error>>),
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
            Answer::Peers(sender) => {
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
            Answer::Peers(sender) => {
                let _ = sender.try_send(validate_peers(genesis, peer, pending, response));
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
    /// `announce` are operator-chosen public IP/TCP addresses identify advertises.
    pub fn start(
        engine: Arc<Engine>,
        identity: Keypair,
        listen: Option<Multiaddr>,
        announce: Vec<Multiaddr>,
    ) -> Result<Self, Error> {
        if let Some(address) = &listen {
            validate_listener(address)?;
        }
        engine.status()?;
        let peer = identity.public().to_peer_id();
        let announce = announce
            .iter()
            .map(|address| validate_announce(address, peer))
            .collect::<Result<Vec<_>, _>>()?;
        let (commands, receiver) = async_mpsc::channel(MAX_PENDING);
        let (startup, ready) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicU64::new(0));
        let shared = Arc::new(Shared::new(peer));
        let control = Control {
            commands: receiver,
            stop: stop.clone(),
            connected: connected.clone(),
            startup,
            shared: shared.clone(),
            announce,
        };
        let worker = std::thread::Builder::new()
            .name("urma-peer".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
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
            shared,
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
            shared: Arc::clone(&self.shared),
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

/// One bounded request: CALL_TIMEOUT and the caller's own deadline, if earlier.
/// Without addresses the peer must already be connected or known to the swarm.
pub(crate) fn request<T>(
    commands: &async_mpsc::Sender<Command>,
    stop: &AtomicBool,
    (peer, addresses): (PeerId, Vec<Multiaddr>),
    kind: Kind,
    limit: Instant,
    answer: fn(mpsc::SyncSender<Result<T, Error>>) -> Answer,
) -> Result<T, Error> {
    if stop.load(Ordering::Acquire) {
        return Err(Error::Busy("peer network stopped".into()));
    }
    let deadline = limit.min(Instant::now() + CALL_TIMEOUT);
    let (sender, receiver) = mpsc::sync_channel(1);
    commands
        .try_send(Command::Fetch(Fetch {
            peer,
            addresses,
            kind,
            deadline,
            answer: answer(sender),
        }))
        .map_err(|_| Error::Busy("peer command queue unavailable".into()))?;
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| Error::Busy("peer acquisition deadline or shutdown".into()))?
}

impl PeerSource {
    pub(crate) fn request<T>(
        &self,
        kind: Kind,
        limit: Instant,
        answer: fn(mpsc::SyncSender<Result<T, Error>>) -> Answer,
    ) -> Result<T, Error> {
        let target = (self.address.peer_id(), vec![self.address.address().clone()]);
        request(&self.commands, &self.stop, target, kind, limit, answer)
    }

    pub(crate) fn parent(&self, txid: Txid, deadline: Instant) -> Result<Parent, Error> {
        self.request(Kind::Parent { txid }, deadline, Answer::Parent)
    }

    /// Whether this peer has an established connection right now.
    pub(crate) fn connected(&self) -> bool {
        self.shared.is_connected(self.address.peer_id())
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
    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.into(), identity.public())
            .with_agent_version(format!("urma-node/{}", env!("CARGO_PKG_VERSION"))),
    );
    let limits = Limits::default();
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
        .with_dns()
        .map_err(|e| Error::Invalid(format!("peer DNS resolver: {e}")))?
        .with_behaviour(|_| Behaviour {
            limits,
            records,
            identify,
        })
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

struct Control {
    commands: async_mpsc::Receiver<Command>,
    stop: Arc<AtomicBool>,
    connected: Arc<AtomicU64>,
    startup: Startup,
    shared: Arc<Shared>,
    announce: Vec<Multiaddr>,
}

/// Remote address per live connection, so gossip can tell loopback requesters.
#[derive(Default)]
struct Remotes(HashMap<ConnectionId, (Multiaddr, bool)>);

impl Remotes {
    fn loopback(&self, connection: ConnectionId) -> bool {
        self.0
            .get(&connection)
            .is_some_and(|(address, _)| is_loopback(address))
    }

    fn outbound(&self, connection: ConnectionId) -> bool {
        self.0
            .get(&connection)
            .is_some_and(|(_, outbound)| *outbound)
    }
}

async fn run(
    engine: Arc<Engine>,
    identity: Keypair,
    listen: Option<Multiaddr>,
    control: Control,
) -> Result<(), Error> {
    let Control {
        mut commands,
        stop,
        connected,
        startup,
        shared,
        announce,
    } = control;
    let genesis = engine.status()?.chain_genesis;
    let mut swarm = swarm(identity)?;
    for address in announce {
        swarm.add_external_address(address);
    }
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
        .spawn(move || serve(&engine, genesis, &serving_stop, input, served))?;
    if !listening {
        let _ = ready.take().unwrap().send(Ok(None));
    }
    let mut pending = HashMap::<OutboundRequestId, Pending>::new();
    let mut inbound = HashSet::new();
    let mut remotes = Remotes::default();
    let mut dials = Dials::default();
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
                dials.expire();
            }
            command = commands.recv() => {
                let command = match command {
                    Some(Command::Fetch(fetch)) => fetch,
                    // A Fetch queued for this peer since the rejection keeps its connection.
                    Some(Command::Disconnect(peer)) => {
                        if !pending.values().any(|p| p.peer == peer) { let _ = swarm.disconnect_peer_id(peer); }
                        continue;
                    }
                    Some(Command::Dial(dial)) => { dials.start(&mut swarm, dial); continue; }
                    None => break Ok(()),
                };
                if Instant::now() >= command.deadline || pending.len() >= MAX_PENDING
                    || pending.values().any(|p| p.peer == command.peer) {
                    command.answer.fail(Error::Busy("peer acquisition capacity or deadline".into()));
                    continue;
                }
                let request = Request { version: VERSION, chain_genesis: genesis, kind: command.kind };
                let id = swarm.behaviour_mut().records.send_request_with_addresses(
                    &command.peer, request, command.addresses);
                pending.insert(id, Pending { peer: command.peer, kind: command.kind, deadline: command.deadline, answer: command.answer });
            }
            response = responses.recv() => {
                let Some(mut response) = response else { break Err(Error::Invalid("peer archive reader stopped".into())); };
                if response.channel.is_open() {
                    if !bytes.take(u64::try_from(response.bytes.saturating_sub(256)).unwrap_or(u64::MAX)) { response.response.result = Reply::Busy; }
                    let _ = swarm.behaviour_mut().records.send_response(response.channel, response.response);
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { mut address, .. } => {
                    address.push(Protocol::P2p(*swarm.local_peer_id()));
                    if let Some(ready) = ready.take() { let _ = ready.send(Ok(Some(address))); }
                }
                SwarmEvent::ListenerError { error, .. } if ready.is_some() => break Err(Error::Io(error)),
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                    remotes.0.insert(connection_id, (endpoint.get_remote_address().clone(), endpoint.is_dialer()));
                    dials.established(connection_id, peer_id);
                    if num_established.get() == 1 {
                        connected.fetch_add(1, Ordering::Relaxed);
                        shared.set_connected(peer_id, true);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                    remotes.0.remove(&connection_id);
                    if num_established == 0 {
                        connected.fetch_sub(1, Ordering::Relaxed);
                        shared.set_connected(peer_id, false);
                    }
                }
                SwarmEvent::OutgoingConnectionError { connection_id, peer_id, error } => {
                    // Queued before request-response reports the same DialFailure.
                    if let (Some(peer), DialError::Denied { cause }) = (peer_id, &error) {
                        if let Some(LimitDenied(limit)) = cause.downcast_ref::<LimitDenied>() { release_denied(&mut pending, peer, *limit); }
                    }
                    dials.failed(connection_id, &error);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { connection_id, peer_id, info })) => {
                    // Inbound peers could steer our address; only dialed peers witness it.
                    if remotes.outbound(connection_id) {
                        if let Some(confirmed) = shared.observe(info.observed_addr, peer_id) { swarm.add_external_address(confirmed); }
                    }
                    shared.identified(peer_id, info.listen_addrs);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Records(event)) => match event {
                    request_response::Event::Message { peer, connection_id, message: Message::Request { request_id, request, channel } } => {
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
                            else if let Kind::Peers { limit } = request.kind {
                                // Gossip is answered from memory, never by the archive reader.
                                Some(shared.serve(peer, remotes.loopback(connection_id), limit))
                            }
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
                            value.answer.fail(Error::Transport(error.to_string()));
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
    dials.close();
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

/// The bounded archive reader: one local lookup per job, sized before sending.
fn serve(
    engine: &Engine,
    genesis: BlockHash,
    stop: &AtomicBool,
    input: mpsc::Receiver<ServeJob>,
    served: async_mpsc::Sender<Served>,
) {
    while let Ok(job) = input.recv() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !job.channel.is_open() || Instant::now() >= job.deadline {
            continue;
        }
        let result = lookup(engine, &job.request);
        if stop.load(Ordering::Acquire) || !job.channel.is_open() || Instant::now() >= job.deadline
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
        let reply = Served {
            channel: job.channel,
            response,
            bytes: count.0,
        };
        if served.blocking_send(reply).is_err() {
            break;
        }
    }
}

/// A dial refused by our own limits is local capacity: the waiting requests
/// fail with which limit refused it, never blaming the peer.
fn release_denied(
    pending: &mut HashMap<OutboundRequestId, Pending>,
    peer: PeerId,
    limit: DialLimit,
) {
    pending.retain(|_, value| {
        if value.peer != peer {
            return true;
        }
        value.answer.fail(Error::DialDenied(limit));
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
        Reply::Busy => Err(Error::PeerBusy),
        _ => Err(Error::Invalid(
            "peer refused record or returned wrong network".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

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
