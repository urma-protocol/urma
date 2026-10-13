//! Test-side codec peer for peer_inventory.rs and peer_discovery.rs: a raw
//! client, a proxy to an upstream node that rewrites its inventory pages
//! (drops every entry naming one txid, or moves every entry out of the
//! requested range, or into an unselected block), or a responder answering
//! Peers with a fixed list.
//! Loaded with #[path]; it is not part of the shared common module.
use bitcoin::{BlockHash, hashes::Hash};
use libp2p::{
    Multiaddr, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    multiaddr::Protocol,
    noise,
    request_response::{self, Event, Message, OutboundRequestId, ProtocolSupport, ResponseChannel},
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::mpsc as async_mpsc;
use urma_chain::observation::Chain;
use urma_node::{
    peer_codec::Codec,
    peer_protocol::{GossipPeer, Kind, PROTOCOL, Reply, Request, Response},
    peerbook::PeerAddress,
};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_BOUND: Duration = Duration::from_secs(12);

type Answer = mpsc::SyncSender<Result<Response, String>>;

/// How the proxy rewrites upstream inventory pages. `Stale` lists every entry
/// in a block outside the selected chain, as a peer on another fork would.
pub enum Rewrite {
    Hide(String),
    OutOfRange,
    Stale,
}

struct Call {
    to: PeerAddress,
    request: Request,
    answer: Answer,
}

pub struct RawPeer {
    address: Option<PeerAddress>,
    calls: async_mpsc::Sender<Call>,
    seen: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

struct RawState {
    upstream: Option<(PeerAddress, Rewrite)>,
    gossip: Option<Vec<GossipPeer>>,
    seen: Arc<Mutex<Vec<Request>>>,
    ready: mpsc::SyncSender<Multiaddr>,
    pending: HashMap<OutboundRequestId, Answer>,
    forwarded: HashMap<OutboundRequestId, ResponseChannel<Response>>,
}

fn raw_swarm(key: Keypair) -> Swarm<request_response::Behaviour<Codec>> {
    let behaviour = request_response::Behaviour::with_codec(
        Codec,
        [(StreamProtocol::new(PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(8)),
    );
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(20)))
        .build()
}

fn rewrite(mut response: Response, rewrite: &Rewrite) -> Response {
    if let Reply::Inventory(page) = &mut response.result {
        match rewrite {
            Rewrite::Hide(hide) => page.entries.retain(|entry| entry.txid.to_string() != *hide),
            Rewrite::OutOfRange => {
                for entry in &mut page.entries {
                    entry.height = u64::MAX;
                }
            }
            Rewrite::Stale => {
                for entry in &mut page.entries {
                    entry.block_hash = BlockHash::all_zeros();
                }
            }
        }
    }
    response
}

fn raw_message(
    swarm: &mut Swarm<request_response::Behaviour<Codec>>,
    state: &mut RawState,
    message: Message<Request, Response>,
) {
    match message {
        Message::Request {
            request, channel, ..
        } => {
            state.seen.lock().unwrap().push(request.clone());
            if let (Some(peers), Kind::Peers { limit }) = (&state.gossip, request.kind) {
                let limit = usize::try_from(limit).unwrap();
                let response = Response {
                    version: request.version,
                    chain_genesis: request.chain_genesis,
                    kind: request.kind,
                    result: Reply::Peers(peers.iter().take(limit).cloned().collect()),
                };
                let _ = swarm.behaviour_mut().send_response(channel, response);
            } else if let Some((upstream, _)) = &state.upstream {
                let id = swarm.behaviour_mut().send_request_with_addresses(
                    &upstream.peer_id(),
                    request,
                    vec![upstream.address().clone()],
                );
                state.forwarded.insert(id, channel);
            }
        }
        Message::Response {
            request_id,
            response,
        } => {
            if let Some(channel) = state.forwarded.remove(&request_id) {
                let response = rewrite(response, &state.upstream.as_ref().unwrap().1);
                let _ = swarm.behaviour_mut().send_response(channel, response);
            } else if let Some(answer) = state.pending.remove(&request_id) {
                let _ = answer.try_send(Ok(response));
            }
        }
    }
}

fn raw_event(
    swarm: &mut Swarm<request_response::Behaviour<Codec>>,
    state: &mut RawState,
    event: SwarmEvent<Event<Request, Response>>,
) {
    match event {
        SwarmEvent::NewListenAddr { mut address, .. } => {
            address.push(Protocol::P2p(*swarm.local_peer_id()));
            let _ = state.ready.try_send(address);
        }
        SwarmEvent::Behaviour(Event::Message { message, .. }) => raw_message(swarm, state, message),
        SwarmEvent::Behaviour(Event::OutboundFailure {
            request_id, error, ..
        }) => {
            state.forwarded.remove(&request_id);
            if let Some(answer) = state.pending.remove(&request_id) {
                let _ = answer.try_send(Err(error.to_string()));
            }
        }
        _ => (),
    }
}

async fn raw_loop(
    key: Keypair,
    mut calls: async_mpsc::Receiver<Call>,
    mut state: RawState,
    stop: Arc<AtomicBool>,
) {
    let mut swarm = raw_swarm(key);
    let listen = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm.listen_on(listen).unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    while !stop.load(Ordering::Acquire) {
        tokio::select! {
            _ = tick.tick() => (),
            call = calls.recv() => {
                let Some(call) = call else { return };
                let id = swarm.behaviour_mut().send_request_with_addresses(
                    &call.to.peer_id(), call.request, vec![call.to.address().clone()]);
                state.pending.insert(id, call.answer);
            }
            event = swarm.select_next_some() => raw_event(&mut swarm, &mut state, event),
        }
    }
}

impl RawPeer {
    pub fn start(upstream: Option<(PeerAddress, Rewrite)>) -> Self {
        Self::spawn(upstream, None)
    }

    /// Answers every Peers request with `peers`; other requests go unanswered.
    pub fn gossiping(peers: Vec<GossipPeer>) -> Self {
        Self::spawn(None, Some(peers))
    }

    fn spawn(upstream: Option<(PeerAddress, Rewrite)>, gossip: Option<Vec<GossipPeer>>) -> Self {
        let key = Keypair::generate_ed25519();
        let id = key.public().to_peer_id();
        let (calls, receiver) = async_mpsc::channel(4);
        let (ready, listening) = mpsc::sync_channel(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let state = RawState {
            upstream,
            gossip,
            seen: seen.clone(),
            ready,
            pending: HashMap::new(),
            forwarded: HashMap::new(),
        };
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(raw_loop(key, receiver, state, flag));
        });
        let mut peer = Self {
            address: None,
            calls,
            seen,
            stop,
            worker: Some(worker),
        };
        let listen = listening.recv_timeout(START_TIMEOUT).expect("raw listener");
        peer.address = Some(PeerAddress::new(id, listen).unwrap());
        peer
    }

    pub fn address(&self) -> PeerAddress {
        self.address.clone().unwrap()
    }

    pub fn asked(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn requests(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }

    pub fn call(&self, to: &PeerAddress, version: u32, kind: Kind) -> Reply {
        // The server's per-identity bucket refills four requests per second.
        thread::sleep(Duration::from_millis(300));
        let genesis = Chain::BitcoinRegtest.genesis().unwrap().0;
        let request = Request {
            version,
            chain_genesis: genesis,
            kind,
        };
        let (answer, receiver) = mpsc::sync_channel(1);
        let to = to.clone();
        self.calls
            .try_send(Call {
                to,
                request,
                answer,
            })
            .unwrap();
        let response = receiver.recv_timeout(CALL_BOUND).unwrap().unwrap();
        assert_eq!(response.chain_genesis, genesis);
        response.result
    }
}

impl Drop for RawPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("raw peer worker panicked");
            }
        }
    }
}
