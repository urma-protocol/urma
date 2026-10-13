//! Test-side serving peer for parity.rs: answers the current record protocol
//! with one fixed inventory placement and one fixed package, whatever its
//! validity. Loaded with #[path]; it is not part of the shared common module.
use bitcoin::BlockHash;
use libp2p::{
    Multiaddr, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    multiaddr::Protocol,
    noise,
    request_response::{self, Event, Message, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use urma_node::{
    model::RecordPackage,
    peer_codec::Codec,
    peer_protocol::{InventoryPage, Kind, PROTOCOL, Placement, Reply, Response, VERSION},
    peerbook::PeerAddress,
};

const START_TIMEOUT: Duration = Duration::from_secs(10);

/// What one peer advertises and serves; the package is never checked here.
#[derive(Clone)]
pub struct Offer {
    pub genesis: BlockHash,
    pub placement: Placement,
    pub package: RecordPackage,
}

pub struct ServingPeer {
    address: PeerAddress,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

fn swarm(key: Keypair) -> Swarm<request_response::Behaviour<Codec>> {
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
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build()
}

fn answer(offer: &Offer, kind: &Kind, served: &AtomicUsize) -> Reply {
    match *kind {
        Kind::Inventory {
            from_height,
            to_height,
            after,
            ..
        } => {
            let at = offer.placement.height;
            let fresh = after
                .is_none_or(|last| (last.height, last.position) < (at, offer.placement.position));
            let listed = (from_height..=to_height).contains(&at) && fresh;
            Reply::Inventory(InventoryPage {
                scanned_through: Some(to_height),
                entries: if listed {
                    vec![offer.placement]
                } else {
                    Vec::new()
                },
                more: false,
            })
        }
        Kind::Record { txid } if txid == offer.placement.txid => {
            served.fetch_add(1, Ordering::AcqRel);
            Reply::Record(Box::new(offer.package.clone()))
        }
        Kind::Record { .. } | Kind::Parent { .. } => Reply::Missing,
        // Gossip and chain probes: same network, no routing hints to share.
        Kind::Peers { .. } => Reply::Peers(Vec::new()),
    }
}

/// What the daemon did to this peer, observed from the peer's side.
#[derive(Default)]
struct Counters {
    served: AtomicUsize,
    requests: AtomicUsize,
    connections: AtomicUsize,
}

async fn serve(
    (key, port): (Keypair, u16),
    offer: Offer,
    ready: mpsc::SyncSender<Multiaddr>,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
) {
    let mut swarm = swarm(key);
    let listen = format!("/ip4/127.0.0.1/tcp/{port}");
    swarm.listen_on(listen.parse().unwrap()).unwrap();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    while !stop.load(Ordering::Acquire) {
        tokio::select! {
            _ = tick.tick() => (),
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { mut address, .. } => {
                    address.push(Protocol::P2p(*swarm.local_peer_id()));
                    let _ = ready.try_send(address);
                }
                SwarmEvent::ConnectionEstablished { .. } => {
                    counters.connections.fetch_add(1, Ordering::AcqRel);
                }
                SwarmEvent::ConnectionClosed { .. } => {
                    counters.connections.fetch_sub(1, Ordering::AcqRel);
                }
                SwarmEvent::Behaviour(Event::Message {
                    message: Message::Request { request, channel, .. },
                    ..
                }) => {
                    counters.requests.fetch_add(1, Ordering::AcqRel);
                    let result = answer(&offer, &request.kind, &counters.served);
                    let response = Response {
                        version: VERSION,
                        chain_genesis: offer.genesis,
                        kind: request.kind,
                        result,
                    };
                    let _ = swarm.behaviour_mut().send_response(channel, response);
                }
                _ => (),
            },
        }
    }
}

impl ServingPeer {
    pub fn start(offer: Offer) -> Self {
        Self::start_at(offer, Keypair::generate_ed25519(), 0)
    }

    /// Listen with a known identity on a chosen port (0 for ephemeral), so
    /// the address can be configured before the peer comes up.
    pub fn start_at(offer: Offer, key: Keypair, port: u16) -> Self {
        let id = key.public().to_peer_id();
        let (ready, listening) = mpsc::sync_channel(1);
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (count, flag) = (counters.clone(), stop.clone());
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(serve((key, port), offer, ready, count, flag));
        });
        let listen = listening
            .recv_timeout(START_TIMEOUT)
            .expect("serving peer listener");
        Self {
            address: PeerAddress::new(id, listen).unwrap(),
            counters,
            stop,
            worker: Some(worker),
        }
    }

    pub fn address(&self) -> &PeerAddress {
        &self.address
    }

    /// Record requests answered with this peer's package.
    pub fn served(&self) -> usize {
        self.counters.served.load(Ordering::Acquire)
    }

    /// Requests of any kind received from anyone.
    pub fn requests(&self) -> usize {
        self.counters.requests.load(Ordering::Acquire)
    }

    /// Connections currently established with this peer.
    pub fn connections(&self) -> usize {
        self.counters.connections.load(Ordering::Acquire)
    }
}

impl Drop for ServingPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("serving peer worker panicked");
            }
        }
    }
}
