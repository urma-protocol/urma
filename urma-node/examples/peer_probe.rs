//! Operator-run two-process probe using public signed fixtures, never a live chain.
//! Each invocation needs its own fresh/empty --data directory. `serve --listen`
//! binds only the supplied socket; `client --peer` dials only the supplied IP/TCP
//! Multiaddr with its terminal /p2p identity. All transport keys are ephemeral.
//!
//! Send `shutdown\n` to server stdin. Its wait expires at 120 seconds from
//! transport startup; shutdown joins the network before dropping the Engine.
//! The bounded stdin reader is detached: if stdin remains blocked at the deadline,
//! that thread lives until process exit. This is not a hard interrupt of I/O.
//! The fixtures authenticate signatures and witness inclusion in our explicitly
//! selected synthetic block, not PoW, difficulty, scripts, UTXOs or consensus.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, Network, ScriptBuf, Transaction, Txid, Witness,
    block::Header,
    blockdata::constants::genesis_block,
    consensus::{deserialize, serialize},
    hashes::Hash,
};
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use urma_chain::{
    inclusion::TransactionProof, observation::Chain, validation::validate_block_integrity,
};
use urma_core::multipart::VerifiedRecord;
use urma_node::{
    Error as NodeError,
    engine::Engine,
    model::{API_VERSION, ArchiveConfig, ArchiveStatus, ChainPoint, RecordPackage, Retention},
    peer::PeerNetwork,
    peerbook::PeerAddress,
    retrieval::RecordSource,
    source::ChainSource,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const HEIGHT: u64 = 100;
const SERVER_WAIT: Duration = Duration::from_secs(120);
const PROFILE_COMMIT: &[u8] =
    include_bytes!("../../tests/vectors/proof-profile-utf8-two-byte128.commit");
const PROFILE_REVEAL: &[u8] =
    include_bytes!("../../tests/vectors/proof-profile-utf8-two-byte128.reveal");
const POST_COMMIT: &[u8] = include_bytes!("../../tests/vectors/proof-post.commit");
const POST_REVEAL: &[u8] = include_bytes!("../../tests/vectors/proof-post.reveal");

#[derive(Parser)]
#[command(about = "Explicit synthetic-fixture peer probe; no live-chain consensus claim")]
struct Args {
    /// Owned fresh/empty archive directory; never stores transport private keys.
    #[arg(long, global = true, value_name = "OWNED_DIRECTORY")]
    data: Option<PathBuf>,
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    Serve {
        #[arg(long)]
        listen: SocketAddr,
    },
    Client {
        /// IP/TCP address including the server's terminal /p2p/PeerId.
        #[arg(long)]
        peer: Multiaddr,
    },
}

struct Pair {
    commit: Transaction,
    reveal: Transaction,
    raw_commit: &'static [u8],
    raw_reveal: &'static [u8],
}

impl Pair {
    fn load(raw_commit: &'static [u8], raw_reveal: &'static [u8]) -> Result<Self> {
        let commit = deserialize(raw_commit)?;
        let reveal: Transaction = deserialize(raw_reveal)?;
        VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
        require(
            serialize(&commit) == raw_commit,
            "fixture commit bytes changed",
        )?;
        require(
            serialize(&reveal) == raw_reveal,
            "fixture reveal bytes changed",
        )?;
        Ok(Self {
            commit,
            reveal,
            raw_commit,
            raw_reveal,
        })
    }

    fn id(&self) -> Txid {
        self.reveal.compute_txid()
    }

    fn package(&self, block: &Block) -> Result<RecordPackage> {
        let position = block
            .txdata
            .iter()
            .position(|tx| tx.compute_txid() == self.id())
            .ok_or_else(|| io::Error::other("fixture missing from synthetic block"))?;
        Ok(RecordPackage {
            version: API_VERSION,
            chain_genesis: Chain::BitcoinRegtest.genesis()?.0,
            block: point(block),
            reveal: TransactionProof::from_block(
                block,
                u32::try_from(position)?,
                self.raw_reveal.to_vec(),
                serialize(&block.txdata[0]),
            )?,
            commit: self.raw_commit.to_vec(),
        })
    }
}

struct Fixtures {
    profile: Pair,
    post: Pair,
    block: Block,
}

impl Fixtures {
    fn load() -> Result<Self> {
        let profile = Pair::load(PROFILE_COMMIT, PROFILE_REVEAL)?;
        let post = Pair::load(POST_COMMIT, POST_REVEAL)?;
        let mut block = genesis_block(Network::Regtest);
        block.header.nonce = 1;
        block.header.bits = CompactTarget::from_consensus(0);
        block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
        block.txdata.extend([
            profile.commit.clone(),
            profile.reveal.clone(),
            post.commit.clone(),
            post.reveal.clone(),
        ]);
        let root = block
            .witness_root()
            .ok_or_else(|| io::Error::other("synthetic block has no witness root"))?;
        let commitment = Block::compute_witness_commitment(&root, &[0; 32]);
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(commitment.as_byte_array());
        block.txdata[0].output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        });
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| io::Error::other("synthetic block has no merkle root"))?;
        validate_block_integrity(&block, block.block_hash())?;
        Ok(Self {
            profile,
            post,
            block,
        })
    }

    fn config(&self) -> ArchiveConfig {
        ArchiveConfig {
            chain: Chain::BitcoinRegtest,
            application_start: point(&self.block),
            retention: Retention::Unpruned,
        }
    }
}

fn point(block: &Block) -> ChainPoint {
    ChainPoint {
        height: HEIGHT,
        hash: block.block_hash(),
    }
}

// Explicit fixture selection, not an implementation of live header consensus.
struct FixtureSource {
    header: Header,
    raw: Vec<u8>,
    body_calls: AtomicUsize,
}

impl FixtureSource {
    fn new(block: &Block) -> Self {
        Self {
            header: block.header,
            raw: serialize(block),
            body_calls: AtomicUsize::new(0),
        }
    }

    fn bodies(&self) -> usize {
        self.body_calls.load(Ordering::Relaxed)
    }
}

impl ChainSource for FixtureSource {
    fn genesis(&self) -> std::result::Result<BlockHash, NodeError> {
        Chain::BitcoinRegtest
            .genesis()
            .map(|id| id.0)
            .map_err(|e| NodeError::Invalid(e.to_string()))
    }

    fn tip(&self) -> std::result::Result<ChainPoint, NodeError> {
        Ok(ChainPoint {
            height: HEIGHT,
            hash: self.header.block_hash(),
        })
    }

    fn header(&self, height: u64) -> std::result::Result<Header, NodeError> {
        if height != HEIGHT {
            return Err(NodeError::Invalid("fixture height unavailable".into()));
        }
        Ok(self.header)
    }

    fn block(&self, height: u64) -> std::result::Result<Vec<u8>, NodeError> {
        self.body_calls.fetch_add(1, Ordering::Relaxed);
        if height != HEIGHT {
            return Err(NodeError::Invalid("fixture body unavailable".into()));
        }
        Ok(self.raw.clone())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(io::Error::other(message).into());
    }
    Ok(())
}

fn same<T: Serialize>(actual: &T, expected: &T, message: &str) -> Result<()> {
    require(
        serde_json::to_vec(actual)? == serde_json::to_vec(expected)?,
        message,
    )
}

fn exact_package(package: &RecordPackage, pair: &Pair, block: &Block) -> Result<()> {
    require(
        package.commit == pair.raw_commit,
        "peer commit bytes differ from fixture",
    )?;
    require(
        package.reveal.transaction == pair.raw_reveal,
        "peer reveal bytes differ from fixture",
    )?;
    same(
        package,
        &pair.package(block)?,
        "peer package differs from exact local proof package",
    )
}

fn receipt(event: &str, fields: Value) -> Result<()> {
    let mut value = json!({
        "event": event,
        "fixture_kind": "public-signed-profile128-and-post/synthetic-witness-block",
        "chain": "bitcoin-regtest",
        "selection": "explicit-in-memory-fixture",
        "live_chain": false,
        "pow_or_consensus_claim": false,
    });
    let fields = fields
        .as_object()
        .ok_or_else(|| io::Error::other("receipt must be an object"))?;
    value.as_object_mut().unwrap().extend(fields.clone());
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn fresh_data(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            require(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "--data must be a real owned directory",
            )?;
            require(
                fs::read_dir(path)?.next().is_none(),
                "--data must be fresh/empty",
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    // Engine creates the directory and holds the exclusive archive-owner lock.
    Ok(())
}

fn peer_address(address: Multiaddr) -> Result<PeerAddress> {
    let peer = match address.iter().last() {
        Some(Protocol::P2p(peer)) => peer,
        _ => return Err(io::Error::other("--peer requires terminal /p2p/PeerId").into()),
    };
    Ok(PeerAddress::new(peer, address)?)
}

fn listener(socket: SocketAddr) -> Multiaddr {
    let mut address = Multiaddr::empty();
    address.push(match socket.ip() {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    });
    address.push(Protocol::Tcp(socket.port()));
    address
}

fn selected_only(
    engine: &Engine,
    source: &FixtureSource,
    fixtures: &Fixtures,
) -> Result<ArchiveStatus> {
    let status = engine.status()?;
    require(
        status.selected_tip == Some(point(&fixtures.block)),
        "fixture tip not selected",
    )?;
    require(
        status.scanned_blocks == 0 && status.indexed_through.is_none(),
        "selective path advanced scan coverage",
    )?;
    require(source.bodies() == 0, "selective path fetched a full block")?;
    require(
        engine.record(fixtures.post.id())?.is_none(),
        "post appeared before full-block audit",
    )?;
    Ok(status)
}

fn audit(engine: &Engine, source: &FixtureSource, fixtures: &Fixtures) -> Result<ArchiveStatus> {
    let status = engine.scan_next()?;
    require(
        status.scanned_blocks == 1 && status.indexed_through == Some(point(&fixtures.block)),
        "full scan coverage mismatch",
    )?;
    require(
        source.bodies() == 1 && status.stored_transactions == 4,
        "full scan transaction/body count mismatch",
    )?;
    require(
        status.unresolved_dependencies == 0,
        "full scan left unresolved dependencies",
    )?;
    for pair in [&fixtures.profile, &fixtures.post] {
        let record = engine
            .record(pair.id())?
            .ok_or_else(|| io::Error::other("full scan did not discover both records"))?;
        exact_package(&record.package, pair, &fixtures.block)?;
    }
    Ok(status)
}

// Always stop owned transport(s) before dropping the Engine. Reopen locally to
// verify owner-lock release and preserved state; no additional networking.
fn finish(
    role: &str,
    data: &Path,
    config: ArchiveConfig,
    engine: Arc<Engine>,
    network: Option<PeerNetwork>,
    outcome: Result<()>,
) -> Result<()> {
    let stopped = network.map_or(Ok(()), PeerNetwork::shutdown);
    let status = engine.status();
    drop(engine);
    let released = (|| {
        let reopened = Engine::open(data, config, None)?;
        if let Ok(status) = &status {
            same(
                &reopened.status()?,
                status,
                "archive state changed during shutdown",
            )?;
        }
        drop(reopened);
        Ok::<_, Box<dyn std::error::Error>>(())
    })();
    receipt(
        "clean",
        json!({
            "role": role,
            "ok": outcome.is_ok() && stopped.is_ok() && status.is_ok() && released.is_ok(),
            "network_shutdown": stopped.is_ok(),
            "engine_dropped": true,
            "archive_owner_released": released.is_ok(),
        }),
    )?;
    stopped?;
    status?;
    released?;
    outcome
}

fn wait_shutdown(started: Instant) -> Result<&'static str> {
    let (send, receive) = mpsc::sync_channel(1);
    // At most 256 bytes are retained, and the server never joins this reader.
    let _reader = std::thread::Builder::new()
        .name("peer-probe-stdin".into())
        .spawn(move || {
            let mut line = Vec::new();
            let result = io::stdin()
                .lock()
                .take(256)
                .read_until(b'\n', &mut line)
                .map(|count| (count, line));
            let _ = send.send(result);
        })?;
    match receive.recv_timeout(SERVER_WAIT.saturating_sub(started.elapsed())) {
        Ok(Ok((0, _))) => Ok("stdin_eof"),
        Ok(Ok((_, line))) if line == b"shutdown\n" || line == b"shutdown\r\n" => {
            Ok("stdin_shutdown")
        }
        Ok(Ok(_)) => Err(io::Error::other("expected bounded stdin line: shutdown").into()),
        Ok(Err(error)) => Err(error.into()),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok("120s_deadline"),
        Err(error) => Err(error.into()),
    }
}

fn serve(data: &Path, listen: SocketAddr, fixtures: &Fixtures) -> Result<()> {
    let source = Arc::new(FixtureSource::new(&fixtures.block));
    let config = fixtures.config();
    let engine = Arc::new(Engine::open(data, config.clone(), Some(source.clone()))?);
    engine.synchronize_headers()?;
    audit(&engine, &source, fixtures)?;
    let started = Instant::now();
    let network = PeerNetwork::start(
        engine.clone(),
        Keypair::generate_ed25519(),
        Some(listener(listen)),
        Vec::new(),
    )?;
    let outcome = (|| {
        receipt(
            "ready",
            json!({
                "role": "serve",
                "peer_id": network.peer_id().to_string(),
                "address": network.listen_address().ok_or_else(|| io::Error::other("listener has no address"))?.to_string(),
                "block": point(&fixtures.block),
                "root_txid": fixtures.profile.id().to_string(),
                "root_kind": "profile (not multipart root)",
                "profile_txid": fixtures.profile.id().to_string(),
                "post_txid": fixtures.post.id().to_string(),
                "record_count": 2,
                "transport_key": "generated-ephemeral-not-persisted",
                "stdin_wait_max_seconds": SERVER_WAIT.as_secs(),
                "status": engine.status()?,
            }),
        )?;
        receipt(
            "shutdown_requested",
            json!({"role": "serve", "reason": wait_shutdown(started)?}),
        )
    })();
    finish("serve", data, config, engine, Some(network), outcome)
}

fn client(data: &Path, address: PeerAddress, fixtures: &Fixtures) -> Result<()> {
    let source = Arc::new(FixtureSource::new(&fixtures.block));
    let config = fixtures.config();
    let engine = Arc::new(Engine::open(data, config.clone(), Some(source.clone()))?);
    engine.synchronize_headers()?;
    selected_only(&engine, &source, fixtures)?;
    let mut network = Some(PeerNetwork::start(
        engine.clone(),
        Keypair::generate_ed25519(),
        None,
        Vec::new(),
    )?);
    let outcome = (|| {
        let first_peer_id = network.as_ref().unwrap().peer_id();
        let before_fetch = engine.status()?;
        let package = network
            .as_ref()
            .unwrap()
            .source(address.clone())
            .fetch(fixtures.profile.id())?
            .ok_or_else(|| io::Error::other("server did not return profile"))?;
        same(
            &engine.status()?,
            &before_fetch,
            "direct peer fetch mutated the archive",
        )?;
        exact_package(&package, &fixtures.profile, &fixtures.block)?;
        let admitted = engine.admit_record(package)?;
        require(
            admitted.txid == fixtures.profile.id(),
            "admission returned another TXID",
        )?;
        let cached = engine
            .record(fixtures.profile.id())?
            .ok_or_else(|| io::Error::other("admitted profile missing"))?;
        exact_package(&cached.package, &fixtures.profile, &fixtures.block)?;
        let selected = selected_only(&engine, &source, fixtures)?;
        require(
            selected.stored_transactions == 2,
            "selective admission did not retain exact commit/reveal pair",
        )?;
        receipt(
            "selective",
            json!({
                "role": "client", "server_peer_id": address.peer_id().to_string(),
                "client_peer_id": first_peer_id.to_string(), "profile_txid": fixtures.profile.id().to_string(),
                "exact_package_bytes": true, "exact_commit_reveal_bytes": true,
                "post_locally_absent": true, "body_calls": source.bodies(), "status": selected,
            }),
        )?;

        // Close the first connection, then use a fresh client transport key for
        // the wrong-identity attempt and the subsequent genuine reconnect.
        network.take().unwrap().shutdown()?;
        network = Some(PeerNetwork::start(
            engine.clone(),
            Keypair::generate_ed25519(),
            None,
            Vec::new(),
        )?);
        let fresh_peer_id = network.as_ref().unwrap().peer_id();
        require(
            fresh_peer_id != first_peer_id,
            "client transport identity was not fresh",
        )?;
        let wrong_id: PeerId = Keypair::generate_ed25519().public().to_peer_id();
        require(
            wrong_id != address.peer_id(),
            "wrong-identity control accidentally matched server",
        )?;
        let mut wrong_socket = address.address().clone();
        let _ = wrong_socket.pop();
        wrong_socket.push(Protocol::P2p(wrong_id));
        let wrong = PeerAddress::new(wrong_id, wrong_socket)?;
        let before_wrong = engine.status()?;
        let rejected = match network
            .as_ref()
            .unwrap()
            .source(wrong)
            .fetch(fixtures.profile.id())
        {
            Err(error) => error,
            Ok(_) => return Err(io::Error::other("wrong expected PeerId was not refused").into()),
        };
        same(
            &engine.status()?,
            &before_wrong,
            "wrong PeerId attempt mutated archive status",
        )?;
        same(
            &engine.record(fixtures.profile.id())?,
            &Some(cached),
            "wrong PeerId attempt mutated retained profile",
        )?;
        selected_only(&engine, &source, fixtures)?;
        receipt(
            "wrong_peer_id",
            json!({
                "role": "client", "rejected": true, "archive_unchanged": true,
                "same_ip_tcp_socket": true, "wrong_expected_peer_id": wrong_id.to_string(),
                "fresh_client_peer_id": fresh_peer_id.to_string(), "error": rejected.to_string(),
            }),
        )?;

        let reconnected = network
            .as_ref()
            .unwrap()
            .source(address.clone())
            .fetch(fixtures.profile.id())?
            .ok_or_else(|| io::Error::other("correct-identity reconnect did not return profile"))?;
        exact_package(&reconnected, &fixtures.profile, &fixtures.block)?;
        same(
            &engine.status()?,
            &before_wrong,
            "reconnect direct fetch mutated archive status",
        )?;
        selected_only(&engine, &source, fixtures)?;
        receipt(
            "reconnect",
            json!({
                "role": "client", "correct_peer_id": address.peer_id().to_string(),
                "fresh_client_peer_id": fresh_peer_id.to_string(), "exact_package_bytes": true,
            }),
        )?;
        let status = audit(&engine, &source, fixtures)?;
        receipt(
            "audit",
            json!({
                "role": "client", "record_count": 2, "newly_discovered_post": true,
                "profile_txid": fixtures.profile.id().to_string(), "post_txid": fixtures.post.id().to_string(),
                "body_calls": source.bodies(), "status": status,
            }),
        )
    })();
    finish("client", data, config, engine, network, outcome)
}

fn run(args: Args) -> Result<()> {
    // Destination syntax and embedded fixtures are checked before archive writes
    // or transport startup. There are no seeds, DNS or implicit listeners.
    // Clap forbids required global options, so require --data here; it remains
    // accepted on either side of the role subcommand, with no implicit default.
    let data = args
        .data
        .ok_or_else(|| io::Error::other("--data OWNED_DIRECTORY is required"))?;
    let peer = match &args.role {
        Role::Client { peer } => Some(peer_address(peer.clone())?),
        Role::Serve { .. } => None,
    };
    let fixtures = Fixtures::load()?;
    fresh_data(&data)?;
    match args.role {
        Role::Serve { listen } => serve(&data, listen, &fixtures),
        Role::Client { .. } => client(&data, peer.unwrap(), &fixtures),
    }
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                json!({"event": "error", "fixture_probe": true, "error": error.to_string()})
            );
            ExitCode::FAILURE
        }
    }
}
