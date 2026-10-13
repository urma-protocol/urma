use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::AddrV2;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_runtime::config::{
    LITECOIN_MAINNET_CHECKPOINT, LITECOIN_TESTNET_CHECKPOINT, P2P_LITECOIN_NODE_MWEB,
};
use urma_runtime::error::Error;
use urma_runtime::p2p::{Discovery, Hello, Message, Next, P2pProvider, Peer};

const SAMPLE: usize = 20;
const FIRST: usize = 6;
const SERVICES: [(&str, u64); 8] = [
    ("NETWORK", 1),
    ("GETUTXO", 1 << 1),
    ("BLOOM", 1 << 2),
    ("WITNESS", 1 << 3),
    ("COMPACT_FILTERS", 1 << 6),
    ("NETWORK_LIMITED", 1 << 10),
    ("P2P_V2", 1 << 11),
    ("MWEB", P2P_LITECOIN_NODE_MWEB),
];
static START: OnceLock<Instant> = OnceLock::new();

fn at() -> String {
    format!("{:>6.1}s", elapsed())
}

fn elapsed() -> f64 {
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

struct Options {
    chain: Chain,
    peers: usize,
    seconds: u64,
    seeds: Vec<String>,
    verbose: bool,
    quiet: bool,
    hello: Hello,
    marks: Vec<u64>,
    catchup: Option<u64>,
    pinned: Vec<SocketAddr>,
    trace: bool,
}

struct Session {
    address: SocketAddr,
    agent: String,
    height: u64,
    opened: f64,
    closed: Option<f64>,
    reason: Option<String>,
    messages: usize,
    first: Vec<String>,
    advertised: usize,
}

#[derive(Default)]
struct Stats {
    seeded: HashSet<SocketAddr>,
    gossip: HashMap<String, &'static str>,
    dials: usize,
    failures: BTreeMap<String, usize>,
    sessions: Vec<Session>,
}

struct Shared {
    chain: Chain,
    height: u64,
    deadline: Instant,
    verbose: bool,
    quiet: bool,
    hello: Hello,
    discovery: Mutex<Discovery>,
    stats: Mutex<Stats>,
}

fn usage() -> Error {
    Error::Invalid(
        "usage: litecoin-peers [--testnet|--mainnet] [--peers N] [--seconds S] [--seed HOST]... \
         [--services none|LIST] [--agent UA] [--relay true|false] [--marks 120,300,600] \
         [--catchup BLOCKS] [--peer ADDR]... [--negotiate] [--trace] [--quiet] [--verbose]"
            .into(),
    )
}

fn service_flags(list: &str) -> Result<ServiceFlags, Error> {
    let mut bits = 0u64;
    for name in list.split(',').filter(|name| *name != "none") {
        let upper = name.to_ascii_uppercase();
        let found = SERVICES.iter().find(|(known, _)| {
            *known == upper || (upper == "LIMITED" && *known == "NETWORK_LIMITED")
        });
        let Some((_, bit)) = found else {
            return Err(Error::Invalid(format!("unknown service {name}")));
        };
        bits |= bit;
    }
    Ok(ServiceFlags::from(bits))
}

fn options() -> Result<Options, Error> {
    let mut options = Options {
        chain: Chain::LitecoinTestnet,
        peers: 8,
        seconds: 60,
        seeds: Vec::new(),
        verbose: false,
        quiet: false,
        hello: Hello::light(),
        marks: vec![120, 300, 600],
        catchup: None,
        pinned: Vec::new(),
        trace: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--testnet" => options.chain = Chain::LitecoinTestnet,
            "--mainnet" => options.chain = Chain::LitecoinMainnet,
            "--peers" => options.peers = args.next().ok_or_else(usage)?.parse()?,
            "--seconds" => options.seconds = args.next().ok_or_else(usage)?.parse()?,
            "--seed" => options.seeds.push(args.next().ok_or_else(usage)?),
            "--services" => {
                options.hello.services = service_flags(&args.next().ok_or_else(usage)?)?
            }
            "--agent" => options.hello.user_agent = args.next().ok_or_else(usage)?,
            "--relay" => {
                options.hello.relay = match args.next().ok_or_else(usage)?.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(usage()),
                }
            }
            "--catchup" => options.catchup = Some(args.next().ok_or_else(usage)?.parse()?),
            "--marks" => {
                let list = args.next().ok_or_else(usage)?;
                options.marks = list.split(',').map(str::parse).collect::<Result<_, _>>()?;
            }
            "--peer" => options.pinned.push(args.next().ok_or_else(usage)?.parse()?),
            "--negotiate" => options.hello.negotiate = true,
            "--trace" => options.trace = true,
            "--quiet" => options.quiet = true,
            "--verbose" => options.verbose = true,
            _ => return Err(usage()),
        }
    }
    Ok(options)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn services(flags: ServiceFlags) -> String {
    let bits = u64::from(flags);
    let mut names: Vec<String> = SERVICES
        .iter()
        .filter(|(_, bit)| bits & bit != 0)
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let known = SERVICES.iter().fold(0, |all, (_, bit)| all | bit);
    if bits & !known != 0 {
        names.push(format!("0x{:x}", bits & !known));
    }
    match names.is_empty() {
        true => "NONE".into(),
        false => names.join("|"),
    }
}

fn resolve(shared: &Shared, extra: &[String]) -> Vec<SocketAddr> {
    let params = shared.chain.params();
    let hosts: Vec<String> = params
        .dns_seeds
        .iter()
        .map(|seed| (*seed).to_owned())
        .chain(extra.iter().cloned())
        .collect();
    let (sender, answers) = mpsc::channel();
    for host in hosts.clone() {
        let sender = sender.clone();
        let port = params.port;
        thread::spawn(move || {
            let outcome = (host.as_str(), port).to_socket_addrs();
            let outcome = outcome.map(|found| found.collect::<Vec<_>>());
            match sender.send((host, outcome)) {
                Ok(()) => (),
                Err(error) => eprintln!("dns answer dropped: {error}"),
            }
        });
    }
    drop(sender);
    let mut addresses = Vec::new();
    for (host, outcome) in answers.iter().take(hosts.len()) {
        match outcome {
            Ok(found) => {
                let v6 = found.iter().filter(|address| address.is_ipv6()).count();
                println!(
                    "{} seed  {host:<36} {} addresses ({v6} ipv6)",
                    at(),
                    found.len()
                );
                addresses.extend(found);
            }
            Err(error) => println!("{} seed  {host:<36} failed: {error}", at()),
        }
    }
    lock(&shared.stats).seeded.extend(addresses.iter().copied());
    addresses
}

fn family_v2(address: &AddrV2) -> &'static str {
    match address {
        AddrV2::Ipv4(_) => "ipv4",
        AddrV2::Ipv6(_) => "ipv6",
        AddrV2::TorV2(_) | AddrV2::TorV3(_) => "onion",
        AddrV2::I2p(_) => "i2p",
        AddrV2::Cjdns(_) => "cjdns",
        AddrV2::Unknown(..) => "other",
    }
}

fn gossip(shared: &Shared, message: &Message) {
    let mut stats = lock(&shared.stats);
    match message {
        Message::Addr(rows) => {
            for (_, address) in rows {
                let (key, family) = match address.socket_addr() {
                    Ok(socket) if socket.is_ipv4() => (socket.to_string(), "ipv4"),
                    Ok(socket) => (socket.to_string(), "ipv6"),
                    Err(_) => (format!("{:?}:{}", address.address, address.port), "onion"),
                };
                stats.gossip.insert(key, family);
            }
        }
        Message::AddrV2(rows) => {
            for row in rows {
                stats
                    .gossip
                    .insert(format!("{:?}:{}", row.addr, row.port), family_v2(&row.addr));
            }
        }
        _ => (),
    }
}

fn dial_failure(error: &Error) -> String {
    match error {
        Error::Io(cause) => match cause.kind() {
            ErrorKind::TimedOut => "connect timeout".into(),
            ErrorKind::WouldBlock => "handshake read timeout".into(),
            ErrorKind::ConnectionRefused => "refused".into(),
            ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => "unreachable".into(),
            ErrorKind::UnexpectedEof => "handshake eof".into(),
            ErrorKind::ConnectionReset => "handshake reset".into(),
            other => format!("io {other:?}"),
        },
        other => {
            let text = other.to_string();
            match () {
                _ if text.contains("lacks block and witness") => "rejected: peer services".into(),
                _ if text.contains("handshake timed out") => "handshake timeout".into(),
                _ => format!("other: {}", text.chars().take(48).collect::<String>()),
            }
        }
    }
}

fn session_failure(error: &Error) -> Option<String> {
    match error {
        Error::Io(cause) => match cause.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => None,
            ErrorKind::UnexpectedEof => Some("eof".into()),
            ErrorKind::ConnectionReset => Some("reset".into()),
            other => Some(format!("io {other:?}")),
        },
        other => Some(format!(
            "protocol: {}",
            other.to_string().chars().take(48).collect::<String>()
        )),
    }
}

fn update(shared: &Shared, address: SocketAddr, change: impl FnOnce(&mut Session)) {
    let mut stats = lock(&shared.stats);
    let session = stats
        .sessions
        .iter_mut()
        .rev()
        .find(|session| session.address == address && session.closed.is_none());
    if let Some(session) = session {
        change(session);
    }
}

fn announce(shared: &Shared, peer: &Peer) {
    let Some(version) = &peer.version else {
        return;
    };
    if !shared.quiet {
        println!(
            "{} peer  {:<26} {} proto {} height {} relay {} [{}]",
            at(),
            peer.address,
            version.user_agent,
            version.version,
            version.start_height,
            version.relay,
            services(version.services)
        );
    }
    if shared.verbose {
        println!("        version {version:?}");
    }
}

fn learned(shared: &Shared, peer: &mut Peer) {
    if peer.learned.is_empty() {
        return;
    }
    let batch = std::mem::take(&mut peer.learned);
    let mut total = 0;
    update(shared, peer.address, |session| {
        session.advertised += batch.len();
        total = session.advertised;
    });
    if !shared.quiet {
        let sample: Vec<String> = batch.iter().take(SAMPLE).map(ToString::to_string).collect();
        println!(
            "{} addr  {:<26} +{} (total {}): {}",
            at(),
            peer.address,
            batch.len(),
            total,
            sample.join(" ")
        );
    }
    let mut discovery = lock(&shared.discovery);
    for address in batch {
        discovery.offer_gossip(address);
    }
}

fn listen(shared: &Shared, mut peer: Peer) {
    announce(shared, &peer);
    while Instant::now() < shared.deadline {
        let outcome = peer.receive().and_then(|message| {
            let name = message.command();
            gossip(shared, &message);
            update(shared, peer.address, |session| {
                session.messages += 1;
                if session.first.len() < FIRST {
                    session.first.push(name);
                }
            });
            peer.absorb(message)
        });
        match outcome {
            Ok(()) => learned(shared, &mut peer),
            Err(error) => {
                let Some(reason) = session_failure(&error) else {
                    continue;
                };
                if !shared.quiet {
                    println!("{} drop  {:<26} {reason}: {error}", at(), peer.address);
                }
                update(shared, peer.address, |session| {
                    session.closed = Some(elapsed());
                    session.reason = Some(reason);
                });
                return;
            }
        }
    }
}

fn worker(shared: Arc<Shared>) {
    while Instant::now() < shared.deadline {
        let next = lock(&shared.discovery).next();
        let Next::Address(address) = next else {
            thread::sleep(Duration::from_millis(500));
            continue;
        };
        lock(&shared.stats).dials += 1;
        match Peer::connect_with(shared.chain, address, shared.height, &shared.hello) {
            Ok(peer) => {
                let agent = match &peer.version {
                    Some(version) => version.user_agent.clone(),
                    None => String::new(),
                };
                lock(&shared.stats).sessions.push(Session {
                    address,
                    agent,
                    height: peer.start_height,
                    opened: elapsed(),
                    closed: None,
                    reason: None,
                    messages: 0,
                    first: Vec::new(),
                    advertised: 0,
                });
                listen(&shared, peer);
            }
            Err(error) => {
                let reason = dial_failure(&error);
                if shared.verbose {
                    println!("{} skip  {address:<26} {reason}: {error}", at());
                }
                *lock(&shared.stats).failures.entry(reason).or_insert(0) += 1;
            }
        }
    }
}

fn families(gossip: &HashMap<String, &'static str>) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for family in gossip.values() {
        *counts.entry(family).or_insert(0) += 1;
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(name, count)| format!("{name} {count}"))
        .collect();
    parts.join(", ")
}

fn snapshot(shared: &Shared) {
    let stats = lock(&shared.stats);
    let now = elapsed();
    let alive = stats
        .sessions
        .iter()
        .filter(|session| session.closed.is_none())
        .count();
    let pool = lock(&shared.discovery).len();
    println!(
        "{} mark  seeds unique {} | gossip unique {} ({}) | dials {} | handshakes {} | alive {alive} | pool {pool} | t={now:.0}",
        at(),
        stats.seeded.len(),
        stats.gossip.len(),
        families(&stats.gossip),
        stats.dials,
        stats.sessions.len()
    );
}

fn lifetime(session: &Session, end: f64) -> f64 {
    match session.closed {
        Some(closed) => closed - session.opened,
        None => end - session.opened,
    }
}

fn summary(shared: &Shared, options: &Options) {
    snapshot(shared);
    let stats = lock(&shared.stats);
    let end = elapsed();
    let mut buckets: BTreeMap<&str, usize> = BTreeMap::new();
    let mut drops: BTreeMap<String, usize> = BTreeMap::new();
    let (mut silent, mut talked) = (0, 0);
    for session in &stats.sessions {
        let life = lifetime(session, end);
        let bucket = match life {
            l if l < 5.0 => "a <5s",
            l if l < 30.0 => "b 5-30s",
            l if l < 60.0 => "c 30-60s",
            l if l < 300.0 => "d 60-300s",
            _ => "e 300s+",
        };
        *buckets.entry(bucket).or_insert(0) += 1;
        let reason = match &session.reason {
            Some(reason) => reason.clone(),
            None => "alive at end".into(),
        };
        *drops.entry(reason).or_insert(0) += 1;
        if session.closed.is_some() {
            match session.messages {
                0 => silent += 1,
                _ => talked += 1,
            }
        }
    }
    let alive60 = stats
        .sessions
        .iter()
        .filter(|session| lifetime(session, end) >= 60.0)
        .count();
    let mut heights: Vec<u64> = stats
        .sessions
        .iter()
        .map(|session| session.height)
        .collect();
    heights.sort_unstable();
    let median = match heights.get(heights.len() / 2) {
        Some(height) => height.to_string(),
        None => "-".into(),
    };
    let mut agents = BTreeMap::new();
    for session in &stats.sessions {
        *agents.entry(session.agent.as_str()).or_insert(0) += 1;
    }
    println!("\n== summary after {:.0}s ==", end);
    println!(
        "config   services {} relay {} agent {} peers {}",
        services(options.hello.services),
        options.hello.relay,
        options.hello.user_agent,
        options.peers
    );
    println!(
        "connect  dials {} | handshakes {} | lived>=60s {alive60} | median height {median}",
        stats.dials,
        stats.sessions.len()
    );
    println!("lifetime {buckets:?}");
    println!("ended    {drops:?} | dropped after sending nothing {silent}, after sending {talked}");
    println!("failures {:?}", stats.failures);
    println!(
        "learned  advertised to us {} (witness-capable) | gossip unique {}",
        stats
            .sessions
            .iter()
            .map(|session| session.advertised)
            .sum::<usize>(),
        stats.gossip.len()
    );
    println!("agents   {agents:?}");
    if options.verbose {
        for session in &stats.sessions {
            println!(
                "session  {:<26} life {:>6.1}s msgs {:>4} first {:?} end {:?}",
                session.address,
                lifetime(session, end),
                session.messages,
                session.first,
                session.reason
            );
        }
    }
}

fn catchup(chain: Chain, blocks: u64, seconds: u64) -> Result<(), Error> {
    let directory = tempfile::tempdir()?;
    let provider = P2pProvider::new(chain, directory.path())?;
    let started = Instant::now();
    provider.warm()?;
    let mut last = 0;
    let synced = loop {
        let progress = provider.progress();
        if progress.synced {
            break progress;
        }
        if started.elapsed() > Duration::from_secs(seconds) {
            println!(
                "{} catchup headers not synced within {seconds}s: {progress:?}",
                at()
            );
            return Ok(());
        }
        if started.elapsed().as_secs() / 10 != last {
            last = started.elapsed().as_secs() / 10;
            println!("{} catchup {progress:?}", at());
        }
        thread::sleep(Duration::from_millis(200));
    };
    let header_time = started.elapsed().as_secs_f64();
    println!(
        "{} catchup headers {} in {header_time:.1}s = {:.0} headers/s, peers {}",
        at(),
        synced.headers_synced,
        synced.headers_synced as f64 / header_time,
        synced.peers_connected
    );
    let (tip, _) = provider.verified_tip()?;
    let fetched = Instant::now();
    let (mut ok, mut failed, mut bytes) = (0u64, 0u64, 0usize);
    for height in tip.saturating_sub(blocks - 1)..=tip {
        match provider.verified_block(height) {
            Ok(block) => {
                ok += 1;
                bytes += block.raw().len();
            }
            Err(error) => {
                failed += 1;
                println!("{} catchup block {height} failed: {error}", at());
            }
        }
    }
    let block_time = fetched.elapsed().as_secs_f64();
    println!(
        "{} catchup blocks {ok} ok {failed} failed, {bytes} bytes in {block_time:.1}s = {:.2} blocks/s, peers {}",
        at(),
        ok as f64 / block_time,
        provider.progress().peers_connected
    );
    Ok(())
}

fn main() -> Result<(), Error> {
    let options = options()?;
    elapsed();
    if let Some(blocks) = options.catchup {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();
        return catchup(options.chain, blocks, options.seconds);
    }
    let height = match options.chain {
        Chain::LitecoinMainnet => LITECOIN_MAINNET_CHECKPOINT.height,
        _ => LITECOIN_TESTNET_CHECKPOINT.height,
    };
    println!(
        "{} peer discovery: {} peers, {}s, services {}, relay {}, agent {}",
        options.chain.label(),
        options.peers,
        options.seconds,
        services(options.hello.services),
        options.hello.relay,
        options.hello.user_agent
    );
    let shared = Arc::new(Shared {
        chain: options.chain,
        height,
        deadline: *START.get_or_init(Instant::now) + Duration::from_secs(options.seconds),
        verbose: options.verbose,
        quiet: options.quiet,
        hello: options.hello.clone(),
        discovery: Mutex::new(Discovery::new()),
        stats: Mutex::new(Stats::default()),
    });
    if options.trace {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_target(false)
            .init();
    }
    let seeded = match options.pinned.is_empty() {
        true => resolve(&shared, &options.seeds),
        false => options.pinned.clone(),
    };
    lock(&shared.discovery).offer_seeded(seeded);
    for _ in 0..options.peers {
        let shared = shared.clone();
        thread::spawn(move || worker(shared));
    }
    for mark in options.marks.iter().filter(|mark| **mark < options.seconds) {
        let until = *START.get_or_init(Instant::now) + Duration::from_secs(*mark);
        thread::sleep(until.saturating_duration_since(Instant::now()));
        snapshot(&shared);
    }
    thread::sleep(shared.deadline.saturating_duration_since(Instant::now()));
    summary(&shared, &options);
    Ok(())
}
