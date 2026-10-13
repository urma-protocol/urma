use bitcoin::p2p::ServiceFlags;
use std::collections::BTreeMap;
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
use urma_runtime::p2p::{Discovery, Next, Peer};

const SAMPLE: usize = 20;
static START: OnceLock<Instant> = OnceLock::new();

fn at() -> String {
    format!(
        "{:>5.1}s",
        START.get_or_init(Instant::now).elapsed().as_secs_f64()
    )
}
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

struct Options {
    chain: Chain,
    peers: usize,
    seconds: u64,
    seeds: Vec<String>,
    verbose: bool,
}

struct Reached {
    address: SocketAddr,
    agent: String,
    height: u64,
    advertised: usize,
}

#[derive(Default)]
struct Tally {
    reached: Vec<Reached>,
    refused: usize,
}

struct Shared {
    chain: Chain,
    height: u64,
    deadline: Instant,
    verbose: bool,
    discovery: Mutex<Discovery>,
    tally: Mutex<Tally>,
}

fn usage() -> Error {
    Error::Invalid(
        "usage: litecoin-peers [--testnet|--mainnet] [--peers N] [--seconds S] [--seed HOST]... [--verbose]"
            .into(),
    )
}

fn options() -> Result<Options, Error> {
    let mut options = Options {
        chain: Chain::LitecoinTestnet,
        peers: 8,
        seconds: 60,
        seeds: Vec::new(),
        verbose: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--testnet" => options.chain = Chain::LitecoinTestnet,
            "--mainnet" => options.chain = Chain::LitecoinMainnet,
            "--peers" => options.peers = args.next().ok_or_else(usage)?.parse()?,
            "--seconds" => options.seconds = args.next().ok_or_else(usage)?.parse()?,
            "--seed" => options.seeds.push(args.next().ok_or_else(usage)?),
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
    names.join("|")
}

fn resolve(chain: Chain, extra: &[String]) -> Vec<SocketAddr> {
    let params = chain.params();
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
                println!("{} seed  {host:<36} {} addresses", at(), found.len());
                addresses.extend(found);
            }
            Err(error) => println!("{} seed  {host:<36} failed: {error}", at()),
        }
    }
    addresses
}

fn connected(shared: &Shared, peer: &Peer) {
    let Some(version) = &peer.version else {
        return;
    };
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
    if shared.verbose {
        println!("       version {version:?}");
    }
}

fn advertised(shared: &Shared, peer: &mut Peer, total: &mut usize) {
    if peer.learned.is_empty() {
        return;
    }
    let batch: Vec<SocketAddr> = std::mem::take(&mut peer.learned);
    *total += batch.len();
    let sample: Vec<String> = batch.iter().take(SAMPLE).map(ToString::to_string).collect();
    println!(
        "{} addr  {:<26} +{} (total {}): {}",
        at(),
        peer.address,
        batch.len(),
        total,
        sample.join(" ")
    );
    for row in lock(&shared.tally)
        .reached
        .iter_mut()
        .filter(|row| row.address == peer.address)
    {
        row.advertised = *total;
    }
    let mut discovery = lock(&shared.discovery);
    for address in batch {
        discovery.offer_gossip(address);
    }
}

fn listen(shared: &Shared, mut peer: Peer) {
    connected(shared, &peer);
    let mut total = 0;
    while Instant::now() < shared.deadline {
        match peer.absorb_next() {
            Ok(()) => advertised(shared, &mut peer, &mut total),
            Err(Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                if shared.verbose {
                    println!("{} idle  {:<26} {error}", at(), peer.address);
                }
            }
            Err(error) => {
                println!("{} drop  {:<26} {error}", at(), peer.address);
                break;
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
        match Peer::connect(shared.chain, address, shared.height) {
            Ok(peer) => {
                let agent = match &peer.version {
                    Some(version) => version.user_agent.clone(),
                    None => String::new(),
                };
                lock(&shared.tally).reached.push(Reached {
                    address,
                    agent,
                    height: peer.start_height,
                    advertised: 0,
                });
                listen(&shared, peer);
            }
            Err(error) => {
                lock(&shared.tally).refused += 1;
                if shared.verbose {
                    println!("{} skip  {address:<26} {error}", at());
                }
            }
        }
    }
}

fn summary(tally: &Tally, seconds: u64) {
    let mut heights: Vec<u64> = tally.reached.iter().map(|row| row.height).collect();
    heights.sort_unstable();
    let median = match heights.get(heights.len() / 2) {
        Some(height) => height.to_string(),
        None => "-".into(),
    };
    let mut agents = BTreeMap::new();
    for row in &tally.reached {
        *agents.entry(row.agent.as_str()).or_insert(0) += 1;
    }
    println!("\n== summary after {seconds}s ==");
    println!("peers reached      {}", tally.reached.len());
    println!("peers refused      {}", tally.refused);
    println!("median height      {median}");
    println!(
        "addresses learned  {}",
        tally
            .reached
            .iter()
            .map(|row| row.advertised)
            .sum::<usize>()
    );
    println!("user agents        {}", agents.len());
    for (agent, count) in agents {
        println!("  {count:>3}  {agent}");
    }
}

fn main() -> Result<(), Error> {
    let options = options()?;
    let started = Instant::now();
    let height = match options.chain {
        Chain::LitecoinMainnet => LITECOIN_MAINNET_CHECKPOINT.height,
        _ => LITECOIN_TESTNET_CHECKPOINT.height,
    };
    println!(
        "{} peer discovery: {} peers, {}s",
        options.chain.label(),
        options.peers,
        options.seconds
    );
    let mut discovery = Discovery::new();
    discovery.offer_seeded(resolve(options.chain, &options.seeds));
    let shared = Arc::new(Shared {
        chain: options.chain,
        height,
        deadline: started + Duration::from_secs(options.seconds),
        verbose: options.verbose,
        discovery: Mutex::new(discovery),
        tally: Mutex::new(Tally::default()),
    });
    for _ in 0..options.peers {
        let shared = shared.clone();
        thread::spawn(move || worker(shared));
    }
    thread::sleep(shared.deadline.saturating_duration_since(Instant::now()));
    summary(&lock(&shared.tally), options.seconds);
    Ok(())
}
