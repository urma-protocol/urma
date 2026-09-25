use crate::{
    config::{self, GatewaySettings},
    gateway_host::{Portal, SiteHost, Suffix},
    gateway_http::{Refusal, State},
    gateway_pages::IndexPoint,
    gateway_route::{Currency, Scan, standing},
    names_cli::{load_index, sync_index},
    node_cli::{chain_name, connect},
    web_cli::{store_publication, web_error},
};
use bitcoin::Txid;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, RwLock,
        mpsc::{Receiver, SyncSender, TrySendError},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use urma_chain::observation::Chain;
use urma_names::{index::NamesIndex, state::Bound};
use urma_runtime::error::{Error, ensure};
use urma_web::store::{Store, StoredPublication, Verified};

pub(crate) struct Snapshot {
    pub(crate) index: NamesIndex,
    pub(crate) tip: u64,
    pub(crate) synced: u64,
    pub(crate) scan: Scan,
}

impl Snapshot {
    pub(crate) fn point(&self) -> IndexPoint {
        IndexPoint {
            height: self.index.registry.height(),
            block_hash: self.index.tip_hash(),
        }
    }
}

#[derive(Clone)]
pub(crate) enum Availability {
    Pending(String),
    Ready(Arc<Snapshot>),
}

pub(crate) struct Network {
    pub(crate) suffix: Suffix,
    pub(crate) chain: Chain,
    pub(crate) name: String,
    pub(crate) genesis: Txid,
    pub(crate) index: PathBuf,
    state: RwLock<Availability>,
}

fn unix_now() -> Result<u64, Error> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| Error::Io(std::io::Error::other(cause)))?
        .as_secs())
}

fn loaded(network: &str, genesis: Txid, path: &Path) -> Result<Snapshot, Error> {
    let index = load_index(network, path)?;
    ensure!(
        index.registry.genesis() == genesis,
        "names index {} belongs to registry {}, not {genesis}",
        path.display(),
        index.registry.genesis()
    );
    let tip = index.registry.height();
    Ok(Snapshot {
        index,
        tip,
        synced: unix_now()?,
        scan: Scan::Never,
    })
}

impl Network {
    fn open(suffix: Suffix, genesis: Txid, directory: &Path) -> Result<Self, Error> {
        let chain = suffix.chain()?;
        let name = chain_name(chain)?;
        let index = config::registry_index(directory, &name, genesis);
        let state = match loaded(&name, genesis, &index) {
            Ok(snapshot) => Availability::Ready(Arc::new(snapshot)),
            Err(cause) => {
                tracing::warn!(target: "urma_gateway", network = %name, index = %index.display(), error = %cause, "no usable names index yet; waiting for the first rescan");
                Availability::Pending(cause.to_string())
            }
        };
        Ok(Self {
            suffix,
            chain,
            name,
            genesis,
            index,
            state: RwLock::new(state),
        })
    }

    pub(crate) fn availability(&self) -> Result<Availability, Refusal> {
        let state = self
            .state
            .read()
            .map_err(|cause| Refusal::internal(format!("names state lock poisoned: {cause}")))?;
        Ok(state.clone())
    }

    fn refresh(&self, blocks: u64) -> Result<Arc<Snapshot>, Error> {
        let node = connect(self.chain)?;
        let report = sync_index(&node, self.genesis, &self.index, blocks)?;
        let mut snapshot = loaded(&self.name, self.genesis, &self.index)?;
        snapshot.tip = report.tip;
        snapshot.scan = Scan::At(Instant::now());
        let snapshot = Arc::new(snapshot);
        let mut state = self
            .state
            .write()
            .map_err(|cause| Error::Invalid(format!("names state lock poisoned: {cause}")))?;
        *state = Availability::Ready(Arc::clone(&snapshot));
        Ok(snapshot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) suffix: Suffix,
    pub(crate) root: Txid,
}

#[derive(Clone)]
enum Flight {
    Queued,
    Landed,
    Failed { at: Instant, reason: String },
}

struct Entry {
    verified: Arc<Verified>,
    size: usize,
}

struct Cache {
    entries: HashMap<Key, Entry>,
    order: VecDeque<Key>,
    bytes: usize,
}

enum Cached {
    Hit(Arc<Verified>),
    Miss,
}

impl Cache {
    fn get(&self, key: &Key) -> Cached {
        let Some(entry) = self.entries.get(key) else {
            return Cached::Miss;
        };
        Cached::Hit(Arc::clone(&entry.verified))
    }

    fn put(&mut self, key: Key, verified: Arc<Verified>, size: usize, budget: usize) {
        self.forget(&key);
        while self.bytes + size > budget {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.forget(&oldest);
        }
        self.bytes += size;
        self.order.push_back(key);
        self.entries.insert(key, Entry { verified, size });
    }

    fn forget(&mut self, key: &Key) {
        let Some(entry) = self.entries.remove(key) else {
            return;
        };
        self.bytes -= entry.size;
        self.order.retain(|queued| queued != key);
    }
}

fn footprint(verified: &Verified) -> Result<usize, Refusal> {
    let mut total = 0usize;
    for file in &verified.package.files {
        total = total
            .checked_add(file.bytes.len())
            .ok_or_else(|| Refusal::internal("publication size overflow".into()))?;
    }
    Ok(total)
}

pub(crate) struct Binding {
    pub(crate) snapshot: Arc<Snapshot>,
    pub(crate) bound: Bound,
    pub(crate) root: Txid,
}

pub(crate) struct Gateway {
    pub(crate) portal: Portal,
    pub(crate) networks: BTreeMap<Suffix, Network>,
    pub(crate) store: Store,
    pub(crate) settings: GatewaySettings,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<Key, Flight>>,
    landed: Condvar,
    jobs: SyncSender<Key>,
}

impl Gateway {
    pub(crate) fn open(
        portal: Portal,
        settings: GatewaySettings,
        jobs: SyncSender<Key>,
    ) -> Result<Self, Error> {
        let store = Store::open(&settings.store).map_err(web_error)?;
        let mut networks = BTreeMap::new();
        for (suffix, genesis) in portal.registries() {
            networks.insert(
                *suffix,
                Network::open(*suffix, *genesis, &settings.names_dir)?,
            );
        }
        Ok(Self {
            portal,
            networks,
            store,
            settings,
            cache: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            }),
            flights: Mutex::new(HashMap::new()),
            landed: Condvar::new(),
            jobs,
        })
    }

    pub(crate) fn network(&self, suffix: Suffix) -> Result<&Network, Refusal> {
        self.networks.get(&suffix).ok_or_else(|| {
            Refusal::new(
                State::NetworkNotServed,
                format!(
                    "the .{} network is not served by this portal",
                    suffix.label()
                ),
            )
        })
    }

    pub(crate) fn snapshot(&self, network: &Network) -> Result<Arc<Snapshot>, Refusal> {
        match network.availability()? {
            Availability::Ready(snapshot) => Ok(snapshot),
            Availability::Pending(reason) => Err(self.settings.freshness.refusal(
                &network.name,
                &format!("no usable names index yet: {reason}"),
            )),
        }
    }

    pub(crate) fn currency(&self, snapshot: &Snapshot) -> Currency {
        self.settings.freshness.judge(
            snapshot.index.registry.height(),
            snapshot.tip,
            snapshot.scan,
            Instant::now(),
        )
    }

    pub(crate) fn current(&self, network: &Network, snapshot: &Snapshot) -> Result<(), Refusal> {
        match self.currency(snapshot) {
            Currency::Current => Ok(()),
            Currency::Behind(reason) => {
                Err(self.settings.freshness.refusal(&network.name, &reason))
            }
        }
    }

    pub(crate) fn binding(
        &self,
        site: &SiteHost,
        network: &Network,
        snapshot: Arc<Snapshot>,
    ) -> Result<Binding, Refusal> {
        let (bound, root) = standing(
            &format!("{}.{}", site.name, site.suffix.label()),
            network.genesis,
            snapshot.index.registry.resolve(&site.name),
            snapshot.tip,
        )?;
        Ok(Binding {
            snapshot,
            bound,
            root,
        })
    }

    pub(crate) fn bound(&self, site: &SiteHost) -> Result<Binding, Refusal> {
        let network = self.network(site.suffix)?;
        let snapshot = self.snapshot(network)?;
        self.current(network, &snapshot)?;
        self.binding(site, network, snapshot)
    }

    pub(crate) fn publication(
        &self,
        network: &Network,
        root: Txid,
    ) -> Result<Arc<Verified>, Refusal> {
        let key = Key {
            suffix: network.suffix,
            root,
        };
        if let Cached::Hit(verified) = self.cached(&key)? {
            return Ok(verified);
        }
        match self.verify(network, root) {
            Ok(verified) => return self.remember(key, verified),
            Err(cause) => {
                tracing::warn!(target: "urma_gateway", %root, error = %cause, "publication not verifiable from the store; fetching it")
            }
        }
        self.await_fetch(key)?;
        let verified = self.verify(network, root).map_err(|cause| {
            Refusal::new(
                State::VerificationFailed,
                format!("publication {root} failed verification in the store: {cause}"),
            )
        })?;
        self.remember(key, verified)
    }

    pub(crate) fn refetch(&self, network: &Network, root: Txid) {
        let key = Key {
            suffix: network.suffix,
            root,
        };
        match self.cache.lock() {
            Ok(mut cache) => cache.forget(&key),
            Err(cause) => {
                tracing::error!(target: "urma_gateway", %root, error = %cause, "publication cache lock poisoned; the failed publication stays cached")
            }
        }
        let mut flights = match self.flights.lock() {
            Ok(flights) => flights,
            Err(cause) => {
                tracing::error!(target: "urma_gateway", %root, error = %cause, "fetch lock poisoned; no refetch queued");
                return;
            }
        };
        match self.launch(&mut flights, key) {
            Ok(()) => {
                tracing::warn!(target: "urma_gateway", %root, "publication failed re-verification; refetching it")
            }
            Err(refusal) => {
                tracing::warn!(target: "urma_gateway", %root, reason = %refusal.detail, "publication failed re-verification; no refetch queued")
            }
        }
    }

    fn verify(&self, network: &Network, root: Txid) -> Result<Verified, Error> {
        self.store
            .publication(&network.name, &root.to_string(), self.settings.max_bytes)
            .map_err(web_error)
    }

    fn cached(&self, key: &Key) -> Result<Cached, Refusal> {
        let cache = self.cache.lock().map_err(|cause| {
            Refusal::internal(format!("publication cache lock poisoned: {cause}"))
        })?;
        Ok(cache.get(key))
    }

    fn remember(&self, key: Key, verified: Verified) -> Result<Arc<Verified>, Refusal> {
        let size = footprint(&verified)?;
        let verified = Arc::new(verified);
        if size <= self.settings.cache_bytes {
            let mut cache = self.cache.lock().map_err(|cause| {
                Refusal::internal(format!("publication cache lock poisoned: {cause}"))
            })?;
            cache.put(key, Arc::clone(&verified), size, self.settings.cache_bytes);
        }
        Ok(verified)
    }

    fn await_fetch(&self, key: Key) -> Result<(), Refusal> {
        let mut flights = self
            .flights
            .lock()
            .map_err(|cause| Refusal::internal(format!("fetch lock poisoned: {cause}")))?;
        self.launch(&mut flights, key)?;
        let started = Instant::now();
        loop {
            let Some(state) = flights.get(&key).cloned() else {
                return Err(Refusal::internal(format!(
                    "fetch record of {} vanished",
                    key.root
                )));
            };
            match state {
                Flight::Landed => return Ok(()),
                Flight::Failed { reason, .. } => return Err(self.failed(key, &reason)),
                Flight::Queued => {}
            }
            let Some(left) = self.settings.fetch_wait.checked_sub(started.elapsed()) else {
                return Err(self.pending(key));
            };
            if left.is_zero() {
                return Err(self.pending(key));
            }
            flights = self
                .landed
                .wait_timeout(flights, left)
                .map_err(|cause| Refusal::internal(format!("fetch lock poisoned: {cause}")))?
                .0;
        }
    }

    fn launch(&self, flights: &mut HashMap<Key, Flight>, key: Key) -> Result<(), Refusal> {
        if flights.contains_key(&key) {
            let Some(state) = flights.get(&key).cloned() else {
                return Err(Refusal::internal("fetch record vanished".into()));
            };
            match state {
                Flight::Queued => return Ok(()),
                Flight::Failed { at, reason } if at.elapsed() < self.settings.fetch_retry => {
                    return Err(self.failed(key, &reason));
                }
                Flight::Failed { .. } | Flight::Landed => {}
            }
        }
        match self.jobs.try_send(key) {
            Ok(()) => {}
            Err(TrySendError::Full(rejected)) => {
                return Err(Refusal::new(
                    State::Fetching,
                    format!(
                        "the fetch queue is full; publication {} will be fetched later",
                        rejected.root
                    ),
                )
                .with("Retry-After", "5".into()));
            }
            Err(TrySendError::Disconnected(rejected)) => {
                return Err(Refusal::internal(format!(
                    "the fetcher stopped; publication {} cannot be fetched",
                    rejected.root
                )));
            }
        }
        flights.insert(key, Flight::Queued);
        Ok(())
    }

    fn pending(&self, key: Key) -> Refusal {
        Refusal::new(
            State::Fetching,
            format!(
                "publication {} is being fetched and verified; retry shortly",
                key.root
            ),
        )
        .with("Retry-After", "5".into())
    }

    fn failed(&self, key: Key, reason: &str) -> Refusal {
        Refusal::new(
            State::FetchFailed,
            format!(
                "publication {} could not be fetched and verified: {reason}",
                key.root
            ),
        )
        .with(
            "Retry-After",
            self.settings.fetch_retry.as_secs().to_string(),
        )
    }

    fn fetch(&self, key: Key) -> Result<StoredPublication, Error> {
        let network = self
            .networks
            .get(&key.suffix)
            .ok_or_else(|| Error::Missing(format!("no network for .{}", key.suffix.label())))?;
        let node = connect(network.chain)?;
        store_publication(&node, key.root, self.store.root(), self.settings.max_bytes)
    }

    fn land(&self, key: Key, flight: Flight) {
        match self.flights.lock() {
            Ok(mut flights) => {
                flights.insert(key, flight);
            }
            Err(cause) => {
                tracing::error!(target: "urma_gateway", error = %cause, "fetch lock poisoned; waiters will time out")
            }
        }
        self.landed.notify_all();
    }

    pub(crate) fn fetch_loop(&self, queue: Receiver<Key>) {
        loop {
            let key = match queue.recv() {
                Ok(key) => key,
                Err(cause) => {
                    tracing::warn!(target: "urma_gateway", error = %cause, "fetch queue closed; the fetcher stops");
                    return;
                }
            };
            let flight = match self.fetch(key) {
                Ok(stored) => {
                    tracing::info!(target: "urma_gateway", root = %stored.root, network = %stored.network, files = stored.files.len(), "publication fetched and verified");
                    Flight::Landed
                }
                Err(cause) => {
                    tracing::warn!(target: "urma_gateway", root = %key.root, error = %cause, "publication fetch failed");
                    Flight::Failed {
                        at: Instant::now(),
                        reason: cause.to_string(),
                    }
                }
            };
            self.land(key, flight);
        }
    }

    pub(crate) fn rescan_loop(&self) {
        loop {
            for network in self.networks.values() {
                match network.refresh(self.settings.scan_blocks) {
                    Ok(snapshot) => {
                        tracing::info!(target: "urma_gateway", network = %network.name, height = snapshot.index.registry.height(), tip = snapshot.tip, "registry index refreshed")
                    }
                    Err(cause) => {
                        tracing::warn!(target: "urma_gateway", network = %network.name, error = %cause, "registry rescan failed; serving the previous index until it is no longer current")
                    }
                }
            }
            std::thread::sleep(self.settings.rescan);
        }
    }
}
