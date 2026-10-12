use crate::{
    config::{self, ArchiveSettings, GatewaySettings},
    gateway_host::{Portal, SiteHost, Suffix},
    gateway_http::{Refusal, Reply, State},
    gateway_pages::IndexPoint,
    gateway_readiness::{NetworkHealth, ResolutionHealth, readiness_reply},
    gateway_route::{Currency, Scan, standing},
    names_archive::{self, View},
    names_cli::{load_index, resolution, sync_index},
    node_cli::{chain_name, connect},
    web_cli::{store_publication, web_error},
};
use bitcoin::Txid;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, RwLock,
        mpsc::{Receiver, SyncSender, TrySendError},
    },
    time::Instant,
};
use urma_chain::observation::Chain;
use urma_names::{
    index::NamesIndex,
    name::Name,
    state::{NameState, Resolution},
};
use urma_runtime::error::{Error, ensure};
use urma_web::store::{Store, StoredPublication, Verified};

enum Projection {
    Local(NamesIndex),
    Archive(View),
}

pub(crate) struct Snapshot {
    projection: Projection,
    pub(crate) tip: u64,
    pub(crate) tip_hash: String,
    pub(crate) scan: Scan,
}

impl Snapshot {
    pub(crate) fn point(&self) -> IndexPoint {
        match &self.projection {
            Projection::Local(index) => IndexPoint {
                height: index.registry.height(),
                block_hash: index.tip_hash(),
            },
            Projection::Archive(view) => IndexPoint {
                height: view.status().projected.height,
                block_hash: view.status().projected.hash.to_string(),
            },
        }
    }

    pub(crate) fn tip_point(&self) -> IndexPoint {
        IndexPoint {
            height: self.tip,
            block_hash: self.tip_hash.clone(),
        }
    }

    pub(crate) fn resolve(&self, name: &Name) -> Resolution {
        match &self.projection {
            Projection::Local(index) => index.registry.resolve(name),
            Projection::Archive(view) => view.resolution(name),
        }
    }

    pub(crate) fn names(&self) -> &BTreeMap<Name, NameState> {
        match &self.projection {
            Projection::Local(index) => index.registry.names(),
            Projection::Archive(view) => view.names(),
        }
    }

    pub(crate) fn resolution(&self, network: &str, name: &Name) -> Result<Value, Error> {
        match &self.projection {
            Projection::Local(index) => resolution(index, name),
            Projection::Archive(view) => Ok(view.resolve(network, name)),
        }
    }

    pub(crate) fn source_kind(&self) -> &'static str {
        match &self.projection {
            Projection::Local(_) => "autonomous-local",
            Projection::Archive(_) => "local-node-operator",
        }
    }

    pub(crate) fn complete_to_tip(&self) -> bool {
        match &self.projection {
            Projection::Local(_) => self.point().height == self.tip,
            Projection::Archive(view) => view.status().complete_to_tip,
        }
    }

    /// Source-specific readiness: operator age is acquisition age only. No
    /// observation timestamp for the operator's actual scan or global tip exists.
    pub(crate) fn source(&self) -> Value {
        let (scan_age, view_age) = match self.scan {
            Scan::Never => (None, None),
            Scan::At(at) => (Some(at.elapsed().as_secs()), None),
            Scan::ArchiveView(at) => (None, Some(at.elapsed().as_secs())),
        };
        let point = self.point();
        let mut value = json!({"kind":self.source_kind(),
            "scan_age_seconds":scan_age,"view_age_seconds":view_age,
            "projected":{"height":point.height,"hash":point.block_hash},
            "selected_tip":{"height":self.tip,"hash":self.tip_hash},
            "complete_to_tip":self.complete_to_tip()});
        if let Projection::Archive(view) = &self.projection {
            value["tip_basis"] = "operator-reported".into();
            value["generation"] = view.status().generation.into();
            value["snapshot"] = json!(view.snapshot());
            value["trust"] =
                "local operator projection; not portable chain or ownership evidence".into();
        } else {
            value["tip_basis"] = "autonomous-chain-source".into();
        }
        value
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

fn loaded(network: &str, genesis: Txid, path: &Path) -> Result<Snapshot, Error> {
    let index = load_index(network, path)?;
    ensure!(
        index.registry.genesis() == genesis,
        "names index {} belongs to registry {}, not {genesis}",
        path.display(),
        index.registry.genesis()
    );
    let tip = index.registry.height();
    let tip_hash = index.tip_hash();
    Ok(Snapshot {
        projection: Projection::Local(index),
        tip,
        tip_hash,
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

    fn refresh(
        &self,
        blocks: u64,
        archive: Option<&ArchiveSettings>,
    ) -> Result<Arc<Snapshot>, Error> {
        if let Some(settings) = archive {
            match names_archive::read(settings, &self.name, self.genesis) {
                Ok(view) => {
                    let tip = view
                        .status()
                        .selected_tip
                        .ok_or_else(|| Error::Invalid("Names view has no selected tip".into()))?;
                    return self.publish(Snapshot {
                        tip: tip.height,
                        tip_hash: tip.hash.to_string(),
                        projection: Projection::Archive(view),
                        scan: Scan::ArchiveView(Instant::now()),
                    });
                }
                Err(_) => tracing::warn!(target: "urma_gateway", network = %self.name,
                    "optional Names archive unavailable; attempting autonomous registry refresh"),
            }
        }
        let node = connect(self.chain)?;
        let report = sync_index(&node, self.genesis, &self.index, blocks)?;
        let mut snapshot = loaded(&self.name, self.genesis, &self.index)?;
        snapshot.tip = report.tip;
        snapshot.tip_hash = node.block_hash(report.tip)?.to_string();
        snapshot.scan = Scan::At(Instant::now());
        self.publish(snapshot)
    }

    fn publish(&self, snapshot: Snapshot) -> Result<Arc<Snapshot>, Error> {
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

    pub(crate) fn readiness(&self) -> Result<Reply, Refusal> {
        let networks = self.networks.values().map(|network| {
            let state = match network.state.try_read() {
                Ok(state) => match &*state {
                    Availability::Pending(reason) => {
                        tracing::debug!(target: "urma_gateway", network = %network.name, reason = %reason, "readiness has no loaded index");
                        ResolutionHealth::Unavailable
                    }
                    Availability::Ready(snapshot) => ResolutionHealth::Loaded {
                        index_height: snapshot.point().height,
                        chain_tip: snapshot.tip,
                        scan: snapshot.scan,
                        currency: self.currency(snapshot),
                        names_source: snapshot.source(),
                    },
                },
                Err(cause) => {
                    tracing::warn!(target: "urma_gateway", network = %network.name, error = %cause, "readiness snapshot unavailable");
                    ResolutionHealth::Unavailable
                }
            };
            NetworkHealth { network: &network.name, suffix: network.suffix.label(),
                registry: network.genesis, state }
        });
        readiness_reply(networks, self.settings.freshness.retry)
    }

    pub(crate) fn currency(&self, snapshot: &Snapshot) -> Currency {
        self.settings.freshness.judge(
            snapshot.point().height,
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

    pub(crate) fn servable(
        &self,
        site: &SiteHost,
        network: &Network,
        snapshot: &Snapshot,
    ) -> Result<Txid, Refusal> {
        self.current(network, snapshot)?;
        standing(
            &format!("{}.{}", site.name, site.suffix.label()),
            network.genesis,
            snapshot.resolve(&site.name),
            snapshot.tip,
        )
    }

    pub(crate) fn bound(&self, site: &SiteHost) -> Result<Txid, Refusal> {
        let network = self.network(site.suffix)?;
        let snapshot = self.snapshot(network)?;
        self.servable(site, network, &snapshot)
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
                match network.refresh(self.settings.scan_blocks, self.settings.archive.as_ref()) {
                    Ok(snapshot) => {
                        tracing::info!(target: "urma_gateway", network = %network.name, height = snapshot.point().height, tip = snapshot.tip, "registry index refreshed")
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
