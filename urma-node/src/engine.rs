use crate::{
    Error,
    archive::{Archive, InventoryRows},
    model::*,
    source::{ChainSource, CommitSource},
};
use std::{
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Same engine for embedded consumers and the standalone service. No signer or
/// user decryption key is present. One synchronization coordinator admits work;
/// the archive lock is never held while waiting for a peer.
pub struct Engine {
    index_instance: String,
    archive: Mutex<Archive>,
    pub(crate) source: Option<Arc<dyn ChainSource>>,
    synchronizing: Mutex<()>,
    retaining: Mutex<Option<bitcoin::Txid>>,
    projecting_names: Mutex<Option<bitcoin::Txid>>,
    resolving_dependencies: Mutex<Option<bitcoin::Txid>>,
}

impl Engine {
    /// Attach a verifier after archive ownership has been acquired. The CLI
    /// uses this order before opening any mutable header-cache files.
    pub fn with_source(mut self, source: Arc<dyn ChainSource>) -> Result<Self, Error> {
        if source.genesis()? != self.status()?.chain_genesis {
            return Err(Error::Invalid("source belongs to another chain".into()));
        }
        self.source = Some(source);
        Ok(self)
    }

    pub fn open(
        path: &Path,
        config: ArchiveConfig,
        source: Option<Arc<dyn ChainSource>>,
    ) -> Result<Self, Error> {
        if let Some(source) = &source {
            let genesis = config
                .chain
                .genesis()
                .map_err(|e| Error::Invalid(e.to_string()))?
                .0;
            if source.genesis()? != genesis {
                return Err(Error::Invalid("source belongs to another chain".into()));
            }
        }
        Ok(Self {
            index_instance: hex::encode(rand::random::<[u8; 16]>()),
            archive: Mutex::new(Archive::open(path, config)?),
            source,
            synchronizing: Mutex::new(()),
            retaining: Mutex::new(None),
            projecting_names: Mutex::new(None),
            resolving_dependencies: Mutex::new(None),
        })
    }

    pub(crate) fn archive(&self) -> Result<MutexGuard<'_, Archive>, Error> {
        self.archive
            .lock()
            .map_err(|_| Error::Invalid("archive coordinator panicked".into()))
    }

    pub fn status(&self) -> Result<ArchiveStatus, Error> {
        self.archive()?.status()
    }

    pub fn record(&self, txid: bitcoin::Txid) -> Result<Option<ArchivedRecord>, Error> {
        self.archive()?.record(txid)
    }

    /// Retained raw bytes by TXID: record commits/reveals and cached parents.
    /// Ignores the selected view, so bytes kept from orphaned blocks can return;
    /// acceptable because requesters bind them to the TXID and re-verify.
    pub(crate) fn raw_transaction(&self, txid: bitcoin::Txid) -> Result<Option<Vec<u8>>, Error> {
        self.archive()?.transaction(txid)
    }

    /// One overlay inventory page from scanned selected blocks; read only.
    pub(crate) fn inventory_page(
        &self,
        from: u64,
        to: u64,
        after: Option<(u64, u32)>,
        limit: u32,
    ) -> Result<InventoryRows, Error> {
        self.archive()?.inventory_page(from, to, after, limit)
    }

    /// Read a bounded Wire view without network or a second scan. All fields
    /// and coverage come from one archive critical section. Concurrent writes
    /// invalidate continuation tokens instead of silently mixing snapshots.
    /// Restart invalidates tokens even if the archive has not changed.
    pub fn wire_page(
        &self,
        cursor: Option<&crate::projection::WireCursor>,
        limit: u32,
    ) -> Result<crate::projection::WirePage, Error> {
        self.archive()?
            .wire_page(&self.index_instance, cursor, limit)
    }

    pub fn object_status(&self, root: bitcoin::Txid) -> Result<Option<ObjectStatus>, Error> {
        self.archive()?.object_status(root)
    }

    /// Register an explicitly selected, authenticated Names genesis in a fully
    /// scanned block. No registry is chosen implicitly and no source is called.
    pub fn register_names(
        &self,
        genesis: bitcoin::Txid,
        block: ChainPoint,
    ) -> Result<crate::names::NamesStatus, Error> {
        self.archive()?.register_names(genesis, block)
    }

    /// Reconcile retained undo, then project at most one fully scanned block.
    /// Missing scan coverage leaves progress unchanged. Missing selected commit
    /// placement refuses the step. SQL and state changes share the archive lock.
    pub fn names_step(&self, genesis: bitcoin::Txid) -> Result<crate::names::NamesStep, Error> {
        self.archive()?.names_step(genesis)
    }

    /// Read normalized Names state without registration, projection or source
    /// access. Metadata and rows share one archive lock. Any committed event or
    /// Engine restart invalidates continuation; discard partial traversals.
    pub fn names_view(
        &self,
        genesis: bitcoin::Txid,
        cursor: Option<&crate::names::NamesCursor>,
        limit: u32,
    ) -> Result<crate::names::NamesPage, Error> {
        self.archive()?
            .names_view(&self.index_instance, genesis, cursor, limit)
    }

    /// Orphaned projection checkpoints are refused until a maintenance step
    /// reconciles them; an orphaned genesis always requires explicit action.
    pub fn names_status(
        &self,
        genesis: bitcoin::Txid,
    ) -> Result<Option<crate::names::NamesStatus>, Error> {
        self.archive()?.names_status(genesis)
    }

    pub fn names_resolve(
        &self,
        genesis: bitcoin::Txid,
        name: &urma_names::name::Name,
    ) -> Result<crate::names::NamesResolution, Error> {
        self.archive()?.names_resolve(genesis, name)
    }

    /// Maintain explicitly registered Names projections without source calls.
    /// Inspect at most 128 registrations and attempt at most one projection
    /// step. The cursor advances before each attempt, including failures and
    /// coverage gaps, so one unavailable registry cannot starve later entries.
    /// Some reports an attempted step, which may have made no progress.
    /// Both retention modes preserve individual Names records. Cancellation is
    /// cooperative before a step; an entered SQL/state operation may finish.
    pub fn maintain_next_names(
        &self,
        cancelled: &AtomicBool,
    ) -> Result<Option<crate::names::NamesStep>, Error> {
        let check_cancelled = || {
            if cancelled.load(Ordering::Acquire) {
                Err(Error::Busy("Names maintenance cancelled".into()))
            } else {
                Ok(())
            }
        };
        check_cancelled()?;
        let mut cursor = self
            .projecting_names
            .try_lock()
            .map_err(|_| Error::Busy("Names maintenance already running".into()))?;
        let mut registries = self.archive()?.names_page(*cursor)?;
        if registries.is_empty() && cursor.is_some() {
            *cursor = None;
            registries = self.archive()?.names_page(None)?;
        }
        for genesis in registries {
            check_cancelled()?;
            *cursor = Some(genesis);
            match self.names_status(genesis) {
                Ok(Some(status)) if status.complete_to_tip => continue,
                Ok(None) => continue,
                // The existing step reconciles an orphaned checkpoint or
                // explicitly refuses an orphaned genesis/insufficient undo.
                Ok(Some(_)) | Err(Error::Stale) => (),
                Err(error) => return Err(error),
            }
            let mut archive = self.archive()?;
            // Recheck after waiting for the archive coordinator as well.
            check_cancelled()?;
            return archive.names_step(genesis).map(Some);
        }
        Ok(None)
    }

    /// Pin a previously reconstructed object only if all its evidence remains
    /// local. This does not claim current chain selection or fetch missing data.
    /// Use retrieval::recover_and_pin to acquire and pin an incomplete object.
    pub fn set_pin(&self, root: bitcoin::Txid, pin: bool) -> Result<(), Error> {
        self.archive()?.set_pin(root, pin)
    }

    /// Explicit cache maintenance; no-op for unpruned archives. Returns child
    /// record count removed. Pins protect exact members even after a reorg.
    pub fn prune_cache(&self) -> Result<u64, Error> {
        self.archive()?.prune_cache()
    }

    /// Enforce a soft logical-byte target on unpinned multipart cache only.
    /// Deletes at most 128 child placements and 512 currently unreferenced raw
    /// transactions per call. SQL accounting work and elapsed time are not
    /// bounded by these row limits. No source calls or scan progress occur.
    /// Existing pins and individual/root evidence survive; in-flight unpinned
    /// recovery may lose cache and must refuse incomplete completion.
    pub fn maintain_cache(
        &self,
        limit_bytes: u64,
        cancelled: &AtomicBool,
    ) -> Result<CacheReceipt, Error> {
        if limit_bytes > i64::MAX as u64 {
            return Err(Error::Invalid("cache limit exceeds storage range".into()));
        }
        let check = || {
            if cancelled.load(Ordering::Acquire) {
                Err(Error::Busy("cache maintenance cancelled".into()))
            } else {
                Ok(())
            }
        };
        check()?;
        let mut archive = self.archive()?;
        check()?;
        archive.maintain_cache(limit_bytes)
    }

    /// One fair, bounded unpruned maintenance step. Scan coverage is never
    /// advanced by object recovery. Failures advance the cursor, so the next
    /// round can attempt another root. Pruned mode performs no acquisition.
    /// Cancellation is cooperative between record acquisitions; in-flight
    /// source I/O may still finish and leave independently verified cache bytes.
    pub fn retain_next_object(
        &self,
        sources: &[&dyn crate::retrieval::RecordSource],
        limits: urma_runtime::multipart::RecoveryLimits,
        scratch: &Path,
        cancelled: &AtomicBool,
    ) -> Result<Option<ObjectStatus>, Error> {
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Busy("object retention cancelled".into()));
        }
        let mut cursor = self
            .retaining
            .try_lock()
            .map_err(|_| Error::Busy("object retention already running".into()))?;
        let mut roots = self.archive()?.root_page(*cursor)?;
        if roots.is_empty() && cursor.is_some() {
            *cursor = None;
            roots = self.archive()?.root_page(None)?;
        }
        for root in roots {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error::Busy("object retention cancelled".into()));
            }
            *cursor = Some(root);
            if self
                .object_status(root)?
                .is_some_and(|status| status.selected_complete())
            {
                continue;
            }
            let _object = crate::retrieval::recover_inner(
                self, root, sources, limits, scratch, false, cancelled,
            )?;
            return self.object_status(root);
        }
        Ok(None)
    }

    pub(crate) fn complete_object(
        &self,
        object: &urma_runtime::multipart::RecoveredObject,
        generation: u64,
        members: &[crate::archive::ObjectMember],
        pin: bool,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        self.archive()?.complete_object(
            object.root(),
            generation,
            object.manifest().length,
            object.manifest().payload_hash,
            members,
            pin,
            deadline,
            cancelled,
        )
    }

    pub(crate) fn chain(&self) -> Result<urma_chain::observation::Chain, Error> {
        Ok(self.archive()?.config().chain)
    }

    /// Fetch only a known transaction location from the independent full-block
    /// source. Standard P2P is not assumed to offer an arbitrary TXID lookup.
    /// The block is verified in full, but this targeted path does not scan/index
    /// every candidate and consequently does not advance coverage.
    pub fn retrieve_located_record(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<ArchivedRecord>, Error> {
        self.retrieve_located_record_before(txid, Instant::now() + Duration::from_secs(30))
    }

    pub(crate) fn retrieve_located_record_before(
        &self,
        txid: bitcoin::Txid,
        deadline: Instant,
    ) -> Result<Option<ArchivedRecord>, Error> {
        check_deadline(deadline)?;
        let cached = self.record(txid)?;
        check_deadline(deadline)?;
        if cached.is_some() {
            return Ok(cached);
        }
        let (location, chain) = {
            let archive = self.archive()?;
            (archive.location(txid)?, archive.config().chain)
        };
        let (Some(location), Some(source)) = (location, &self.source) else {
            return Ok(None);
        };
        check_deadline(deadline)?;
        let raw = source.block(location.height);
        check_deadline(deadline)?;
        let raw = raw?;
        let decoded =
            urma_chain::decode::esplora_block_with_transactions(&raw, chain, location.hash)
                .map_err(|e| Error::Invalid(format!("located block: {e}")))?;
        let (block, raw) = decoded.into_parts();
        let Some(position) = block.txdata.iter().position(|t| t.compute_txid() == txid) else {
            return Err(Error::Invalid(
                "verified block contradicts stored locator".into(),
            ));
        };
        let reveal = &block.txdata[position];
        if reveal.input.len() != 1 {
            return Err(Error::Invalid("located transaction is not a reveal".into()));
        }
        let parent = reveal.input[0].previous_output.txid;
        let commit =
            if let Some(index) = block.txdata.iter().position(|t| t.compute_txid() == parent) {
                Some(raw[index].clone())
            } else if let Some(raw) = self.archive()?.transaction(parent)? {
                Some(raw)
            } else {
                let parent_location = self.archive()?.location(parent)?;
                match parent_location {
                    None => None,
                    Some(parent_location) => {
                        check_deadline(deadline)?;
                        let bytes = source.block(parent_location.height);
                        check_deadline(deadline)?;
                        let bytes = bytes?;
                        let parent_block = urma_chain::decode::esplora_block_with_transactions(
                            &bytes,
                            chain,
                            parent_location.hash,
                        )
                        .map_err(|e| Error::Invalid(format!("located parent block: {e}")))?;
                        parent_block
                            .block()
                            .txdata
                            .iter()
                            .position(|t| t.compute_txid() == parent)
                            .map(|i| parent_block.raw_transactions()[i].clone())
                    }
                }
            };
        check_deadline(deadline)?;
        let Some(commit) = commit else {
            return Ok(None);
        };
        let proof = urma_chain::inclusion::BlockProofBuilder::new(&block)
            .and_then(|builder| {
                builder.proof(position as u32, raw[position].clone(), raw[0].clone())
            })
            .map_err(|e| Error::Invalid(e.to_string()))?;
        check_deadline(deadline)?;
        let header = source.header(location.height);
        check_deadline(deadline)?;
        if header?.block_hash() != location.hash {
            return Err(Error::Stale);
        }
        self.admit_record_before(
            RecordPackage {
                version: API_VERSION,
                chain_genesis: chain
                    .genesis()
                    .map_err(|e| Error::Invalid(e.to_string()))?
                    .0,
                block: location,
                reveal: proof,
                commit,
            },
            Some(deadline),
        )?;
        let record = self.record(txid)?;
        check_deadline(deadline)?;
        Ok(record)
    }

    /// Supply a missing commit by its computed TXID. This is auxiliary prevout
    /// evidence, NOT a claim about the commit's chain placement or witness.
    /// Only existing dependencies from locally scanned blocks can be resolved.
    /// At most 128 references are processed per call; repeat for a shared parent.
    pub fn resolve_commit(&self, raw: &[u8]) -> Result<usize, Error> {
        self.resolve_commit_inner(raw, None, &AtomicBool::new(false))
    }

    /// Try one distinct selected dependency whose parent is not cached. The
    /// display-hex cursor is in memory only and advances before a source miss
    /// or error, so one unavailable parent cannot starve later parents. No
    /// source is called when none are missing. If a retained record caches the
    /// parent, resolve_cached_dependency can finish remaining shared references.
    /// Invalid candidates or omitted Pruned children do not cache that parent;
    /// remaining references can require another explicit source call.
    ///
    /// Fetch runs outside the archive mutex. Its own I/O bounds are the source's
    /// responsibility; cancellation is checked between calls/proof work and
    /// before atomic finalization, not a hard interrupt or global deadline.
    /// The selected generation is captured before fetch and cannot be rebound
    /// to a newer view even if the same parent remains needed after a reorg.
    pub fn resolve_next_dependency(
        &self,
        source: &dyn CommitSource,
        cancelled: &AtomicBool,
    ) -> Result<usize, Error> {
        check_dependency_cancelled(cancelled)?;
        let mut cursor = self
            .resolving_dependencies
            .try_lock()
            .map_err(|_| Error::Busy("dependency acquisition already running".into()))?;
        check_dependency_cancelled(cancelled)?;
        let chain = source.chain(); // Contract: local configuration, no I/O.
        let selection = {
            let archive = self.archive()?;
            check_dependency_cancelled(cancelled)?;
            if chain
                .genesis()
                .map_err(|error| Error::Invalid(error.to_string()))?
                != archive
                    .config()
                    .chain
                    .genesis()
                    .map_err(|error| Error::Invalid(error.to_string()))?
            {
                return Err(Error::Invalid(
                    "commit source belongs to another chain".into(),
                ));
            }
            let mut selection = archive.next_missing_dependency(*cursor)?;
            if selection.is_none() && cursor.is_some() {
                selection = archive.next_missing_dependency(None)?;
            }
            selection
        };
        check_dependency_cancelled(cancelled)?;
        let Some((requested, generation)) = selection else {
            *cursor = None;
            return Ok(0);
        };
        *cursor = Some(requested);
        let fetched = source.fetch(requested, cancelled);
        check_dependency_cancelled(cancelled)?;
        {
            let archive = self.archive()?;
            check_dependency_cancelled(cancelled)?;
            archive.check_generation(generation)?;
        }
        let Some(raw) = fetched? else {
            return Ok(0);
        };
        self.resolve_commit_inner(&raw, Some((requested, generation)), cancelled)
    }

    fn resolve_commit_inner(
        &self,
        raw: &[u8],
        expected: Option<(bitcoin::Txid, u64)>,
        cancelled: &AtomicBool,
    ) -> Result<usize, Error> {
        check_dependency_cancelled(cancelled)?;
        let (chain, retention) = {
            let archive = self.archive()?;
            check_dependency_cancelled(cancelled)?;
            if let Some((_, generation)) = expected {
                archive.check_generation(generation)?;
            }
            (archive.config().chain, archive.config().retention)
        };
        // The configured-chain decoder enforces its existing 8,000,000-byte
        // bound and exact syntax before any dependency mutation.
        let commit = urma_chain::decode::transaction(raw, chain)
            .map_err(|e| Error::Invalid(format!("dependency commit: {e}")))?;
        if expected.is_some_and(|(id, _)| id != commit.compute_txid()) {
            return Err(Error::Invalid("commit source returned another TXID".into()));
        }
        check_dependency_cancelled(cancelled)?;
        let pending = {
            let archive = self.archive()?;
            check_dependency_cancelled(cancelled)?;
            if let Some((_, generation)) = expected {
                archive.check_generation(generation)?;
            }
            archive.pending_for(commit.compute_txid())?
        };
        let mut completed = Vec::new();
        for (ticket, position, proof) in pending {
            check_dependency_cancelled(cancelled)?;
            let header = {
                let archive = self.archive()?;
                check_dependency_cancelled(cancelled)?;
                if let Some((_, generation)) = expected {
                    archive.check_generation(generation)?;
                }
                archive
                    .header_at(ticket.point().height)?
                    .ok_or(Error::Stale)?
            };
            if header.block_hash() != ticket.point().hash {
                return Err(Error::Stale);
            }
            let included = proof
                .verify(chain, &header)
                .map_err(|e| Error::Invalid(format!("stored dependency proof: {e}")))?;
            if included.position() != position {
                return Err(Error::Invalid("stored dependency position mismatch".into()));
            }
            check_dependency_cancelled(cancelled)?;
            let reveal = included.transaction();
            // The exact parent TXID fixes the output values/script. Failure
            // here classifies this candidate, rather than trusting a peer's
            // declaration that a dependency or signed object is invalid.
            let verified = urma_core::multipart::VerifiedRecord::verify(
                reveal.compute_txid(),
                reveal,
                &commit,
            );
            let record = match verified {
                Ok(verified) => {
                    let kind = urma_core::format::RecordKind::parse(verified.record_bytes())
                        .map_err(|e| Error::Invalid(e.to_string()))?;
                    if retention == Retention::Pruned
                        && matches!(
                            kind,
                            urma_core::format::RecordKind::DataPart
                                | urma_core::format::RecordKind::LeafManifest
                        )
                    {
                        None
                    } else {
                        Some(crate::scan::Record {
                            position,
                            wtxid: reveal.compute_wtxid(),
                            verified,
                            commit: commit.clone(),
                            raw_commit: raw.to_vec(),
                            proof,
                        })
                    }
                }
                Err(_) => None,
            };
            check_dependency_cancelled(cancelled)?;
            completed.push((ticket, position, record));
        }
        check_dependency_cancelled(cancelled)?;
        let mut archive = self.archive()?;
        check_dependency_cancelled(cancelled)?;
        if let Some((_, generation)) = expected {
            archive.check_generation(generation)?;
        }
        archive.finish_dependencies(completed)
    }

    /// Cache an explicitly requested record, including children in pruned mode.
    /// This is not a pin or a statement that the multipart object is complete.
    /// Header selection is independent of the sender; reorg invalidates the
    /// ticket before persistence. No source call or database lock spans proof work.
    pub fn admit_record(&self, package: RecordPackage) -> Result<RecordReceipt, Error> {
        self.admit_record_before(package, None)
    }

    pub(crate) fn admit_record_before(
        &self,
        package: RecordPackage,
        deadline: Option<Instant>,
    ) -> Result<RecordReceipt, Error> {
        if let Some(deadline) = deadline {
            check_deadline(deadline)?;
        }
        let (ticket, chain, header) = {
            let archive = self.archive()?;
            let chain = archive.config().chain;
            if package.version != API_VERSION
                || package.chain_genesis
                    != chain
                        .genesis()
                        .map_err(|e| Error::Invalid(e.to_string()))?
                        .0
            {
                return Err(Error::Invalid(
                    "record package version or network mismatch".into(),
                ));
            }
            let ticket = archive.ticket(package.block.height)?;
            if ticket.point() != package.block {
                return Err(Error::Stale);
            }
            let header = archive
                .header_at(package.block.height)?
                .ok_or(Error::Stale)?;
            (ticket, chain, header)
        };
        let included = package
            .reveal
            .verify(chain, &header)
            .map_err(|e| Error::Invalid(format!("selective inclusion: {e}")))?;
        let commit = urma_chain::decode::transaction(&package.commit, chain)
            .map_err(|e| Error::Invalid(format!("selective commit: {e}")))?;
        let reveal = included.transaction();
        let verified =
            urma_core::multipart::VerifiedRecord::verify(reveal.compute_txid(), reveal, &commit)
                .map_err(|e| Error::Invalid(format!("selective URMA proof: {e}")))?;
        // VerifiedRecord authenticates bytes before interpreting references.
        // Admission additionally requires a valid V0 record, as in the scanner.
        // Validate the structure AFTER authentication, without repeating signature verification.
        urma_core::envelope::extract_reveal(reveal)
            .map_err(|e| Error::Invalid(format!("selective V0 record: {e}")))?;
        let record = crate::scan::Record {
            position: included.position(),
            wtxid: reveal.compute_wtxid(),
            verified,
            commit,
            raw_commit: package.commit,
            proof: package.reveal,
        };
        let mut archive = self.archive()?;
        if let Some(deadline) = deadline {
            check_deadline(deadline)?;
        }
        archive.admit_record(ticket, record)
    }

    /// Admit at most 2,000 headers from the selected verifier view. This makes
    /// no block-scan or completeness claim. Concurrent callers do not duplicate
    /// the synchronization cycle; they receive Busy.
    pub fn synchronize_headers(&self) -> Result<ArchiveStatus, Error> {
        self.synchronize_headers_until(&AtomicBool::new(false))
    }

    /// Cancellation/deadline is checked between source calls, not a hard I/O
    /// interrupt. Each source call must also have its own bounded timeout.
    pub fn synchronize_headers_until(
        &self,
        cancelled: &AtomicBool,
    ) -> Result<ArchiveStatus, Error> {
        let budget = Budget::new(cancelled);
        budget.check()?;
        let _sync = self
            .synchronizing
            .try_lock()
            .map_err(|_| Error::Busy("synchronization already running".into()))?;
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| Error::Invalid("node is offline; no chain source configured".into()))?;
        let before = self.status()?;
        let remote = source.tip()?;
        budget.check()?;
        let floor = before.application_start.height;
        if remote.height < floor {
            return Err(Error::Invalid(
                "source tip precedes application start".into(),
            ));
        }
        if source.header(floor)?.block_hash() != before.application_start.hash {
            return Err(Error::Invalid(
                "source does not contain configured application start".into(),
            ));
        }
        let mut start = floor;
        if let Some(local) = before.selected_tip {
            let mut height = local.height.min(remote.height);
            loop {
                budget.check()?;
                let chosen = source.header(height)?;
                if self.archive()?.header_at(height)? == Some(chosen) {
                    if height == remote.height && remote.height < local.height {
                        return Err(Error::Invalid("verifier tip regressed on the same prefix; archived view retained, synchronization suspended".into()));
                    }
                    start = height + 1;
                    break;
                }
                if height == floor {
                    break;
                }
                height -= 1;
            }
        }
        if start > remote.height {
            return self.status();
        }
        let end = remote.height.min(start.saturating_add(1999));
        let mut headers = Vec::new();
        for height in start..=end {
            budget.check()?;
            headers.push(source.header(height)?);
        }
        // Linked prefix plus unchanged final header binds the fetched batch to
        // one verifier branch even if the source changed during acquisition.
        budget.check()?;
        if source.header(end)?
            != *headers
                .last()
                .ok_or_else(|| Error::Invalid("empty header batch".into()))?
        {
            return Err(Error::Stale);
        }
        budget.check()?;
        let mut archive = self.archive()?;
        let now = archive.status()?;
        if now.generation != before.generation || now.selected_tip != before.selected_tip {
            return Err(Error::Stale);
        }
        budget.check()?;
        archive.select(start, &headers)?;
        archive.status()
    }

    /// Verify a full block and atomically commit its index evidence. Selective
    /// imports cannot call this path or manufacture a locally scanned interval.
    pub fn scan_next(&self) -> Result<ArchiveStatus, Error> {
        self.scan_next_until(&AtomicBool::new(false))
    }

    /// Retry one available parent per scheduler round. Missing dependencies do
    /// not starve subsequent block scanning or acquire completeness from peers.
    pub fn resolve_cached_dependency(&self) -> Result<usize, Error> {
        let raw = self.archive()?.cached_dependency()?;
        match raw {
            Some(raw) => self.resolve_commit(&raw),
            None => Ok(0),
        }
    }

    pub fn scan_next_until(&self, cancelled: &AtomicBool) -> Result<ArchiveStatus, Error> {
        let budget = Budget::new(cancelled);
        budget.check()?;
        let _sync = self
            .synchronizing
            .try_lock()
            .map_err(|_| Error::Busy("synchronization already running".into()))?;
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| Error::Invalid("node is offline; no chain source configured".into()))?;
        let (ticket, chain, retention) = {
            let archive = self.archive()?;
            let Some(ticket) = archive.next_scan()? else {
                return archive.status();
            };
            (ticket, archive.config().chain, archive.config().retention)
        };
        let raw = source.block(ticket.point().height)?;
        budget.check()?;
        let batch = crate::scan::ScanBatch::verify(chain, ticket, &raw, retention, |txid| {
            budget.check()?;
            if let Some(raw) = self.archive()?.transaction(txid)? {
                return Ok(Some(raw));
            }
            let location = self.archive()?.location(txid)?;
            let Some(location) = location else {
                return Ok(None);
            };
            let raw = source.block(location.height)?;
            budget.check()?;
            let decoded =
                urma_chain::decode::esplora_block_with_transactions(&raw, chain, location.hash)
                    .map_err(|e| Error::Invalid(format!("dependency block: {e}")))?;
            budget.check()?;
            if source.header(location.height)?.block_hash() != location.hash {
                return Err(Error::Stale);
            }
            budget.check()?;
            Ok(decoded
                .block()
                .txdata
                .iter()
                .position(|tx| tx.compute_txid() == txid)
                .map(|i| decoded.raw_transactions()[i].clone()))
        })?;
        budget.check()?;
        if source.header(ticket.point().height)?.block_hash() != ticket.point().hash {
            return Err(Error::Stale);
        }
        budget.check()?;
        let mut archive = self.archive()?;
        budget.check()?;
        archive.commit_scan(batch)?;
        archive.status()
    }
}

fn check_dependency_cancelled(cancelled: &AtomicBool) -> Result<(), Error> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Busy("dependency acquisition cancelled".into()));
    }
    Ok(())
}

struct Budget<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}
impl<'a> Budget<'a> {
    fn new(cancelled: &'a AtomicBool) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(30),
            cancelled,
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::Busy(
                "synchronization cancelled or time budget exhausted".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Busy("record acquisition deadline".into()))
    } else {
        Ok(())
    }
}
