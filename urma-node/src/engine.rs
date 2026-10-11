use crate::{Error, archive::Archive, model::*, source::ChainSource};
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
    archive: Mutex<Archive>,
    source: Option<Arc<dyn ChainSource>>,
    synchronizing: Mutex<()>,
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
            archive: Mutex::new(Archive::open(path, config)?),
            source,
            synchronizing: Mutex::new(()),
        })
    }

    fn archive(&self) -> Result<MutexGuard<'_, Archive>, Error> {
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

    /// Supply a missing commit by its computed TXID. This is auxiliary prevout
    /// evidence, NOT a claim about the commit's chain placement or witness.
    /// Only existing dependencies from locally scanned blocks can be resolved.
    /// At most 128 references are processed per call; repeat for a shared parent.
    pub fn resolve_commit(&self, raw: &[u8]) -> Result<usize, Error> {
        let (chain, retention) = {
            let archive = self.archive()?;
            (archive.config().chain, archive.config().retention)
        };
        let commit = urma_chain::decode::transaction(raw, chain)
            .map_err(|e| Error::Invalid(format!("dependency commit: {e}")))?;
        let pending = self.archive()?.pending_for(commit.compute_txid())?;
        let mut completed = Vec::new();
        for (ticket, position, proof) in pending {
            let header = self
                .archive()?
                .header_at(ticket.point().height)?
                .ok_or(Error::Stale)?;
            if header.block_hash() != ticket.point().hash {
                return Err(Error::Stale);
            }
            let included = proof
                .verify(chain, &header)
                .map_err(|e| Error::Invalid(format!("stored dependency proof: {e}")))?;
            if included.position() != position {
                return Err(Error::Invalid("stored dependency position mismatch".into()));
            }
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
            completed.push((ticket, position, record));
        }
        self.archive()?.finish_dependencies(completed)
    }

    /// Cache an explicitly requested record, including children in pruned mode.
    /// This is not a pin or a statement that the multipart object is complete.
    /// Header selection is independent of the sender; reorg invalidates the
    /// ticket before persistence. No source call or database lock spans proof work.
    pub fn admit_record(&self, package: RecordPackage) -> Result<RecordReceipt, Error> {
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
        let record = crate::scan::Record {
            position: included.position(),
            wtxid: reveal.compute_wtxid(),
            verified,
            commit,
            raw_commit: package.commit,
            proof: package.reveal,
        };
        self.archive()?.admit_record(ticket, record)
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
            let decoded =
                urma_chain::decode::esplora_block_with_transactions(&raw, chain, location.hash)
                    .map_err(|e| Error::Invalid(format!("dependency block: {e}")))?;
            if source.header(location.height)?.block_hash() != location.hash {
                return Err(Error::Stale);
            }
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
