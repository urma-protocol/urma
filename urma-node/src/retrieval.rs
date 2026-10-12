//! On-demand content acquisition. Sources supply untrusted packages; the local
//! engine supplies the independently selected chain view. Missing peers do not
//! imply missing chain data: a known locator can fall back to full witness blocks.
use crate::{Error, engine::Engine, model::RecordPackage};
use bitcoin::Txid;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use urma_core::multipart::VerifiedRecord;
use urma_runtime::multipart::{
    Candidate, FetchError, MultipartSource, RecordRequest, RecoveredObject, RecoveryLimits,
};

/// A data source, not a chain verifier or completeness authority. Implementations
/// must bound their own I/O; the caller's deadline is checked between callbacks.
pub trait RecordSource {
    fn fetch(&self, txid: Txid) -> Result<Option<RecordPackage>, Error>;
}

/// Explicit acquisition budgets, independent of protocol geometry limits.
#[derive(Clone, Copy)]
pub struct FetchLimits {
    pub sources: usize,
    pub timeout: Duration,
}
impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            sources: 4,
            timeout: Duration::from_secs(30),
        }
    }
}

fn verify_cached(
    engine: &Engine,
    expected: Txid,
    package: &RecordPackage,
) -> Result<VerifiedRecord, Error> {
    let chain = engine.chain()?;
    let reveal = urma_chain::decode::transaction(&package.reveal.transaction, chain)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let commit = urma_chain::decode::transaction(&package.commit, chain)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    VerifiedRecord::verify(expected, &reveal, &commit).map_err(|e| Error::Invalid(e.to_string()))
}

/// Fetch one structurally valid V0 record. This does not check a signed parent
/// reference hash: multipart reconstruction performs that check AFTER proof.
/// A returned record is relative to the local selected view at retrieval time.
pub fn fetch_record(
    engine: &Engine,
    txid: Txid,
    sources: &[&dyn RecordSource],
    limits: FetchLimits,
) -> Result<Option<VerifiedRecord>, Error> {
    let began = Instant::now();
    let deadline = began
        .checked_add(limits.timeout)
        .ok_or_else(|| Error::Invalid("record deadline overflow".into()))?;
    crate::engine::check_deadline(deadline)?;
    if let Some(record) = engine.record(txid)? {
        let verified = verify_cached(engine, txid, &record.package)?;
        crate::engine::check_deadline(deadline)?;
        return Ok(Some(verified));
    }
    let mut last = None;
    for source in sources.iter().take(limits.sources) {
        if began.elapsed() >= limits.timeout {
            return Err(Error::Busy("record acquisition deadline".into()));
        }
        let package = match source.fetch(txid) {
            Ok(Some(package)) => package,
            Ok(None) => continue,
            Err(error) => {
                last = Some(error);
                continue;
            }
        };
        if began.elapsed() >= limits.timeout {
            return Err(Error::Busy("record acquisition deadline".into()));
        }
        // Bind the requested identifier before admitting any package. Valid data
        // for an unrelated TXID cannot satisfy this request or pollute its cache.
        match verify_cached(engine, txid, &package) {
            Err(error) => {
                last = Some(error);
                continue;
            }
            Ok(verified) => match engine.admit_record_before(package, Some(deadline)) {
                Ok(_) => return Ok(Some(verified)),
                Err(error) => {
                    // A peer's stale block claim must not veto another source.
                    // Admission still checks tickets; recover checks its epoch.
                    last = Some(error);
                }
            },
        }
    }
    if began.elapsed() >= limits.timeout {
        return Err(Error::Busy("record acquisition deadline".into()));
    }
    let fallback = engine.retrieve_located_record_before(txid, deadline);
    crate::engine::check_deadline(deadline)?;
    match fallback {
        Ok(Some(record)) => {
            if began.elapsed() >= limits.timeout {
                return Err(Error::Busy("record acquisition deadline".into()));
            }
            let verified = verify_cached(engine, txid, &record.package)?;
            crate::engine::check_deadline(deadline)?;
            Ok(Some(verified))
        }
        Err(error) => Err(error),
        Ok(None) => match last {
            Some(error) => Err(error),
            None => Ok(None),
        },
    }
}

/// Recover an object without exporting partial output. This reuses the existing
/// root/leaf/data signed-reference and final length/digest checks. Reorg during
/// recovery invalidates the result; cached immutable bytes remain reusable.
/// The scratch directory belongs to the caller. No plaintext decryption occurs.
pub fn recover(
    engine: &Engine,
    root: Txid,
    sources: &[&dyn RecordSource],
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    recover_inner(
        engine,
        root,
        sources,
        limits,
        scratch,
        false,
        &AtomicBool::new(false),
    )
}

/// Recover and protect all exact members in the same completion transaction.
/// On failure, no new completion or pin is published; independently verified
/// partial cache entries may remain. No user decryption key is required.
pub fn recover_and_pin(
    engine: &Engine,
    root: Txid,
    sources: &[&dyn RecordSource],
    limits: RecoveryLimits,
    scratch: &Path,
) -> Result<RecoveredObject, Error> {
    recover_inner(
        engine,
        root,
        sources,
        limits,
        scratch,
        true,
        &AtomicBool::new(false),
    )
}

pub(crate) fn recover_inner(
    engine: &Engine,
    root: Txid,
    sources: &[&dyn RecordSource],
    limits: RecoveryLimits,
    scratch: &Path,
    pin: bool,
    cancelled: &AtomicBool,
) -> Result<RecoveredObject, Error> {
    check_cancelled(cancelled)?;
    let generation = engine.status()?.generation;
    let began = Instant::now();
    let deadline = began
        .checked_add(limits.timeout)
        .ok_or_else(|| Error::Invalid("object deadline overflow".into()))?;
    let fetch_limits = FetchLimits {
        sources: limits.attempts.max(1) as usize,
        timeout: limits.timeout,
    };
    let root = fetch_record(engine, root, sources, fetch_limits)?
        .ok_or_else(|| Error::Invalid("root is not available from the supplied sources".into()))?;
    check_cancelled(cancelled)?;
    let mut remaining = limits;
    remaining.timeout = limits.timeout.saturating_sub(began.elapsed());
    let mut adapter = Adapter {
        engine,
        sources,
        fetch_limits,
        began,
        members: BTreeMap::from([(root.txid(), crate::archive::ObjectMember::from(&root))]),
        cancelled,
    };
    let object = urma_runtime::multipart::reconstruct(&root, &mut adapter, remaining, scratch)
        .map_err(|e| Error::Source(Box::new(e)))?;
    check_cancelled(cancelled)?;
    // Completion atomically rechecks the epoch and retained identities. A
    // concurrent prune may refuse completion, never create false availability.
    engine.complete_object(
        &object,
        generation,
        &adapter.members.into_values().collect::<Vec<_>>(),
        pin,
        deadline,
        cancelled,
    )?;
    Ok(object)
}

struct Adapter<'a> {
    engine: &'a Engine,
    sources: &'a [&'a dyn RecordSource],
    fetch_limits: FetchLimits,
    began: Instant,
    members: BTreeMap<Txid, crate::archive::ObjectMember>,
    cancelled: &'a AtomicBool,
}
impl MultipartSource for Adapter<'_> {
    fn fetch(
        &mut self,
        request: &RecordRequest,
        _rejected: &[String],
    ) -> Result<Candidate, FetchError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(FetchError::Source(urma_runtime::error::Error::Io(
                std::io::Error::other("object retention cancelled"),
            )));
        }
        // Source-level proof failures have already tried the bounded source list.
        // A fully authenticated wrong reference hash remains terminal in reconstruct.
        match fetch_record(
            self.engine,
            request.reference.txid,
            self.sources,
            FetchLimits {
                timeout: self
                    .fetch_limits
                    .timeout
                    .saturating_sub(self.began.elapsed()),
                ..self.fetch_limits
            },
        ) {
            Ok(Some(record)) => {
                self.members
                    .insert(record.txid(), crate::archive::ObjectMember::from(&record));
                Ok(Candidate {
                    origin: "node-selected-view".into(),
                    record,
                })
            }
            Ok(None) => Err(FetchError::Unavailable),
            Err(error) => Err(FetchError::Source(urma_runtime::error::Error::Io(
                std::io::Error::other(error.to_string()),
            ))),
        }
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), Error> {
    if cancelled.load(Ordering::Acquire) {
        Err(Error::Busy("object retention cancelled".into()))
    } else {
        Ok(())
    }
}
