use crate::{
    config,
    error::Error,
    inventory::Inventory,
    review::{self, Finding, ScanReport},
    scan_batch::Batch,
};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
};

struct Jobs<'a> {
    repo: &'a Path,
    scratch: &'a Path,
    inventory: &'a Inventory,
    next: AtomicUsize,
    cancelled: AtomicBool,
    findings: &'a AtomicUsize,
}

fn worker(
    jobs: &Jobs<'_>,
    sender: &SyncSender<Result<(usize, ScanReport), Error>>,
) -> Result<(), Error> {
    let mut batch = Batch::new(jobs.repo, jobs.scratch)?;
    let outcome = scan_jobs(jobs, sender, &mut batch);
    match outcome {
        Ok(()) => batch.finish(),
        Err(cause) => {
            tracing::warn!(%cause, "stopping failed scanner");
            batch.abort()?;
            Err(cause)
        }
    }
}

fn scan_jobs(
    jobs: &Jobs<'_>,
    sender: &SyncSender<Result<(usize, ScanReport), Error>>,
    batch: &mut Batch,
) -> Result<(), Error> {
    let rules = review::rules()?;
    loop {
        if jobs.cancelled.load(Ordering::Acquire) {
            break;
        }
        let index = jobs.next.fetch_add(1, Ordering::Relaxed);
        let Some(object) = jobs.inventory.objects.get(index) else {
            break;
        };
        let report = batch.scan(object, &rules, jobs.findings)?;
        sender
            .send(Ok((index, report)))
            .map_err(|cause| Error::Io(std::io::Error::other(cause)))?;
    }
    Ok(())
}

fn run_worker(jobs: &Jobs<'_>, sender: SyncSender<Result<(usize, ScanReport), Error>>) {
    match worker(jobs, &sender) {
        Ok(()) => (),
        Err(cause) => {
            tracing::warn!(%cause, "scanner worker failed");
            jobs.cancelled.store(true, Ordering::Release);
            match sender.send(Err(cause)) {
                Ok(()) => (),
                Err(cause) => tracing::warn!(%cause, "scanner result receiver closed"),
            }
        }
    }
}

pub(crate) fn scan(
    repo: &Path,
    inventory: &Inventory,
    scratch: &Path,
    report: &mut ScanReport,
    findings: &AtomicUsize,
) -> Result<(), Error> {
    let count = config::scan_workers(inventory.objects.len())?;
    tracing::info!(target: "urma_ui", phase = "Scanning public objects", done = 0u64, total = inventory.objects.len());
    tracing::info!(target: "urma_progress", "Scanning with {} persistent Git workers (CPU and memory budget)", count);
    let jobs = Jobs {
        repo,
        scratch,
        inventory,
        next: AtomicUsize::new(0),
        cancelled: AtomicBool::new(false),
        findings,
    };
    let mut results = Vec::new();
    let mut errors = Vec::new();
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(count);
        let mut handles = Vec::new();
        for _ in 0..count {
            let sender = sender.clone();
            let jobs = &jobs;
            handles.push(scope.spawn(move || run_worker(jobs, sender)));
        }
        drop(sender);
        for result in receiver {
            match result {
                Ok((index, part)) => {
                    report.objects += part.objects;
                    match report.bytes.checked_add(part.bytes) {
                        Some(bytes) => report.bytes = bytes,
                        None => {
                            jobs.cancelled.store(true, Ordering::Release);
                            errors.push(Error::Capacity("scanner byte count overflow".into()));
                            continue;
                        }
                    }
                    if !part.findings.is_empty() {
                        results.push((index, part.findings));
                    }
                    if report.objects.is_multiple_of(128) {
                        tracing::debug!(target: "urma_progress", "Scanned {} / {} objects, {} bytes", report.objects, inventory.objects.len(), report.bytes);
                    }
                    tracing::info!(target: "urma_ui", phase = "Scanning public objects", done = report.objects, total = inventory.objects.len());
                }
                Err(cause) => {
                    tracing::warn!(%cause, "parallel scanner failed");
                    errors.push(cause);
                }
            }
        }
        for handle in handles {
            match handle.join() {
                Ok(()) => (),
                Err(cause) => {
                    tracing::warn!("scanner worker panicked: {:?}", cause.type_id());
                    errors.push(Error::Git("scanner worker panicked".into()));
                }
            }
        }
    });
    errors.into_iter().try_for_each(Err::<(), Error>)?;
    tracing::info!(target: "urma_ui", phase = "Checking complete scan results");
    finish(report, inventory, results)
}

fn finish(
    report: &mut ScanReport,
    inventory: &Inventory,
    mut results: Vec<(usize, Vec<Finding>)>,
) -> Result<(), Error> {
    if report.objects != inventory.objects.len() {
        return Err(Error::Invalid(
            "not every snapshot object was scanned".into(),
        ));
    }
    results.sort_by_key(|entry| entry.0);
    for (_, findings) in results {
        report.findings.extend(findings);
    }
    Ok(())
}
