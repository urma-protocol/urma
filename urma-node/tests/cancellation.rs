// The shared fixture module also serves other test suites; keep it unchanged.
#[allow(dead_code)]
mod common;

use bitcoin::{Block, BlockHash, block::Header};
use common::{FIRST_HEIGHT, MemorySource, config, point, profile, readonly_archive, witness_block};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use urma_node::{
    Error,
    engine::Engine,
    model::{ArchiveStatus, ChainPoint, Retention},
    source::ChainSource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Genesis,
    Tip,
    Header(u64),
    Block(u64),
}

struct CancellingSource {
    inner: MemorySource,
    cancelled: Arc<AtomicBool>,
    cancel_after: Mutex<Option<Call>>,
    calls: Mutex<Vec<Call>>,
}

impl CancellingSource {
    fn new(blocks: &[Block], cancelled: Arc<AtomicBool>) -> Self {
        Self {
            inner: MemorySource::new(blocks),
            cancelled,
            cancel_after: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn arm(&self, call: Call) {
        *self.cancel_after.lock().unwrap() = Some(call);
    }

    fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn called(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
        let mut trigger = self.cancel_after.lock().unwrap();
        if *trigger == Some(call) {
            self.cancelled.store(true, Ordering::Release);
            *trigger = None;
        }
    }
}

impl ChainSource for CancellingSource {
    fn genesis(&self) -> Result<BlockHash, Error> {
        let result = self.inner.genesis();
        self.called(Call::Genesis);
        result
    }

    fn tip(&self) -> Result<ChainPoint, Error> {
        let result = self.inner.tip();
        self.called(Call::Tip);
        result
    }

    fn header(&self, height: u64) -> Result<Header, Error> {
        let result = self.inner.header(height);
        // Cancellation is visible when this source callback returns. It does
        // not interrupt an in-flight source call or simulate an elapsed deadline.
        self.called(Call::Header(height));
        result
    }

    fn block(&self, height: u64) -> Result<Vec<u8>, Error> {
        let result = self.inner.block(height);
        self.called(Call::Block(height));
        result
    }
}

fn assert_unchanged(engine: &Engine, before: &ArchiveStatus) {
    assert_eq!(
        serde_json::to_value(engine.status().unwrap()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

fn assert_cancelled(result: Result<ArchiveStatus, Error>) {
    let error = result.unwrap_err();
    assert!(matches!(error, Error::Busy(_)), "{error}");
    assert!(error.to_string().contains("synchronization cancelled"));
}

// Engine is dropped before every call. Inspect only through a read-only handle,
// including rows not exposed in status, to detect accidental admission/events.
fn assert_archive_counts(
    directory: &std::path::Path,
    selected: i64,
    scans: i64,
    stored: i64,
    locators: i64,
) {
    let db = readonly_archive(directory);
    for (table, expected) in [
        ("selected", selected),
        ("headers", selected),
        ("scans", scans),
        ("transactions", stored),
        ("records", stored / 2),
        ("dependencies", 0),
        ("locators", locators),
        ("pins", 0),
        ("events", if selected > 0 { 1 + scans } else { scans }),
    ] {
        let actual: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(actual, expected, "{table}");
    }
}

#[test]
fn cancellation_in_final_batch_header_skips_recheck_and_selection() {
    let directory = tempfile::tempdir().unwrap();
    let first = witness_block(&[], None, 1);
    let last = witness_block(&[], Some(&first), 2);
    let cancelled = Arc::new(AtomicBool::new(false));
    let source = Arc::new(CancellingSource::new(
        &[first.clone(), last],
        cancelled.clone(),
    ));
    let config = config(&first, Retention::Pruned);
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    let before = engine.status().unwrap();
    source.clear_calls(); // Exclude the chain-identity check during Engine::open.
    source.arm(Call::Header(FIRST_HEIGHT + 1));

    assert_cancelled(engine.synchronize_headers_until(&cancelled));
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(
        source.calls(),
        [
            Call::Tip,
            Call::Header(FIRST_HEIGHT), // Application-start validation.
            Call::Header(FIRST_HEIGHT), // First batch header.
            Call::Header(FIRST_HEIGHT + 1), // Final batch header cancels.
        ]
    );
    assert_unchanged(&engine, &before);
    drop(engine);
    assert_archive_counts(directory.path(), 0, 0, 0, 0);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_unchanged(&restarted, &before);
}

#[test]
fn cancellation_in_block_callback_prevents_scan_and_writes() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let block = witness_block(&pair.transactions(), None, 1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let source = Arc::new(CancellingSource::new(
        std::slice::from_ref(&block),
        cancelled.clone(),
    ));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    let before = engine.synchronize_headers().unwrap();
    source.clear_calls();
    source.arm(Call::Block(FIRST_HEIGHT));

    assert_cancelled(engine.scan_next_until(&cancelled));
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(source.calls(), [Call::Block(FIRST_HEIGHT)]);
    assert_unchanged(&engine, &before);
    drop(engine);
    assert_archive_counts(directory.path(), 1, 0, 0, 0);
}

#[test]
fn precancelled_header_sync_and_scan_make_no_source_calls() {
    let directory = tempfile::tempdir().unwrap();
    let pair = profile();
    let block = witness_block(&pair.transactions(), None, 1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let source = Arc::new(CancellingSource::new(
        std::slice::from_ref(&block),
        cancelled.clone(),
    ));
    let engine = Engine::open(
        directory.path(),
        config(&block, Retention::Pruned),
        Some(source.clone()),
    )
    .unwrap();
    // Ensure scan work exists; zero calls must come from pre-cancellation,
    // rather than an empty selected view or an already scanned interval.
    let before = engine.synchronize_headers().unwrap();
    source.clear_calls();
    cancelled.store(true, Ordering::Release);

    assert_cancelled(engine.synchronize_headers_until(&cancelled));
    assert!(source.calls().is_empty());
    assert_cancelled(engine.scan_next_until(&cancelled));
    assert!(source.calls().is_empty());
    assert_unchanged(&engine, &before);
    drop(engine);
    assert_archive_counts(directory.path(), 1, 0, 0, 0);
}

#[test]
fn same_prefix_shorter_tip_is_explicitly_refused_without_state_changes() {
    let directory = tempfile::tempdir().unwrap();
    let first = witness_block(&[], None, 1);
    let pair = profile();
    let last = witness_block(&pair.transactions(), Some(&first), 2);
    let cancelled = Arc::new(AtomicBool::new(false));
    let source = Arc::new(CancellingSource::new(
        &[first.clone(), last.clone()],
        cancelled,
    ));
    let config = config(&first, Retention::Pruned);
    let engine = Engine::open(directory.path(), config.clone(), Some(source.clone())).unwrap();
    engine.synchronize_headers().unwrap();
    engine.scan_next().unwrap();
    let before = engine.scan_next().unwrap();
    assert_eq!(before.selected_tip, Some(point(FIRST_HEIGHT + 1, &last)));
    assert_eq!(before.indexed_through, before.selected_tip);
    assert_eq!(before.scanned_blocks, 2);
    assert_eq!(before.stored_transactions, 2);
    source.inner.replace_branch(&[first]);
    source.clear_calls();

    let error = engine.synchronize_headers().unwrap_err();
    assert!(matches!(error, Error::Invalid(_)), "{error}");
    assert!(
        error
            .to_string()
            .contains("verifier tip regressed on the same prefix")
    );
    assert_eq!(
        source.calls(),
        [
            Call::Tip,
            Call::Header(FIRST_HEIGHT),
            Call::Header(FIRST_HEIGHT)
        ]
    );
    assert_unchanged(&engine, &before); // Includes generation, tip and coverage.
    drop(engine);
    assert_archive_counts(directory.path(), 2, 2, 2, 4);
    let restarted = Engine::open(directory.path(), config, None).unwrap();
    assert_unchanged(&restarted, &before);
}
