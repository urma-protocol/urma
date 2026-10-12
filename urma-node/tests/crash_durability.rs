//! Real SIGKILL durability for the embedded scan scheduler on Linux.
//! A self re-exec host scans genuine signed vectors in mock-selected
//! witness-authenticated blocks (no PoW, UTXO or consensus claim) and waits for
//! an acknowledgement before every step. The parent SIGKILLs its owned process
//! group at a step start, or once /proc/<pid>/io shows that step's WAL commit
//! being written. Process death is tested, not power loss: bytes already handed
//! to the kernel survive SIGKILL. Inspection is read-only after Engine release.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
use bitcoin::{
    Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, hashes::Hash, transaction::Version,
};
use common::{
    FIRST_HEIGHT, MemorySource, SignedPair, config, point, readonly_archive, stored_bytes,
    witness_block,
};
use rusqlite::{Connection, types::Value as SqlValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};
use urma_node::{
    engine::Engine,
    model::{ArchiveConfig, ArchiveStatus, Retention},
};

const BLOCKS: u64 = 8;
const FILLER: u32 = 2000;
const WAL_WRITE: u64 = 64 * 1024;
const ATTEMPTS: usize = 12;
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
// libtest may print its own unterminated text before the host's first line,
// so protocol lines are found by this tag anywhere in a line.
const BEGIN: &str = "crash-step begin ";
const DONE: &str = "crash-step done ";

fn tagged<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
    line.split_once(tag).map(|(_, label)| label)
}
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture {
    blocks: Vec<Block>,
    pairs: Vec<SignedPair>,
    // Block offsets from FIRST_HEIGHT that carry each pair's reveal.
    reveals: Vec<Vec<u64>>,
}

// Unique non-candidate spends only enlarge each scan's locator commit, so one
// WAL commit spans many frames and a kill can land inside it.
fn filler(offset: u64) -> Vec<Transaction> {
    (0..FILLER)
        .map(|i| {
            let mut seed = [0xf1; 32];
            seed[..8].copy_from_slice(&offset.to_le_bytes());
            seed[8..12].copy_from_slice(&i.to_le_bytes());
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(seed),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::new(),
                }],
            }
        })
        .collect()
}

fn fixture() -> Fixture {
    let pairs: Vec<SignedPair> = [
        "proof-profile-utf8-two-byte128",
        "proof-post",
        "proof-reply",
        "proof-post-max",
        "proof-avatar-ega16-reference",
        "proof-private",
    ]
    .into_iter()
    .map(SignedPair::load)
    .collect();
    // B's commit precedes its reveal, exercising the scan-time locator lookup.
    // A's reveal stays unresolved until block 5 repeats it beside its commit
    // and resolve_cached_dependency finishes block 2 from the cached parent.
    let layout = [
        pairs[0].transactions().to_vec(),
        vec![pairs[1].commit.clone()],
        vec![pairs[2].reveal.clone()],
        vec![pairs[1].reveal.clone()],
        pairs[3].transactions().to_vec(),
        pairs[2].transactions().to_vec(),
        pairs[4].transactions().to_vec(),
        pairs[5].transactions().to_vec(),
    ];
    let mut blocks: Vec<Block> = Vec::new();
    for (offset, mut transactions) in (0u64..).zip(layout) {
        transactions.extend(filler(offset));
        let nonce = u32::try_from(offset + 1).unwrap();
        let block = witness_block(&transactions, blocks.last(), nonce);
        blocks.push(block);
    }
    let reveals = vec![vec![0], vec![3], vec![2, 5], vec![4], vec![6], vec![7]];
    Fixture {
        blocks,
        pairs,
        reveals,
    }
}

fn source(fixture: &Fixture) -> Arc<MemorySource> {
    Arc::new(MemorySource::new(&fixture.blocks))
}

fn archive_config(fixture: &Fixture) -> ArchiveConfig {
    config(&fixture.blocks[0], Retention::Unpruned)
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<SqlValue>>>,
}

// Every call follows Engine release; the handle is read-only.
fn snapshot(directory: &Path) -> Snapshot {
    let db = readonly_archive(directory);
    let schema: Vec<(String, String, String, Option<String>)> = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables = schema
        .iter()
        .filter(|row| row.0 == "table")
        .map(|row| (row.1.clone(), table_rows(&db, &row.1)))
        .collect();
    Snapshot {
        version: db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap(),
        schema,
        tables,
    }
}

fn table_rows(db: &Connection, name: &str) -> Vec<Vec<SqlValue>> {
    let quoted = format!("\"{}\"", name.replace('"', "\"\""));
    let mut statement = db
        .prepare(&format!("SELECT * FROM {quoted} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|i| row.get::<_, SqlValue>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn count(db: &Connection, sql: &str) -> u64 {
    let value: i64 = db.query_row(sql, [], |row| row.get(0)).unwrap();
    u64::try_from(value).unwrap()
}

// Durable claims are derived only from committed rows: scans form the exact
// prefix of fixture blocks, nothing is placed beyond them, and status agrees.
fn assert_claims(db: &Connection, status: &ArchiveStatus, fixture: &Fixture) {
    let scanned = usize::try_from(status.scanned_blocks).unwrap();
    let covered = &fixture.blocks[..scanned];
    let marks: BTreeMap<String, i64> = db
        .prepare("SELECT block_hash,unresolved FROM scans")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let hashes: BTreeSet<String> = covered
        .iter()
        .map(|block| block.block_hash().to_string())
        .collect();
    assert_eq!(marks.keys().cloned().collect::<BTreeSet<_>>(), hashes);
    let stray = count(
        db,
        "SELECT count(*) FROM (SELECT block_hash FROM locators UNION ALL
         SELECT block_hash FROM records UNION ALL SELECT block_hash FROM dependencies)
         WHERE block_hash NOT IN (SELECT block_hash FROM scans)",
    );
    assert_eq!(stray, 0, "evidence placed beyond durable scan marks");
    let locators: usize = covered.iter().map(|block| block.txdata.len()).sum();
    let stored = count(db, "SELECT count(*) FROM locators");
    assert_eq!(stored, u64::try_from(locators).unwrap());
    let scans = count(db, "SELECT count(*) FROM events WHERE kind='scan'");
    assert_eq!(scans, status.scanned_blocks);
    let pending = count(db, "SELECT count(*) FROM dependencies");
    assert_eq!(pending, status.unresolved_dependencies);
    let indexed = covered
        .iter()
        .zip(0u64..)
        .take_while(|(block, _)| marks[&block.block_hash().to_string()] == 0)
        .last()
        .map(|(block, offset)| point(FIRST_HEIGHT + offset, block));
    assert_eq!(status.indexed_through, indexed);
}

// Records exist only in scanned blocks, with exact bytes; every pair revealed
// inside the indexed prefix remains retrievable.
fn assert_records(engine: &Engine, status: &ArchiveStatus, fixture: &Fixture) {
    let scanned = status.scanned_blocks;
    let indexed = status
        .indexed_through
        .map(|tip| tip.height.checked_sub(FIRST_HEIGHT).unwrap());
    for (pair, heights) in fixture.pairs.iter().zip(&fixture.reveals) {
        let required = indexed.is_some_and(|tip| heights.iter().any(|h| *h <= tip));
        match engine.record(pair.reveal.compute_txid()).unwrap() {
            Some(record) => {
                assert!(heights.iter().any(|h| *h < scanned));
                assert!(record.receipt.block.height < FIRST_HEIGHT + scanned);
                assert_eq!(record.package.commit, pair.raw_commit);
                assert_eq!(record.package.reveal.transaction, pair.raw_reveal);
            }
            None => assert!(!required, "indexed record is not retrievable"),
        }
    }
}

// Offline reopen proves the kernel released the owner lock with the process.
fn checkpoint(directory: &Path, fixture: &Fixture) -> Snapshot {
    let engine = Engine::open(directory, archive_config(fixture), None)
        .expect("offline reopen after process exit");
    let status = engine.status().unwrap();
    assert_records(&engine, &status, fixture);
    drop(engine);
    let db = readonly_archive(directory);
    let integrity: String = db
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert_claims(&db, &status, fixture);
    drop(db);
    snapshot(directory)
}

struct Reference {
    // Committed states a kill at each step label may leave: [before, after].
    steps: Vec<(String, [Snapshot; 2])>,
    last: Snapshot,
    bytes: BTreeMap<String, Vec<u8>>,
}

impl Reference {
    fn allowed(&self, label: &str) -> &[Snapshot; 2] {
        &self.steps.iter().find(|(name, _)| name == label).unwrap().1
    }
}

// The uninterrupted run performs the host's exact operation order in-process,
// with a release/inspect/reopen between steps.
fn reference(fixture: &Fixture) -> Reference {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let chain = source(fixture);
    let step = |operation: &dyn Fn(&Engine) -> usize| {
        let engine = Engine::open(path, archive_config(fixture), Some(chain.clone())).unwrap();
        let changed = operation(&engine);
        drop(engine);
        (changed, checkpoint(path, fixture))
    };
    let (_, opened) = step(&|_| 0);
    let (_, synced) = step(&|engine| {
        engine.synchronize_headers().unwrap();
        0
    });
    let (startup, _) = step(&|engine| engine.resolve_cached_dependency().unwrap());
    assert_eq!(startup, 0);
    let mut steps = vec![("sync".to_owned(), [opened, synced.clone()])];
    let mut before = synced;
    for k in 0..BLOCKS {
        let (_, scanned) = step(&|engine| {
            engine.scan_next().unwrap();
            0
        });
        let (resolved, after) = step(&|engine| engine.resolve_cached_dependency().unwrap());
        assert_eq!(
            resolved,
            usize::from(k == 5),
            "dependency resolves at block 5"
        );
        steps.push((format!("scan {k}"), [before, scanned.clone()]));
        steps.push((format!("resolve {k}"), [scanned, after.clone()]));
        before = after;
    }
    let engine = Engine::open(path, archive_config(fixture), None).unwrap();
    let status = engine.status().unwrap();
    drop(engine);
    assert_eq!(status.unresolved_dependencies, 0);
    let tip = fixture.blocks.last().unwrap();
    assert_eq!(status.indexed_through, Some(point(FIRST_HEIGHT + 7, tip)));
    let bytes = stored_bytes(&readonly_archive(path));
    Reference {
        steps,
        last: before,
        bytes,
    }
}

fn host_step(label: &str, step: impl FnOnce()) {
    let mut out = std::io::stdout();
    writeln!(out, "{BEGIN}{label}").unwrap();
    out.flush().unwrap();
    let mut ack = String::new();
    std::io::stdin().read_line(&mut ack).unwrap();
    assert_eq!(ack, "go\n", "parent acknowledgement");
    step();
    writeln!(out, "{DONE}{label}").unwrap();
    out.flush().unwrap();
}

#[test]
#[ignore = "owned SIGKILL target, spawned only by the crash durability tests"]
fn crash_durability_host() {
    let directory = PathBuf::from(std::env::var_os("CRASH_DURABILITY_DIR").expect("owned dir"));
    let fixture = fixture();
    let engine =
        Engine::open(&directory, archive_config(&fixture), Some(source(&fixture))).unwrap();
    host_step("sync", || {
        engine.synchronize_headers().unwrap();
    });
    // A kill between a scan commit and its resolution resumes here, in the
    // same order as the uninterrupted run.
    engine.resolve_cached_dependency().unwrap();
    for _ in 0..2 * BLOCKS {
        let status = engine.status().unwrap();
        if status.scanned_blocks == BLOCKS && status.unresolved_dependencies == 0 {
            return;
        }
        let k = status.scanned_blocks;
        host_step(&format!("scan {k}"), || {
            engine.scan_next().unwrap();
        });
        host_step(&format!("resolve {k}"), || {
            engine.resolve_cached_dependency().unwrap();
        });
    }
    panic!("host exceeded its step bound");
}

// The process group belongs exclusively to this test.
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

fn reap(child: &mut Child) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => return Ok(exit),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            other => return Err(format!("owned host reap exceeded bound: {other:?}")),
        }
    }
}

fn written(pid: i32) -> u64 {
    let io = std::fs::read_to_string(format!("/proc/{pid}/io")).unwrap();
    io.lines()
        .find_map(|line| line.strip_prefix("wchar: "))
        .unwrap()
        .parse()
        .unwrap()
}

struct Host {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    pid: i32,
    logs: PathBuf,
}

impl Host {
    fn spawn(directory: &Path, logs: &Path) -> Self {
        let (sender, lines) = mpsc::channel();
        let mut host = Self {
            child: None,
            stdin: None,
            lines,
            pid: 0,
            logs: logs.to_owned(),
        };
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "crash_durability_host"])
            .args(["--nocapture", "--test-threads=1"])
            .env_clear()
            .env("TMPDIR", logs)
            .env("CRASH_DURABILITY_DIR", directory)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(logs.join("stderr")).unwrap())
            .spawn()
            .unwrap();
        let child = host.child.insert(child);
        host.pid = i32::try_from(child.id()).unwrap();
        host.stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        host
    }

    // The next step label, or None once the host closed stdout.
    fn begin(&self, deadline: Instant) -> Option<String> {
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("host step exceeded bound: {}", self.stderr()));
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    if let Some(label) = tagged(&line, BEGIN) {
                        return Some(label.to_owned());
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) => panic!("host step bound: {}", self.stderr()),
            }
        }
    }

    fn ack(&mut self) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(b"go\n").unwrap();
        stdin.flush().unwrap();
    }

    fn sigkill(&mut self) -> Result<(), String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        // SAFETY: process_group(0) made this owned child the group leader; no
        // process outside this test was admitted to that group.
        unsafe {
            kill(-self.pid, 9);
        }
        reap(child)?;
        self.child = None;
        Ok(())
    }

    fn complete(&mut self) {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while self.begin(deadline).is_some() {
            self.ack();
        }
        let exit = reap(self.child.as_mut().unwrap()).unwrap();
        self.child = None;
        assert!(exit.success(), "host failed: {exit}; {}", self.stderr());
    }

    fn stderr(&self) -> String {
        let mut text = String::new();
        if let Ok(file) = File::open(self.logs.join("stderr")) {
            file.take(64 * 1024).read_to_string(&mut text).unwrap();
        }
        text
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Err(error) = self.sigkill() {
            eprintln!("{error}");
        }
    }
}

#[derive(Debug)]
enum Kill {
    Start,
    WalWrite(u64),
}

// True when the step's own writes armed the kill before it reported done.
fn wait_for_writes(host: &Host, base: u64, threshold: u64, label: &str) -> bool {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while Instant::now() < deadline {
        if written(host.pid).checked_sub(base).unwrap() >= threshold {
            return true;
        }
        match host.lines.try_recv() {
            Ok(line) if tagged(&line, DONE) == Some(label) => return false,
            Ok(_) | Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => panic!("host exited inside {label}"),
        }
    }
    panic!("step {label} neither wrote nor finished within bound");
}

fn crash_at(directory: &Path, logs: &Path, label: &str, kill: &Kill) -> bool {
    let mut host = Host::spawn(directory, logs);
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        let current = host
            .begin(deadline)
            .unwrap_or_else(|| panic!("host finished before {label}"));
        if current != label {
            host.ack();
            continue;
        }
        // The host is blocked on stdin, so this baseline is quiescent.
        let base = written(host.pid);
        host.ack();
        let armed = match kill {
            Kill::Start => false,
            Kill::WalWrite(threshold) => wait_for_writes(&host, base, *threshold, label),
        };
        host.sigkill().unwrap();
        return armed;
    }
}

// Returns (armed, landed): landed 0 is the pre-step state, 1 the committed step.
fn crash_and_resume(
    fixture: &Fixture,
    reference: &Reference,
    label: &str,
    kill: &Kill,
) -> (bool, usize) {
    let directory = tempfile::tempdir().unwrap();
    let logs = tempfile::tempdir().unwrap();
    let armed = crash_at(directory.path(), logs.path(), label, kill);
    let state = checkpoint(directory.path(), fixture);
    let landed = reference
        .allowed(label)
        .iter()
        .position(|allowed| *allowed == state)
        .unwrap_or_else(|| panic!("SIGKILL at {label} left a state no committed step produced"));
    Host::spawn(directory.path(), logs.path()).complete();
    assert_eq!(
        checkpoint(directory.path(), fixture),
        reference.last,
        "resumed archive differs from the uninterrupted run"
    );
    assert_eq!(
        stored_bytes(&readonly_archive(directory.path())),
        reference.bytes
    );
    eprintln!("{label} {kill:?}: armed={armed} landed={landed}");
    (armed, landed)
}

fn run_point(label: &str, kills: &[Kill]) {
    let fixture = fixture();
    let reference = reference(&fixture);
    for kill in kills {
        crash_and_resume(&fixture, &reference, label, kill);
    }
}

// Repeats until one outcome is observed; every attempt still checks every rule.
fn run_until(label: &str, kill: &Kill, wanted: (bool, usize)) {
    let fixture = fixture();
    let reference = reference(&fixture);
    let mut outcomes = Vec::new();
    for attempt in 1..=ATTEMPTS {
        let outcome = crash_and_resume(&fixture, &reference, label, kill);
        if outcome == wanted {
            // Captured stderr is hidden on success; keep the count readable.
            let report = format!("{label} {kill:?}: {attempt} attempt(s) {outcomes:?}\n");
            let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("crash_durability_attempts");
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            file.write_all(report.as_bytes()).unwrap();
            return;
        }
        outcomes.push(outcome);
    }
    panic!("{label} {kill:?} never produced {wanted:?}: {outcomes:?}");
}

#[test]
fn sigkill_during_header_selection_never_leaves_a_partial_view() {
    run_point("sync", &[Kill::Start, Kill::WalWrite(1)]);
}

#[test]
fn sigkill_during_first_block_scan_keeps_coverage_exact_and_resumes_identically() {
    run_point("scan 0", &[Kill::Start, Kill::WalWrite(WAL_WRITE)]);
}

#[test]
fn sigkill_mid_wal_commit_of_a_middle_block_rolls_back_and_resumes_identically() {
    run_until("scan 3", &Kill::WalWrite(WAL_WRITE), (true, 0));
}

#[test]
fn sigkill_between_dependency_scan_and_resolution_claims_no_indexed_progress() {
    run_until("resolve 5", &Kill::Start, (false, 0));
}

#[test]
fn sigkill_during_last_block_scan_and_resolution_resumes_identically() {
    run_point("scan 7", &[Kill::Start, Kill::WalWrite(WAL_WRITE)]);
    run_point("resolve 7", &[Kill::Start]);
}
