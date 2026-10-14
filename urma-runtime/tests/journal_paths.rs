#![cfg(not(target_arch = "wasm32"))]
use urma_runtime::publish::ensure_journal_distinct;

#[test]
fn native_journal_validation_rejects_hard_links_by_file_identity() {
    let directory = tempfile::tempdir().unwrap();
    let plan = directory.path().join("plan.json");
    std::fs::write(&plan, b"immutable fixture").unwrap();
    let hard_link = directory.path().join("hard-link.json");
    std::fs::hard_link(&plan, &hard_link).unwrap();
    for alias in [&plan, &hard_link] {
        assert!(ensure_journal_distinct(&plan, alias).is_err());
    }
    let journal = directory.path().join("journal.json");
    ensure_journal_distinct(&plan, &journal).unwrap();
    std::fs::write(&journal, b"separate fixture").unwrap();
    ensure_journal_distinct(&plan, &journal).unwrap();
    assert_eq!(std::fs::read(&plan).unwrap(), b"immutable fixture");
}

#[cfg(unix)]
#[test]
fn native_journal_validation_rejects_symbolic_links() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let plan = directory.path().join("plan.json");
    std::fs::write(&plan, b"immutable fixture").unwrap();
    let symbolic_link = directory.path().join("symbolic-link.json");
    symlink(&plan, &symbolic_link).unwrap();
    assert!(ensure_journal_distinct(&plan, &symbolic_link).is_err());
}
