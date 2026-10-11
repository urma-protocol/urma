CREATE TABLE config (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL);
CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation INTEGER NOT NULL);
INSERT INTO state VALUES(1,0);
CREATE TABLE headers (hash TEXT PRIMARY KEY, bytes BLOB NOT NULL CHECK(length(bytes)=80));
CREATE TABLE selected (height INTEGER PRIMARY KEY CHECK(height>=0), hash TEXT NOT NULL UNIQUE REFERENCES headers(hash));
CREATE TABLE scans (
    block_hash TEXT PRIMARY KEY REFERENCES headers(hash),
    rules INTEGER NOT NULL,
    unresolved INTEGER NOT NULL CHECK(unresolved>=0)
);
CREATE TABLE locators (
    block_hash TEXT NOT NULL REFERENCES headers(hash),
    position INTEGER NOT NULL CHECK(position>=0),
    txid TEXT NOT NULL,
    wtxid TEXT NOT NULL,
    PRIMARY KEY(block_hash,position)
);
CREATE INDEX locator_txid ON locators(txid);
CREATE TABLE transactions (wtxid TEXT PRIMARY KEY, txid TEXT NOT NULL, raw BLOB NOT NULL);
CREATE INDEX transaction_txid ON transactions(txid);
CREATE TABLE records (
    block_hash TEXT NOT NULL REFERENCES headers(hash),
    position INTEGER NOT NULL,
    wtxid TEXT NOT NULL REFERENCES transactions(wtxid),
    author TEXT NOT NULL,
    record BLOB NOT NULL,
    commit_wtxid TEXT NOT NULL REFERENCES transactions(wtxid),
    proof BLOB NOT NULL,
    PRIMARY KEY(block_hash,position)
);
CREATE TABLE dependencies (
    block_hash TEXT NOT NULL REFERENCES headers(hash),
    position INTEGER NOT NULL,
    commit_txid TEXT NOT NULL,
    proof BLOB NOT NULL,
    PRIMARY KEY(block_hash,position)
);
CREATE TABLE pins (root_txid TEXT PRIMARY KEY);
CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL,
    kind TEXT NOT NULL,
    height INTEGER,
    block_hash TEXT
);
PRAGMA user_version=1;
