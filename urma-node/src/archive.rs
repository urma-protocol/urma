//! Transactional archive owned by one process. Readers use the owning engine or
//! its API; consumers never open the service database for independent writes.

use crate::{Error, model::*};
use bitcoin::{BlockHash, block::Header, consensus::serialize};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    time::Duration,
};

mod cache;
mod names;
mod objects;
mod peers;
mod projections;
pub(crate) use objects::ObjectMember;

pub struct Archive {
    // Keep the OS lock until after the connection has closed.
    db: Connection,
    _lock: File,
    config: ArchiveConfig,
    // One restored registry at a time. SQL remains authoritative; errors drop
    // the working copy so staged in-memory changes cannot outlive rollback.
    names_cache: Option<urma_names::engine::Registry>,
}

impl Archive {
    /// Opens only local state. The directory is a local-filesystem archive, not
    /// a network share; SQLite WAL relies on local shared-memory coordination.
    pub fn open(directory: &Path, config: ArchiveConfig) -> Result<Self, Error> {
        if config.application_start.height > i64::MAX as u64 {
            return Err(Error::Invalid(
                "application start exceeds storage range".into(),
            ));
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory)?;
        if std::fs::symlink_metadata(directory)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Invalid(
                "archive directory must not be a symlink".into(),
            ));
        }
        let lock_path = directory.join("owner.lock");
        for path in [&lock_path, &directory.join("archive.sqlite3")] {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if !meta.is_file() => {
                    return Err(Error::Invalid("archive files must be regular files".into()));
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.try_lock().map_err(|e| Error::Busy(e.to_string()))?;
        let mut db = Connection::open(directory.join("archive.sqlite3"))?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let encoded = serde_json::to_string(&config)?;
        if version == 0 {
            let tx = db.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.execute("INSERT INTO config VALUES(1,?1)", [&encoded])?;
            tx.commit()?;
        } else if !(1..=5).contains(&version) {
            return Err(Error::Invalid(format!(
                "unsupported archive schema {version}"
            )));
        }
        let saved: String =
            db.query_row("SELECT value FROM config WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if saved != encoded {
            return Err(Error::Invalid(
                "archive configuration differs; explicit migration required".into(),
            ));
        }
        // Configuration identity is checked before any existing archive migration.
        // Schema 1 remains intact if the additive migration fails.
        migrate(&mut db, version)?;
        Ok(Self {
            db,
            _lock: lock,
            config,
            names_cache: None,
        })
    }

    pub fn config(&self) -> &ArchiveConfig {
        &self.config
    }

    pub fn status(&self) -> Result<ArchiveStatus, Error> {
        let generation = generation(&self.db)?;
        let selected_tip = self
            .db
            .query_row(
                "SELECT height,hash FROM selected ORDER BY height DESC LIMIT 1",
                [],
                point,
            )
            .optional()?;
        let indexed_through = self.indexed_through()?;
        let scanned_blocks = self.db.query_row(
            "SELECT count(*) FROM scans c JOIN selected s ON s.hash=c.block_hash WHERE c.rules=?1",
            [SCAN_RULES_VERSION],
            |r| unsigned(r, 0),
        )?;
        let unresolved_dependencies = self.db.query_row(
            "SELECT count(*) FROM dependencies d JOIN selected s ON s.hash=d.block_hash",
            [],
            |r| unsigned(r, 0),
        )?;
        let stored_transactions =
            self.db
                .query_row("SELECT count(*) FROM transactions", [], |r| unsigned(r, 0))?;
        Ok(ArchiveStatus {
            api_version: API_VERSION,
            chain_genesis: self
                .config
                .chain
                .genesis()
                .map_err(|e| Error::Invalid(e.to_string()))?
                .0,
            application_start: self.config.application_start,
            retention: self.config.retention,
            generation,
            selected_tip,
            indexed_through,
            scanned_blocks,
            unresolved_dependencies,
            stored_transactions,
            scan_rules_version: SCAN_RULES_VERSION,
            peer_synced_through: peers::synced_through(
                &self.db,
                self.config.application_start.height,
            )?,
            peer_omissions: peers::omission_count(&self.db)?,
            unaudited_records: peers::unaudited_count(&self.db)?,
        })
    }

    /// Contiguous fully scanned, dependency-complete coverage from application start.
    fn indexed_through(&self) -> Result<Option<ChainPoint>, Error> {
        let start = self.config.application_start.height;
        let mut next = start;
        let mut indexed_through = None;
        let mut rows = self.db.prepare(
            "SELECT s.height,s.hash FROM selected s JOIN scans c ON c.block_hash=s.hash
             WHERE s.height>=?1 AND c.rules=?2 AND c.unresolved=0 ORDER BY s.height",
        )?;
        for row in rows.query_map(params![sql_integer(start)?, SCAN_RULES_VERSION], point)? {
            let current = row?;
            if current.height != next {
                break;
            }
            next += 1;
            indexed_through = Some(current);
        }
        Ok(indexed_through)
    }

    pub fn ticket(&self, height: u64) -> Result<ScanTicket, Error> {
        let point = self
            .db
            .query_row(
                "SELECT height,hash FROM selected WHERE height=?1",
                [sql_integer(height)?],
                point,
            )
            .optional()?
            .ok_or_else(|| Error::Invalid("block is not in the selected view".into()))?;
        Ok(ScanTicket {
            generation: generation(&self.db)?,
            point,
        })
    }

    pub(crate) fn header_at(&self, height: u64) -> Result<Option<Header>, Error> {
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT h.bytes FROM selected s JOIN headers h ON h.hash=s.hash WHERE s.height=?1",
                [sql_integer(height)?],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|raw| {
            bitcoin::consensus::deserialize(&raw)
                .map_err(|e| Error::Invalid(format!("stored header: {e}")))
        })
        .transpose()
    }

    /// Only the chain coordinator calls this, after the header engine selected
    /// the branch. This validates archive continuity, not difficulty/chainwork.
    /// Untrusted peers and API clients cannot supply a branch to this method.
    pub(crate) fn select(&mut self, start: u64, headers: &[Header]) -> Result<(), Error> {
        if headers.is_empty() || start < self.config.application_start.height {
            return Err(Error::Invalid("empty or out-of-domain chain update".into()));
        }
        let end = start
            .checked_add(headers.len() as u64 - 1)
            .filter(|h| *h <= i64::MAX as u64)
            .ok_or_else(|| Error::Invalid("chain update height overflow".into()))?;
        if start == self.config.application_start.height {
            if headers[0].block_hash() != self.config.application_start.hash {
                return Err(Error::Invalid(
                    "selected chain does not contain configured application start".into(),
                ));
            }
        } else {
            let previous = self
                .header_at(start - 1)?
                .ok_or_else(|| Error::Invalid("chain update has a gap".into()))?;
            if headers[0].prev_blockhash != previous.block_hash() {
                return Err(Error::Invalid(
                    "chain update does not join selected parent".into(),
                ));
            }
        }
        for pair in headers.windows(2) {
            if pair[1].prev_blockhash != pair[0].block_hash() {
                return Err(Error::Invalid("noncontiguous selected headers".into()));
            }
        }
        let mut changed_at = None;
        for (offset, header) in headers.iter().enumerate() {
            let height = start + offset as u64;
            if self.header_at(height)?.is_some_and(|old| old != *header) {
                changed_at = Some(height);
                break;
            }
        }
        let tx = self.db.transaction()?;
        if let Some(height) = changed_at {
            tx.execute(
                "DELETE FROM selected WHERE height>=?1",
                [sql_integer(height)?],
            )?;
            tx.execute(
                "UPDATE state SET generation=generation+1 WHERE singleton=1",
                [],
            )?;
            tx.execute("INSERT INTO events(generation,kind,height) SELECT generation,'reorg',?1 FROM state", [sql_integer(height)?])?;
            peers::reorg(&tx, height)?;
        }
        for (offset, header) in headers.iter().enumerate() {
            let hash = header.block_hash().to_string();
            tx.execute(
                "INSERT OR IGNORE INTO headers VALUES(?1,?2)",
                params![hash, serialize(header)],
            )?;
            tx.execute("INSERT INTO selected VALUES(?1,?2) ON CONFLICT(height) DO UPDATE SET hash=excluded.hash",
                params![sql_integer(start + offset as u64)?, hash])?;
        }
        tx.execute("INSERT INTO events(generation,kind,height,block_hash) SELECT generation,'chain',?1,?2 FROM state",
            params![sql_integer(end)?, headers.last().expect("nonempty checked").block_hash().to_string()])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn check_ticket(&self, ticket: ScanTicket) -> Result<(), Error> {
        if generation(&self.db)? != ticket.generation
            || self.ticket(ticket.point.height)?.point != ticket.point
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub(crate) fn next_scan(&self) -> Result<Option<ScanTicket>, Error> {
        let height: Option<u64> = self
            .db
            .query_row(
                "SELECT s.height FROM selected s LEFT JOIN scans c ON c.block_hash=s.hash
             WHERE c.block_hash IS NULL OR c.rules!=?1 ORDER BY s.height LIMIT 1",
                [SCAN_RULES_VERSION],
                |r| unsigned(r, 0),
            )
            .optional()?;
        height.map(|h| self.ticket(h)).transpose()
    }

    pub(crate) fn transaction(&self, txid: bitcoin::Txid) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .db
            .query_row(
                "SELECT raw FROM transactions WHERE txid=?1 LIMIT 1",
                [txid.to_string()],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub(crate) fn location(&self, txid: bitcoin::Txid) -> Result<Option<ChainPoint>, Error> {
        Ok(self.db.query_row(
            "SELECT s.height,s.hash FROM locators l JOIN selected s ON s.hash=l.block_hash WHERE l.txid=?1 ORDER BY s.height LIMIT 1",
            [txid.to_string()], point,
        ).optional()?)
    }

    /// Placements of records this node holds in fully scanned selected blocks
    /// within [from, to], strictly after `after` as (height, position),
    /// ascending; `limit` rows at most. Rows never exceed `scanned_through`,
    /// this node's contiguous indexed prefix: a scanned block still waiting on
    /// a dependency sits above that ceiling and is not listed until it joins
    /// the prefix. Pending reveals appear once their parent resolves. Evicted records drop out; only LeafManifest/DataPart
    /// are ever evicted, and those are exempt from omission detection.
    pub(crate) fn inventory_page(
        &self,
        from: u64,
        to: u64,
        after: Option<(u64, u32)>,
        limit: u32,
    ) -> Result<InventoryRows, Error> {
        let Some(ceiling) = self.indexed_through()? else {
            return Ok(InventoryRows {
                scanned_through: None,
                entries: Vec::new(),
                more: false,
            });
        };
        let (after_height, after_position) = match after {
            Some((height, position)) => (sql_integer(height)?, i64::from(position)),
            None => (-1, -1),
        };
        let mut statement = self.db.prepare(
            "SELECT s.height,s.hash,l.position,l.txid,l.wtxid FROM records p
             JOIN locators l ON l.block_hash=p.block_hash AND l.position=p.position
             JOIN selected s ON s.hash=p.block_hash
             JOIN scans c ON c.block_hash=p.block_hash AND c.rules=?5
             WHERE s.height>=?1 AND s.height<=?2 AND s.height<=?7
               AND (s.height>?3 OR (s.height=?3 AND l.position>?4))
             ORDER BY s.height,l.position LIMIT ?6",
        )?;
        let wanted = usize::try_from(limit).map_err(|e| Error::Invalid(e.to_string()))?;
        let bound = params![
            sql_integer(from)?,
            sql_integer(to)?,
            after_height,
            after_position,
            SCAN_RULES_VERSION,
            i64::from(limit) + 1,
            sql_integer(ceiling.height)?
        ];
        let mut entries = Vec::new();
        for row in statement.query_map(bound, |row| {
            Ok((
                point(row)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })? {
            let (block, position, txid, wtxid) = row?;
            let invalid = |e: String| Error::Invalid(format!("archived locator: {e}"));
            entries.push((
                block,
                u32::try_from(position).map_err(|e| invalid(e.to_string()))?,
                txid.parse()
                    .map_err(|e: bitcoin::hex::HexToArrayError| invalid(e.to_string()))?,
                wtxid
                    .parse()
                    .map_err(|e: bitcoin::hex::HexToArrayError| invalid(e.to_string()))?,
            ));
        }
        let more = entries.len() > wanted;
        entries.truncate(wanted);
        Ok(InventoryRows {
            scanned_through: Some(ceiling.height),
            entries,
            more,
        })
    }

    /// Orphan bytes remain archived but are never returned as selected evidence.
    pub(crate) fn record(&self, txid: bitcoin::Txid) -> Result<Option<ArchivedRecord>, Error> {
        let row: Option<(ChainPoint, u32, String, Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT s.height,s.hash,r.position,r.wtxid,r.proof,t.raw FROM records r
             JOIN selected s ON s.hash=r.block_hash
             JOIN transactions reveal ON reveal.wtxid=r.wtxid
             JOIN transactions t ON t.wtxid=r.commit_wtxid
             WHERE reveal.txid=?1 ORDER BY s.height,r.position LIMIT 1",
                [txid.to_string()],
                |r| Ok((point(r)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?;
        let Some((block, position, wtxid, proof, commit)) = row else {
            return Ok(None);
        };
        Ok(Some(ArchivedRecord {
            receipt: RecordReceipt {
                generation: generation(&self.db)?,
                block,
                position,
                txid,
                wtxid: wtxid
                    .parse()
                    .map_err(|e| Error::Invalid(format!("stored WTXID: {e}")))?,
            },
            package: RecordPackage {
                version: API_VERSION,
                chain_genesis: self
                    .config
                    .chain
                    .genesis()
                    .map_err(|e| Error::Invalid(e.to_string()))?
                    .0,
                block,
                reveal: serde_json::from_slice(&proof)?,
                commit,
            },
        }))
    }

    /// One distinct selected parent absent from every cached witness variant.
    /// Cursor comparison uses persisted display hex, not Txid's byte ordering.
    pub(crate) fn next_missing_dependency(
        &self,
        after: Option<bitcoin::Txid>,
    ) -> Result<Option<(bitcoin::Txid, u64)>, Error> {
        let id: Option<String> = self
            .db
            .query_row(
                "SELECT DISTINCT d.commit_txid FROM dependencies d
             JOIN selected s ON s.hash=d.block_hash
             WHERE NOT EXISTS(SELECT 1 FROM transactions t WHERE t.txid=d.commit_txid)
             AND (?1 IS NULL OR d.commit_txid>?1)
             ORDER BY d.commit_txid LIMIT 1",
                [after.map(|id| id.to_string())],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| {
            let id = id
                .parse()
                .map_err(|error| Error::Invalid(format!("stored parent TXID: {error}")))?;
            Ok((id, generation(&self.db)?))
        })
        .transpose()
    }

    pub(crate) fn check_generation(&self, expected: u64) -> Result<(), Error> {
        if generation(&self.db)? != expected {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub(crate) fn pending_for(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Vec<(ScanTicket, u32, urma_chain::inclusion::TransactionProof)>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT s.height,s.hash,d.position,d.proof FROM dependencies d
             JOIN selected s ON s.hash=d.block_hash WHERE d.commit_txid=?1
             ORDER BY s.height,d.position LIMIT 128",
        )?;
        let rows = stmt.query_map([txid.to_string()], |r| {
            Ok((point(r)?, r.get::<_, u32>(2)?, r.get::<_, Vec<u8>>(3)?))
        })?;
        let epoch = generation(&self.db)?;
        rows.map(|row| {
            let (point, position, proof) = row?;
            Ok((
                ScanTicket {
                    generation: epoch,
                    point,
                },
                position,
                serde_json::from_slice(&proof)?,
            ))
        })
        .collect()
    }

    pub(crate) fn cached_dependency(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .db
            .query_row(
                "SELECT t.raw FROM dependencies d JOIN selected s ON s.hash=d.block_hash
             JOIN transactions t ON t.txid=d.commit_txid ORDER BY s.height,d.position LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Completion changes only evidence from blocks already fully scanned.
    /// A supplied parent cannot create a scan mark or a transaction placement.
    pub(crate) fn finish_dependencies(
        &mut self,
        completed: Vec<(ScanTicket, u32, Option<crate::scan::Record>)>,
    ) -> Result<usize, Error> {
        for (ticket, _, _) in &completed {
            self.check_ticket(*ticket)?;
        }
        let tx = self.db.transaction()?;
        let mut count = 0;
        for (ticket, position, record) in completed {
            let hash = ticket.point.hash.to_string();
            let removed = tx.execute(
                "DELETE FROM dependencies WHERE block_hash=?1 AND position=?2",
                params![hash, position],
            )?;
            if removed == 0 {
                continue;
            }
            if let Some(record) = record {
                store_record(&tx, &hash, &record)?;
            }
            tx.execute("UPDATE scans SET unresolved=(SELECT count(*) FROM dependencies WHERE block_hash=?1) WHERE block_hash=?1", [&hash])?;
            tx.execute("INSERT INTO events(generation,kind,height,block_hash) VALUES(?1,'dependency',?2,?3)",
                params![sql_integer(ticket.generation)?, sql_integer(ticket.point.height)?, hash])?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    pub(crate) fn admit_record(
        &mut self,
        ticket: ScanTicket,
        record: crate::scan::Record,
    ) -> Result<RecordReceipt, Error> {
        self.check_ticket(ticket)?;
        let receipt = RecordReceipt {
            generation: ticket.generation,
            block: ticket.point,
            position: record.position,
            txid: record.verified.txid(),
            wtxid: record.wtxid,
        };
        let tx = self.db.transaction()?;
        store_record(&tx, &ticket.point.hash.to_string(), &record)?;
        tx.execute(
            "INSERT INTO events(generation,kind,height,block_hash) VALUES(?1,'record',?2,?3)",
            params![
                sql_integer(ticket.generation)?,
                sql_integer(ticket.point.height)?,
                ticket.point.hash.to_string()
            ],
        )?;
        // No locators, scan marks, dependency resolution, or completeness claims
        // are inferred from a selective package.
        tx.commit()?;
        Ok(receipt)
    }

    pub(crate) fn commit_scan(&mut self, batch: crate::scan::ScanBatch) -> Result<(), Error> {
        self.check_ticket(batch.ticket)?;
        let point = batch.ticket.point;
        let hash = point.hash.to_string();
        let tx = self.db.transaction()?;
        for (position, (txid, wtxid)) in batch.locators.iter().enumerate() {
            tx.execute("INSERT INTO locators VALUES(?1,?2,?3,?4) ON CONFLICT(block_hash,position) DO UPDATE SET txid=excluded.txid,wtxid=excluded.wtxid",
                params![hash, sql_integer(position as u64)?, txid.to_string(), wtxid.to_string()])?;
        }
        // One transaction includes all records, dependencies, progress and event.
        // An I/O/constraint failure rolls it all back, including progress.
        tx.execute("DELETE FROM dependencies WHERE block_hash=?1", [&hash])?;
        peers::record_omissions(&tx, &batch)?;
        for record in batch.records {
            store_record(&tx, &hash, &record)?;
        }
        let unresolved = batch.dependencies.len() as u64;
        for dependency in batch.dependencies {
            tx.execute(
                "INSERT INTO dependencies VALUES(?1,?2,?3,?4)",
                params![
                    hash,
                    dependency.position,
                    dependency.commit.to_string(),
                    serde_json::to_vec(&dependency.proof)?
                ],
            )?;
        }
        tx.execute("INSERT INTO scans VALUES(?1,?2,?3) ON CONFLICT(block_hash) DO UPDATE SET rules=excluded.rules,unresolved=excluded.unresolved",
            params![hash, SCAN_RULES_VERSION, sql_integer(unresolved)?])?;
        tx.execute("INSERT INTO events(generation,kind,height,block_hash) SELECT generation,'scan',?1,?2 FROM state",
            params![sql_integer(point.height)?, hash])?;
        tx.commit()?;
        Ok(())
    }
}

fn migrate(db: &mut Connection, version: u32) -> Result<(), Error> {
    if version >= 5 {
        return Ok(());
    }
    let tx = db.transaction()?;
    if version < 2 {
        tx.execute_batch(objects::SCHEMA)?;
    } else if version == 2 {
        objects::migrate_v2(&tx)?;
    }
    if version < 4 {
        tx.execute_batch(names::SCHEMA)?;
    }
    tx.execute_batch(peers::SCHEMA)?;
    tx.commit()?;
    Ok(())
}

/// One inventory page as stored: (block, position, txid, wtxid) rows.
pub(crate) struct InventoryRows {
    pub(crate) scanned_through: Option<u64>,
    pub(crate) entries: Vec<(ChainPoint, u32, bitcoin::Txid, bitcoin::Wtxid)>,
    pub(crate) more: bool,
}

fn generation(db: &Connection) -> Result<u64, Error> {
    Ok(
        db.query_row("SELECT generation FROM state WHERE singleton=1", [], |r| {
            unsigned(r, 0)
        })?,
    )
}

fn point(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChainPoint> {
    let hash: String = row.get(1)?;
    Ok(ChainPoint {
        height: unsigned(row, 0)?,
        hash: hash.parse::<BlockHash>().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?,
    })
}

fn sql_integer(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::Invalid("integer exceeds archive range".into()))
}

fn unsigned(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}

fn store_record(db: &Connection, hash: &str, record: &crate::scan::Record) -> Result<(), Error> {
    let wtxid = record.wtxid.to_string();
    let commit_wtxid = record.commit.compute_wtxid().to_string();
    db.execute(
        "INSERT OR IGNORE INTO transactions VALUES(?1,?2,?3)",
        params![
            wtxid,
            record.verified.txid().to_string(),
            record.proof.transaction
        ],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO transactions VALUES(?1,?2,?3)",
        params![
            commit_wtxid,
            record.commit.compute_txid().to_string(),
            record.raw_commit
        ],
    )?;
    db.execute("INSERT INTO records VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(block_hash,position) DO UPDATE SET wtxid=excluded.wtxid,author=excluded.author,record=excluded.record,commit_wtxid=excluded.commit_wtxid,proof=excluded.proof",
        params![hash, record.position, wtxid, record.verified.author().to_string(), record.verified.record_bytes(), commit_wtxid, serde_json::to_vec(&record.proof)?])?;
    Ok(())
}
