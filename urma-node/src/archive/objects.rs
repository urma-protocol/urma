use super::{Archive, generation, sql_integer, unsigned};
use crate::{
    Error,
    model::{ObjectStatus, Retention},
};
use bitcoin::{
    Txid, XOnlyPublicKey,
    hashes::{Hash, sha256},
};
use rusqlite::{OptionalExtension, params};
use urma_core::{format::RecordKind, multipart::VerifiedRecord};

// Member evidence deliberately survives record eviction and branch changes.
// No FK to records: an old successful verification is not current availability.
pub(super) const SCHEMA: &str = "
CREATE TABLE objects (
    root_txid TEXT PRIMARY KEY,
    verified_generation INTEGER NOT NULL CHECK(verified_generation>=0),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0),
    payload_hash BLOB NOT NULL CHECK(length(payload_hash)=32)
);
CREATE TABLE object_members (
    root_txid TEXT NOT NULL REFERENCES objects(root_txid) ON DELETE CASCADE,
    txid TEXT NOT NULL,
    block_hash TEXT NOT NULL REFERENCES headers(hash),
    position INTEGER NOT NULL,
    wtxid TEXT NOT NULL,
    record_hash BLOB NOT NULL CHECK(length(record_hash)=32),
    PRIMARY KEY(root_txid,txid)
);
CREATE INDEX object_member_record ON object_members(block_hash,position,wtxid);
PRAGMA user_version=3;";

/// Upgrade the short-lived schema-2 draft only when its missing identity hashes
/// can be recovered from retained exact records. Never fabricate hashes for
/// already evicted members or silently discard their historical evidence.
pub(super) fn migrate_v2(tx: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    let mut members = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT m.root_txid,m.txid,m.block_hash,m.position,m.wtxid,r.record
            FROM object_members m LEFT JOIN records r ON r.block_hash=m.block_hash
            AND r.position=m.position AND r.wtxid=m.wtxid",
        )?;
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })? {
            let (root, id, block, pos, wtxid, bytes) = row?;
            let bytes = bytes.ok_or_else(|| {
                Error::Invalid(
                    "schema 2 member evidence was evicted; explicit identity migration required"
                        .into(),
                )
            })?;
            members.push((
                root,
                id,
                block,
                pos,
                wtxid,
                sha256::Hash::hash(&bytes).to_byte_array(),
            ));
        }
    }
    tx.execute_batch(
        "CREATE TABLE object_members_v3 (
        root_txid TEXT NOT NULL REFERENCES objects(root_txid) ON DELETE CASCADE,
        txid TEXT NOT NULL, block_hash TEXT NOT NULL REFERENCES headers(hash),
        position INTEGER NOT NULL, wtxid TEXT NOT NULL,
        record_hash BLOB NOT NULL CHECK(length(record_hash)=32), PRIMARY KEY(root_txid,txid));",
    )?;
    for (root, id, block, pos, wtxid, hash) in members {
        tx.execute(
            "INSERT INTO object_members_v3 VALUES(?1,?2,?3,?4,?5,?6)",
            params![root, id, block, pos, wtxid, hash.as_slice()],
        )?;
    }
    tx.execute_batch(
        "DROP TABLE object_members; ALTER TABLE object_members_v3 RENAME TO object_members;
        CREATE INDEX object_member_record ON object_members(block_hash,position,wtxid);
        PRAGMA user_version=3;",
    )?;
    Ok(())
}

/// Only reconstruction collects these, from authenticated records it consumed.
/// Retaining identities instead of payloads bounds bookkeeping by node count.
pub(crate) struct ObjectMember {
    pub txid: Txid,
    hash: [u8; 32],
    author: XOnlyPublicKey,
}

impl From<&VerifiedRecord> for ObjectMember {
    fn from(record: &VerifiedRecord) -> Self {
        Self {
            txid: record.txid(),
            hash: record.reference().record_hash,
            author: record.author(),
        }
    }
}

impl Archive {
    /// A bounded cursor page, including already completed roots. The scheduler
    /// advances across these pages so one missing/oversized object cannot starve
    /// all later roots. This query makes no completeness or retention assertion.
    pub(crate) fn root_page(&self, after: Option<Txid>) -> Result<Vec<Txid>, Error> {
        if self.config.retention != Retention::Unpruned {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT t.txid FROM records r
            JOIN selected s ON s.hash=r.block_hash JOIN transactions t ON t.wtxid=r.wtxid
            WHERE substr(r.record,1,8)=?1 AND (?2 IS NULL OR t.txid>?2)
            ORDER BY t.txid LIMIT 128",
        )?;
        let rows = stmt.query_map(
            params![
                RecordKind::RootManifest.prefix().as_slice(),
                after.map(|id| id.to_string())
            ],
            |r| r.get::<_, String>(0),
        )?;
        rows.map(|row| {
            row?.parse()
                .map_err(|e| Error::Invalid(format!("stored root TXID: {e}")))
        })
        .collect()
    }

    pub(crate) fn object_status(&self, root: Txid) -> Result<Option<ObjectStatus>, Error> {
        let row: Option<(u64, u64)> = self
            .db
            .query_row(
                "SELECT verified_generation,payload_bytes FROM objects WHERE root_txid=?1",
                [root.to_string()],
                |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)),
            )
            .optional()?;
        let Some((verified_generation, payload_bytes)) = row else {
            return Ok(None);
        };
        let (members_total, members_local, members_selected) = self.db.query_row(
            "SELECT count(*),coalesce(sum(r.wtxid IS NOT NULL AND t.wtxid IS NOT NULL AND c.wtxid IS NOT NULL),0),
             coalesce(sum(s.hash IS NOT NULL),0)
             FROM object_members m
             LEFT JOIN records r ON r.block_hash=m.block_hash AND r.position=m.position AND r.wtxid=m.wtxid
             LEFT JOIN transactions t ON t.wtxid=r.wtxid
             LEFT JOIN transactions c ON c.wtxid=r.commit_wtxid
             LEFT JOIN selected s ON s.hash=m.block_hash
             WHERE m.root_txid=?1", [root.to_string()],
            |r| Ok((unsigned(r,0)?, unsigned(r,1)?, unsigned(r,2)?)),
        )?;
        let pinned = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pins WHERE root_txid=?1)",
            [root.to_string()],
            |r| r.get(0),
        )?;
        Ok(Some(ObjectStatus {
            root,
            verified_generation,
            payload_bytes,
            members_total,
            members_local,
            members_selected,
            pinned,
        }))
    }

    /// Called only after successful reconstruction, under the engine archive
    /// mutex. Recheck the epoch and every consumed identity before publishing
    /// completion; concurrent pruning may make completion fail, never lie.
    pub(crate) fn complete_object(
        &mut self,
        root: Txid,
        epoch: u64,
        payload_bytes: u64,
        payload_hash: [u8; 32],
        members: &[ObjectMember],
        pin: bool,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<(), Error> {
        let check_budget = || -> Result<(), Error> {
            crate::engine::check_deadline(deadline)?;
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                return Err(Error::Busy("object completion cancelled".into()));
            }
            Ok(())
        };
        check_budget()?;
        if generation(&self.db)? != epoch {
            return Err(Error::Stale);
        }
        if !members.iter().any(|member| member.txid == root) {
            return Err(Error::Invalid("object members omit root".into()));
        }
        // A TXID commits to no witness. Match authenticated record hash AND
        // author before binding the exact selected WTXID and placement.
        let mut locations = Vec::with_capacity(members.len());
        for member in members {
            check_budget()?;
            let mut stmt = self.db.prepare(
                "SELECT r.block_hash,r.position,r.wtxid,r.record,r.author FROM records r
                 JOIN selected s ON s.hash=r.block_hash JOIN transactions t ON t.wtxid=r.wtxid
                 WHERE t.txid=?1 ORDER BY s.height,r.position",
            )?;
            let rows = stmt.query_map([member.txid.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            let mut found = None;
            for row in rows {
                let (block, position, wtxid, bytes, author) = row?;
                if sha256::Hash::hash(&bytes).to_byte_array() == member.hash
                    && author == member.author.to_string()
                {
                    found = Some((member.txid.to_string(), block, position, wtxid, member.hash));
                    break;
                }
            }
            locations.push(found.ok_or_else(|| {
                Error::Busy("object member no longer retained in selected view".into())
            })?);
        }
        if self.has_pin(root)? {
            let mut stmt = self.db.prepare("SELECT txid,block_hash,position,wtxid,record_hash FROM object_members WHERE root_txid=?1 ORDER BY txid")?;
            let existing = stmt
                .query_map([root.to_string()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u32>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut proposed = locations
                .iter()
                .map(|(id, block, pos, wtxid, hash)| {
                    (
                        id.clone(),
                        block.clone(),
                        *pos,
                        wtxid.clone(),
                        hash.to_vec(),
                    )
                })
                .collect::<Vec<_>>();
            proposed.sort_by(|a, b| a.0.cmp(&b.0));
            if existing != proposed {
                return Err(Error::Invalid(
                    "pinned object membership differs; explicitly unpin before replacing it".into(),
                ));
            }
        }
        check_budget()?;
        let tx = self.db.transaction()?;
        tx.execute("INSERT INTO objects VALUES(?1,?2,?3,?4) ON CONFLICT(root_txid) DO UPDATE SET
            verified_generation=excluded.verified_generation,payload_bytes=excluded.payload_bytes,payload_hash=excluded.payload_hash",
            params![root.to_string(),sql_integer(epoch)?,sql_integer(payload_bytes)?,payload_hash.as_slice()])?;
        tx.execute(
            "DELETE FROM object_members WHERE root_txid=?1",
            [root.to_string()],
        )?;
        for (txid, block, position, wtxid, hash) in locations {
            tx.execute(
                "INSERT INTO object_members VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    root.to_string(),
                    txid,
                    block,
                    position,
                    wtxid,
                    hash.as_slice()
                ],
            )?;
        }
        if pin {
            tx.execute("INSERT OR IGNORE INTO pins VALUES(?1)", [root.to_string()])?;
        }
        tx.execute(
            "INSERT INTO events(generation,kind) VALUES(?1,'object')",
            [sql_integer(epoch)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn set_pin(&mut self, root: Txid, pin: bool) -> Result<(), Error> {
        let status = self.object_status(root)?;
        if pin && !status.as_ref().is_some_and(ObjectStatus::locally_complete) {
            return Err(Error::Invalid(
                "pin requires a verified object complete in local storage".into(),
            ));
        }
        if self.has_pin(root)? == pin {
            return Ok(());
        }
        let tx = self.db.transaction()?;
        if pin {
            tx.execute("INSERT INTO pins VALUES(?1)", [root.to_string()])?;
        } else {
            tx.execute("DELETE FROM pins WHERE root_txid=?1", [root.to_string()])?;
        }
        tx.execute(
            "INSERT INTO events(generation,kind) SELECT generation,'pin' FROM state",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn has_pin(&self, root: Txid) -> Result<bool, Error> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pins WHERE root_txid=?1)",
            [root.to_string()],
            |r| r.get(0),
        )?)
    }

    /// Evict only unpinned multipart child records, including orphan cache.
    /// Roots, application records, scan marks, locators and unresolved dependency
    /// proofs survive. Return deleted record count, not transaction count.
    pub(crate) fn prune_cache(&mut self) -> Result<u64, Error> {
        if self.config.retention != Retention::Pruned {
            return Ok(0);
        }
        let mut candidates = Vec::new();
        {
            let mut stmt = self.db.prepare(
                "SELECT r.block_hash,r.position,r.record FROM records r WHERE NOT EXISTS(
                 SELECT 1 FROM object_members m JOIN pins p ON p.root_txid=m.root_txid
                 WHERE m.block_hash=r.block_hash AND m.position=r.position AND m.wtxid=r.wtxid)",
            )?;
            for row in stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })? {
                let (block, position, bytes) = row?;
                let kind = RecordKind::parse(&bytes)
                    .map_err(|e| Error::Invalid(format!("stored record: {e}")))?;
                if matches!(kind, RecordKind::LeafManifest | RecordKind::DataPart) {
                    candidates.push((block, position));
                }
            }
        }
        let tx = self.db.transaction()?;
        let mut count = 0u64;
        for (block, position) in candidates {
            count += tx.execute(
                "DELETE FROM records WHERE block_hash=?1 AND position=?2",
                params![block, position],
            )? as u64;
        }
        // Parents used by pending dependencies must not disappear during GC.
        let raw_removed = tx.execute("DELETE FROM transactions WHERE NOT EXISTS(SELECT 1 FROM records r WHERE r.wtxid=transactions.wtxid OR r.commit_wtxid=transactions.wtxid)
            AND NOT EXISTS(SELECT 1 FROM dependencies d WHERE d.commit_txid=transactions.txid)", [])?;
        if count != 0 || raw_removed != 0 {
            tx.execute(
                "INSERT INTO events(generation,kind) SELECT generation,'prune' FROM state",
                [],
            )?;
        }
        tx.commit()?;
        Ok(count)
    }
}
