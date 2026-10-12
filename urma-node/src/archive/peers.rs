use super::{Archive, generation, point, sql_integer, unsigned};
use crate::{
    Error,
    model::{ChainPoint, Omission},
    scan::{ScanBatch, prunable},
};
use rusqlite::{Connection, OptionalExtension, params};

pub(super) const SCHEMA: &str = "
CREATE TABLE peer_coverage (
 peer TEXT NOT NULL, from_height INTEGER NOT NULL CHECK(from_height>=0),
 to_height INTEGER NOT NULL CHECK(to_height>=from_height), generation INTEGER NOT NULL,
 PRIMARY KEY(peer,from_height)
);
CREATE TABLE peer_omissions (
 peer TEXT NOT NULL, block_hash TEXT NOT NULL REFERENCES headers(hash),
 position INTEGER NOT NULL CHECK(position>=0), txid TEXT NOT NULL, generation INTEGER NOT NULL,
 PRIMARY KEY(peer,block_hash,position)
);
PRAGMA user_version=5;";

impl Archive {
    /// Merges with the peer's adjacent or overlapping ranges. `observed` is the
    /// generation seen before fetching the inventory; any reorg since is Stale.
    pub(crate) fn record_peer_coverage(
        &mut self,
        peer: &str,
        from: u64,
        to: u64,
        observed: u64,
    ) -> Result<(), Error> {
        let tip = self
            .status()?
            .selected_tip
            .ok_or_else(|| Error::Invalid("no selected view to cover".into()))?;
        if peer.is_empty() || from > to || from < self.config.application_start.height {
            return Err(Error::Invalid(
                "peer coverage outside the application".into(),
            ));
        }
        if to > tip.height {
            return Err(Error::Invalid(
                "peer coverage above the selected tip".into(),
            ));
        }
        let tx = self.db.transaction()?;
        let current = generation(&tx)?;
        if current != observed {
            return Err(Error::Stale);
        }
        let epoch = sql_integer(current)?;
        let mut low = from;
        let mut high = to;
        let mut rows = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT from_height,to_height FROM peer_coverage
                 WHERE peer=?1 AND generation=?2 AND from_height<=?3+1 AND to_height+1>=?4",
            )?;
            let bounds = params![peer, epoch, sql_integer(to)?, sql_integer(from)?];
            for row in stmt.query_map(bounds, |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)))? {
                rows.push(row?);
            }
        }
        for (start, end) in rows {
            low = low.min(start);
            high = high.max(end);
            tx.execute(
                "DELETE FROM peer_coverage WHERE peer=?1 AND from_height=?2",
                params![peer, sql_integer(start)?],
            )?;
        }
        tx.execute(
            "INSERT INTO peer_coverage VALUES(?1,?2,?3,?4)
             ON CONFLICT(peer,from_height) DO UPDATE SET to_height=excluded.to_height,generation=excluded.generation",
            params![peer, sql_integer(low)?, sql_integer(high)?, epoch],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn peer_cursor(&self, peer: &str) -> Result<u64, Error> {
        let mut stmt = self.db.prepare(
            "SELECT from_height,to_height FROM peer_coverage
             WHERE peer=?1 AND generation=?2 ORDER BY from_height",
        )?;
        let epoch = sql_integer(generation(&self.db)?)?;
        let rows = stmt.query_map(params![peer, epoch], |r| {
            Ok((unsigned(r, 0)?, unsigned(r, 1)?))
        })?;
        contiguous(self.config.application_start.height, rows)
    }

    pub(crate) fn peer_synced_through(&self) -> Result<Option<ChainPoint>, Error> {
        synced_through(&self.db, self.config.application_start.height)
    }

    pub(crate) fn omitting_peers(&self) -> Result<Vec<String>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT o.peer FROM peer_omissions o JOIN selected s ON s.hash=o.block_hash
             ORDER BY o.peer",
        )?;
        let peers = stmt.query_map([], |r| r.get(0))?;
        Ok(peers.collect::<Result<Vec<String>, _>>()?)
    }

    pub(crate) fn peer_omissions(&self) -> Result<Vec<Omission>, Error> {
        self.omissions(
            "SELECT s.height,s.hash,o.peer,o.position,o.txid,o.generation FROM peer_omissions o
             JOIN selected s ON s.hash=o.block_hash ORDER BY s.height,o.position,o.peer
             LIMIT ?1",
            -1,
        )
    }

    /// The `limit` highest selected omissions, returned in ascending order.
    pub(crate) fn peer_omissions_latest(&self, limit: u32) -> Result<Vec<Omission>, Error> {
        let mut latest = self.omissions(
            "SELECT s.height,s.hash,o.peer,o.position,o.txid,o.generation FROM peer_omissions o
             JOIN selected s ON s.hash=o.block_hash
             ORDER BY s.height DESC,o.position DESC,o.peer DESC LIMIT ?1",
            i64::from(limit),
        )?;
        latest.reverse();
        Ok(latest)
    }

    fn omissions(&self, sql: &str, limit: i64) -> Result<Vec<Omission>, Error> {
        let mut stmt = self.db.prepare(sql)?;
        let rows = stmt.query_map([limit], |r| {
            Ok((
                point(r)?,
                r.get::<_, String>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, String>(4)?,
                unsigned(r, 5)?,
            ))
        })?;
        let mut omissions = Vec::new();
        for row in rows {
            let (block, peer, position, txid, generation) = row?;
            omissions.push(Omission {
                peer,
                block,
                position,
                txid: txid
                    .parse()
                    .map_err(|error| Error::Invalid(format!("stored omission TXID: {error}")))?,
                generation,
            });
        }
        Ok(omissions)
    }
}

/// First height at or after `start` not covered by the ordered ranges.
fn contiguous(
    start: u64,
    rows: impl Iterator<Item = Result<(u64, u64), rusqlite::Error>>,
) -> Result<u64, Error> {
    let mut next = start;
    for row in rows {
        let (from, to) = row?;
        if from > next {
            break;
        }
        let after = to
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("peer coverage height overflow".into()))?;
        next = next.max(after);
    }
    Ok(next)
}

pub(super) fn synced_through(db: &Connection, start: u64) -> Result<Option<ChainPoint>, Error> {
    let mut stmt = db.prepare(
        "SELECT from_height,to_height FROM peer_coverage WHERE generation=?1 ORDER BY from_height",
    )?;
    let epoch = sql_integer(generation(db)?)?;
    let rows = stmt.query_map([epoch], |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)))?;
    let next = contiguous(start, rows)?;
    let Some(last) = next.checked_sub(1).filter(|last| *last >= start) else {
        return Ok(None);
    };
    Ok(db
        .query_row(
            "SELECT height,hash FROM selected WHERE height=?1",
            [sql_integer(last)?],
            point,
        )
        .optional()?)
}

pub(super) fn unaudited_count(db: &Connection) -> Result<u64, Error> {
    Ok(db.query_row(
        "SELECT count(*) FROM records r JOIN selected s ON s.hash=r.block_hash
         WHERE NOT EXISTS(SELECT 1 FROM scans c WHERE c.block_hash=r.block_hash)",
        [],
        |r| unsigned(r, 0),
    )?)
}

pub(super) fn omission_count(db: &Connection) -> Result<u64, Error> {
    Ok(db.query_row(
        "SELECT count(*) FROM peer_omissions o JOIN selected s ON s.hash=o.block_hash",
        [],
        |r| unsigned(r, 0),
    )?)
}

/// Placements found by a full scan that no earlier admission supplied are
/// omissions of every peer whose current coverage claims this height.
/// "Held" means any records row at that placement, whatever its source, so an
/// empty omitting_peers is not proof that a peer listed everything.
/// Only complete records are checked, matching inventories that list records
/// rows only: pending dependencies are never omissions. LeafManifest and
/// DataPart records are exempt, since a pruned peer may omit them while scanning.
pub(super) fn record_omissions(db: &Connection, batch: &ScanBatch) -> Result<(), Error> {
    let block = batch.ticket.point();
    let hash = block.hash.to_string();
    let epoch = sql_integer(generation(db)?)?;
    let height = sql_integer(block.height)?;
    let peers = {
        let mut stmt = db.prepare(
            "SELECT peer FROM peer_coverage
             WHERE generation=?1 AND from_height<=?2 AND to_height>=?2",
        )?;
        let rows = stmt.query_map(params![epoch, height], |r| r.get(0))?;
        rows.collect::<Result<Vec<String>, _>>()?
    };
    if peers.is_empty() {
        return Ok(());
    }
    let mut positions = Vec::new();
    for record in &batch.records {
        if !prunable(&record.verified)? {
            positions.push(record.position);
        }
    }
    for position in positions {
        let held = db.query_row(
            "SELECT count(*) FROM records WHERE block_hash=?1 AND position=?2",
            params![hash, position],
            |r| unsigned(r, 0),
        )?;
        if held > 0 {
            continue;
        }
        let index = usize::try_from(position).map_err(|e| Error::Invalid(e.to_string()))?;
        let txid = batch
            .locators
            .get(index)
            .ok_or_else(|| Error::Invalid("record placement outside block".into()))?
            .0
            .to_string();
        for peer in &peers {
            db.execute(
                "INSERT OR IGNORE INTO peer_omissions VALUES(?1,?2,?3,?4,?5)",
                params![peer, hash, position, txid, epoch],
            )?;
        }
    }
    Ok(())
}

/// Called inside the reorg transaction after deselection and the generation
/// bump: coverage is truncated below the fork and re-stamped with the new
/// generation; omissions in deselected blocks are dropped, the rest keep
/// their detection generation.
pub(super) fn reorg(db: &Connection, first_deselected: u64) -> Result<(), Error> {
    let fork = sql_integer(first_deselected)?;
    db.execute(
        "UPDATE peer_coverage SET to_height=?1-1 WHERE from_height<?1 AND to_height>=?1",
        [fork],
    )?;
    db.execute("DELETE FROM peer_coverage WHERE from_height>=?1", [fork])?;
    db.execute(
        "DELETE FROM peer_omissions WHERE block_hash NOT IN (SELECT hash FROM selected)",
        [],
    )?;
    db.execute(
        "UPDATE peer_coverage SET generation=(SELECT generation FROM state WHERE singleton=1)",
        [],
    )?;
    Ok(())
}
