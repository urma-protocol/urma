use super::{Archive, unsigned};
use crate::{
    Error,
    cache::*,
    model::{CacheReceipt, Retention},
};
use rusqlite::Connection;

// Match the complete V0 prefix, not just the kind byte. No blob is loaded into
// Rust. Pins protect exact placements globally, including retained orphans.
const ELIGIBLE: &str = "WITH eligible AS (
    SELECT r.block_hash,r.position,r.wtxid,r.commit_wtxid,r.record,r.proof
    FROM records r
    WHERE substr(r.record,1,8) IN (x'55524d4100070000',x'55524d4100080000')
    AND NOT EXISTS(SELECT 1 FROM object_members m JOIN pins p ON p.root_txid=m.root_txid
        WHERE m.block_hash=r.block_hash AND m.position=r.position AND m.wtxid=r.wtxid)
)";

fn reclaimable_bytes(db: &Connection) -> Result<u64, Error> {
    // Raw bytes are counted once per transactions PK (WTXID). Eligible-only
    // references do not protect raw from this potential-reclamation metric;
    // actual deletion below requires ALL remaining references to be absent.
    let query = format!("{ELIGIBLE}, protected_raw AS (
        SELECT r.wtxid AS id FROM records r WHERE (r.block_hash,r.position) NOT IN
            (SELECT block_hash,position FROM eligible)
        UNION
        SELECT r.commit_wtxid FROM records r WHERE (r.block_hash,r.position) NOT IN
            (SELECT block_hash,position FROM eligible)
    ) SELECT
        (SELECT COALESCE(SUM(length(CAST(record AS BLOB))+length(CAST(proof AS BLOB))),0) FROM eligible)
        + (SELECT COALESCE(SUM(length(CAST(raw AS BLOB))),0) FROM transactions
            WHERE wtxid NOT IN (SELECT id FROM protected_raw)
            AND txid NOT IN (SELECT commit_txid FROM dependencies))");
    Ok(db.query_row(&query, [], |row| unsigned(row, 0))?)
}

impl Archive {
    pub(crate) fn maintain_cache(&mut self, limit_bytes: u64) -> Result<CacheReceipt, Error> {
        let enabled = self.config.retention == Retention::Pruned;
        let mut receipt = CacheReceipt {
            enabled,
            limit_bytes,
            before_bytes: 0,
            remaining_bytes: 0,
            removed_records: 0,
            removed_transactions: 0,
            over_budget: false,
        };
        if !enabled {
            return Ok(receipt);
        }
        let tx = self.db.transaction()?;
        receipt.before_bytes = reclaimable_bytes(&tx)?;
        receipt.remaining_bytes = receipt.before_bytes;
        if receipt.before_bytes > limit_bytes {
            // Stable order, not LRU. A full batch can undershoot the target;
            // this deliberately makes no minimal-victim-set promise.
            let query = format!(
                "{ELIGIBLE} SELECT block_hash,position FROM eligible
                ORDER BY block_hash,position LIMIT ?1"
            );
            let candidates = {
                let mut statement = tx.prepare(&query)?;
                statement
                    .query_map([MAX_CACHE_RECORDS as i64], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for (block, position) in candidates {
                receipt.removed_records += tx.execute(
                    "DELETE FROM records WHERE block_hash=?1 AND position=?2",
                    rusqlite::params![block, position],
                )? as u64;
            }
            // Include old unreferenced backlog as well as newly freed pairs.
            // Dependencies protect every witness variant of their parent TXID.
            receipt.removed_transactions = tx.execute(
                "DELETE FROM transactions WHERE wtxid IN (
                    SELECT wtxid FROM transactions
                    WHERE wtxid NOT IN (SELECT wtxid FROM records UNION SELECT commit_wtxid FROM records)
                    AND txid NOT IN (SELECT commit_txid FROM dependencies)
                    ORDER BY wtxid LIMIT ?1)", [MAX_CACHE_TRANSACTIONS as i64],
            )? as u64;
            receipt.remaining_bytes = reclaimable_bytes(&tx)?;
            if receipt.removed_records != 0 || receipt.removed_transactions != 0 {
                tx.execute(
                    "INSERT INTO events(generation,kind) SELECT generation,'cache' FROM state",
                    [],
                )?;
            }
        }
        receipt.over_budget = receipt.remaining_bytes > limit_bytes;
        tx.commit()?;
        Ok(receipt)
    }
}
