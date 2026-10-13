use super::{Archive, point, sql_integer, unsigned};
use crate::{Error, projection::*};
use bitcoin::{Txid, Weight};
use rusqlite::{Row, params};
use urma_chain::{decode, observation::Chain};
use urma_core::format::Urma;

impl Archive {
    pub(crate) fn wire_page(
        &self,
        instance: &str,
        cursor: Option<&WireCursor>,
        limit: u32,
    ) -> Result<WirePage, Error> {
        if !(1..=MAX_WIRE_PAGE).contains(&limit) {
            return Err(Error::Invalid("Wire page limit must be 1..128".into()));
        }
        let revision =
            self.db
                .query_row("SELECT COALESCE(MAX(sequence),0) FROM events", [], |r| {
                    unsigned(r, 0)
                })?;
        let snapshot = IndexSnapshot {
            instance: instance.into(),
            revision,
        };
        if cursor.is_some_and(|cursor| cursor.snapshot != snapshot) {
            return Err(Error::Busy(
                "Wire index snapshot changed; restart traversal".into(),
            ));
        }
        let (height, position) = match cursor {
            Some(cursor) => (sql_integer(cursor.height)?, i64::from(cursor.position)),
            None => (-1, -1),
        };
        // A derived view of already verified records, not a second block scan.
        // The kind predicate is only a prefilter; the common Wire projector
        // strictly checks the full V0 payload below. Bound blobs before loading
        // even if local storage is corrupted. At most 128 public records/page.
        let mut statement = self.db.prepare(
            "SELECT s.height,s.hash,r.position,r.wtxid,t.txid,r.author,
             CASE WHEN length(r.record)<=?4 THEN r.record ELSE NULL END,
             CASE WHEN length(t.raw)<=?5 THEN t.raw ELSE NULL END
             FROM selected s JOIN records r ON r.block_hash=s.hash
             JOIN transactions t ON t.wtxid=r.wtxid
             WHERE (s.height>?1 OR (s.height=?1 AND r.position>?2))
             AND substr(r.record,6,1) IN (x'02',x'04',x'05',x'06',x'0a',x'0b')
             ORDER BY s.height,r.position LIMIT ?3",
        )?;
        let mut rows = statement.query(params![
            height,
            position,
            i64::from(limit) + 1,
            (Urma::PREFIX_BYTES + Urma::MAX_PUBLIC_BYTES) as i64,
            sql_integer(Weight::MAX_BLOCK.to_wu())?,
        ])?;
        let mut records = Vec::new();
        let mut next = None;
        while let Some(row) = rows.next()? {
            if records.len() == limit as usize {
                let last: &WireRecord = records.last().expect("nonzero page limit");
                next = Some(WireCursor {
                    snapshot: snapshot.clone(),
                    height: last.entry.height,
                    position: last.entry.position,
                });
                break;
            }
            records.push(wire_record(row, self.config.chain)?);
        }
        Ok(WirePage {
            snapshot,
            archive: self.status()?,
            records,
            next,
        })
    }
}

fn wire_record(row: &Row<'_>, chain: Chain) -> Result<WireRecord, Error> {
    let block = point(row)?;
    let position: u32 = row.get(2)?;
    let wtxid: String = row.get(3)?;
    let txid: String = row.get(4)?;
    let author: String = row.get(5)?;
    let bytes: Option<Vec<u8>> = row.get(6)?;
    let bytes = bytes.ok_or_else(|| Error::Invalid("stored Wire record exceeds bound".into()))?;
    let raw: Option<Vec<u8>> = row.get(7)?;
    let raw = raw.ok_or_else(|| Error::Invalid("stored Wire reveal exceeds bound".into()))?;
    let reveal = decode::transaction(&raw, chain)
        .map_err(|e| Error::Invalid(format!("stored Wire reveal: {e}")))?;
    let txid: Txid = txid
        .parse()
        .map_err(|e| Error::Invalid(format!("stored Wire TXID: {e}")))?;
    if reveal.compute_txid() != txid {
        return Err(Error::Invalid(
            "stored Wire reveal identity mismatch".into(),
        ));
    }
    let returned = reveal
        .output
        .first()
        .ok_or_else(|| Error::Invalid("stored Wire reveal has no return output".into()))?;
    let entry = urma_wire::index::entry_from_record(
        &bytes,
        txid,
        author
            .parse()
            .map_err(|e| Error::Invalid(format!("stored Wire author: {e}")))?,
        Some(&returned.script_pubkey),
        block.height,
        position,
    )
    .map_err(|e| Error::Invalid(format!("stored Wire record: {e}")))?
    .ok_or_else(|| Error::Invalid("stored Wire kind mismatch".into()))?;
    Ok(WireRecord {
        block_hash: block.hash,
        wtxid: wtxid
            .parse()
            .map_err(|e| Error::Invalid(format!("stored Wire WTXID: {e}")))?,
        entry,
    })
}
