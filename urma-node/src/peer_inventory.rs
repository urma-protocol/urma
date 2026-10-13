//! Serving local lookups and bounded inventory pages over the overlay, plus the
//! client-side inventory request. Pages describe only fully scanned blocks.
use crate::{
    Error,
    engine::Engine,
    model::RecordPackage,
    peer::{Answer, CALL_TIMEOUT, PeerSource, Pending, bind_response},
    peer_protocol::{
        INVENTORY_ENTRIES, INVENTORY_LIMIT, INVENTORY_SPAN, InventoryPage, Kind, PARENT_LIMIT,
        Placement, Reply, Request, Response,
    },
    source::check_cancelled,
};
use bitcoin::{BlockHash, Txid};
use libp2p::PeerId;
use std::{sync::atomic::AtomicBool, time::Instant};

/// Local retained bytes only: never scans, fetches or asks another peer.
pub(crate) fn lookup(engine: &Engine, request: &Request) -> Reply {
    match request.kind {
        Kind::Record { txid } => match engine.record(txid) {
            Ok(Some(record)) => Reply::Record(Box::new(record.package)),
            Ok(None) => Reply::Missing,
            Err(_) => Reply::Busy,
        },
        Kind::Parent { txid } => match engine.raw_transaction(txid) {
            Ok(Some(raw)) if raw.len() > PARENT_LIMIT => Reply::TooLarge,
            Ok(Some(raw)) => Reply::Parent(hex::encode(raw)),
            Ok(None) => Reply::Missing,
            Err(_) => Reply::Busy,
        },
        Kind::Inventory {
            from_height,
            to_height,
            after,
            limit,
        } => inventory(engine, (from_height, to_height), after, limit),
        // Gossip is served by the network thread from memory, never from here.
        Kind::Peers { .. } => Reply::Refused,
    }
}

fn admissible(from: u64, to: u64, limit: u32) -> bool {
    to >= from && to - from <= INVENTORY_SPAN && (1..=INVENTORY_ENTRIES).contains(&limit)
}

fn inventory(engine: &Engine, range: (u64, u64), after: Option<Placement>, limit: u32) -> Reply {
    const ENVELOPE: usize = 1024;
    let (from, to) = range;
    if !admissible(from, to, limit) {
        return Reply::Refused;
    }
    let cursor = after.map(|placement| (placement.height, placement.position));
    let rows = match engine.inventory_page(from, to, cursor, limit) {
        Ok(rows) => rows,
        Err(_) => return Reply::Busy,
    };
    let entries = rows
        .entries
        .into_iter()
        .map(|(block, position, txid, wtxid)| Placement {
            height: block.height,
            block_hash: block.hash,
            position,
            txid,
            wtxid,
        })
        .collect();
    let page = InventoryPage {
        scanned_through: rows.scanned_through,
        entries,
        more: rows.more,
    };
    match serde_json::to_vec(&page) {
        Ok(bytes) if bytes.len() + ENVELOPE <= INVENTORY_LIMIT => Reply::Inventory(page),
        _ => Reply::TooLarge,
    }
}

/// Missing is no answer and Busy is retryable. Refusals, limits and other
/// kinds are errors.
pub(crate) fn validate_inventory(
    genesis: BlockHash,
    peer: PeerId,
    pending: &Pending,
    response: Response,
) -> Result<Option<InventoryPage>, Error> {
    bind_response(genesis, peer, pending, &response)?;
    match response.result {
        Reply::Inventory(page) => check_page(&response.kind, page).map(Some),
        Reply::Missing => Ok(None),
        Reply::Busy => Err(Error::PeerBusy),
        Reply::Record(_) | Reply::Parent(_) | Reply::Peers(_) => Err(Error::Invalid(
            "peer answered an inventory request with another kind".into(),
        )),
        Reply::Refused | Reply::TooLarge | Reply::WrongNetwork | Reply::UnsupportedVersion => {
            Err(Error::Invalid("peer refused the inventory request".into()))
        }
    }
}

/// Entries stay inside the requested range and limit, strictly after the
/// cursor in (height, position) order. Placement truth is the caller's check.
fn check_page(kind: &Kind, page: InventoryPage) -> Result<InventoryPage, Error> {
    let Kind::Inventory {
        from_height,
        to_height,
        after,
        limit,
    } = *kind
    else {
        return Err(Error::Invalid("inventory reply to another request".into()));
    };
    let limit = usize::try_from(limit).map_err(|e| Error::Invalid(e.to_string()))?;
    if page.entries.len() > limit {
        return Err(Error::Invalid(
            "peer inventory exceeds the requested limit".into(),
        ));
    }
    let mut previous = after.map(|placement| (placement.height, placement.position));
    for entry in &page.entries {
        let at = (entry.height, entry.position);
        let ordered = previous.is_none_or(|last| at > last);
        if entry.height < from_height || entry.height > to_height || !ordered {
            return Err(Error::Invalid(
                "peer inventory entry out of range or order".into(),
            ));
        }
        previous = Some(at);
    }
    Ok(page)
}

impl PeerSource {
    /// One bounded inventory page. Missing or Busy, remote or local (including
    /// deadline and stopped network), is None; refusals and limits are errors.
    pub fn inventory(
        &self,
        from_height: u64,
        to_height: u64,
        after: Option<Placement>,
        limit: u32,
        cancelled: &AtomicBool,
    ) -> Result<Option<InventoryPage>, Error> {
        let range = (from_height, to_height);
        let deadline = Instant::now() + CALL_TIMEOUT;
        match self.inventory_until(range, after, limit, cancelled, deadline) {
            Err(Error::Busy(_) | Error::PeerBusy) => Ok(None),
            other => other,
        }
    }

    /// One record request bounded by CALL_TIMEOUT and the caller's `deadline`.
    pub(crate) fn fetch_until(
        &self,
        txid: Txid,
        deadline: Instant,
    ) -> Result<Option<RecordPackage>, Error> {
        self.request(Kind::Record { txid }, deadline, Answer::Record)
    }

    /// As `inventory`, also bounded by the caller's own `deadline`; Busy,
    /// remote or local, stays an error so the scheduler can count it.
    pub(crate) fn inventory_until(
        &self,
        (from_height, to_height): (u64, u64),
        after: Option<Placement>,
        limit: u32,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Option<InventoryPage>, Error> {
        check_cancelled(cancelled)?;
        let kind = Kind::Inventory {
            from_height,
            to_height,
            after,
            limit,
        };
        self.request(kind, deadline, Answer::Inventory)
    }
}
