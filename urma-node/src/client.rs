//! Optional, explicitly configured loopback client. No daemon is started and no
//! DNS, proxy, environment configuration or chain source is consulted.
//!
//! Responses are DATA supplied by a locally trusted operator, not independently
//! verified chain evidence. A receiver using a package from a peer must pass it
//! through `Engine::admit_record`, with its independently selected chain view.
//!
//! Transport, framing limits and operation deadlines are provided by
//! [`urma_node_client::Client`]. This wrapper preserves Node error types and
//! the local record-source adapter; it performs no automatic retry.

use crate::{
    Error,
    model::{ArchivedRecord, ObjectStatus, PinReceipt, PruneReceipt},
    projection::{WireCursor, WirePage},
};
use bitcoin::Txid;
use std::net::SocketAddr;

/// An optional local service connection, trusting the configured local operator.
/// Construction performs no I/O. Each operation opens one bounded connection.
pub struct Client {
    inner: urma_node_client::Client,
}

impl Client {
    pub fn new(address: SocketAddr, token: String) -> Result<Self, Error> {
        urma_node_client::Client::new(address, token)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Read status reported by the local operator, without verifying its claims.
    pub fn status(&self) -> Result<serde_json::Value, Error> {
        self.inner.status().map_err(Error::from)
    }

    /// Read locally archived data. `None` means HTTP 404 (not locally available),
    /// not proof that a record does not exist. Authentication and other failures
    /// remain errors. Only the receipt's TXID is compared with the requested ID.
    ///
    /// The chain is unknown here: reveal decoding, TXID/witness recomputation,
    /// inclusion and URMA verification belong to independent admission through
    /// `Engine::admit_record`. Deserialization does not establish those claims.
    pub fn record(&self, txid: Txid) -> Result<Option<ArchivedRecord>, Error> {
        self.inner.record(txid).map_err(Error::from)
    }

    /// Read object availability reported by the configured local operator.
    /// These are operator data, not independently verified chain evidence.
    /// Selected member count is independent of local retention: either count
    /// may exceed the other, but both must be within a nonzero member total.
    /// `None` means only that no completed object is recorded locally (HTTP 404),
    /// not global absence. Root/count sanity checks establish no crypto claims.
    pub fn object_status(&self, root: Txid) -> Result<Option<ObjectStatus>, Error> {
        self.inner.object_status(root).map_err(Error::from)
    }

    /// Request a local pin or unpin and read the operator's acknowledgement at
    /// its commit point. This is not cryptographic evidence or a promise of
    /// future availability, chain selection or pin state. Only HTTP 200 with
    /// the requested root and pin value succeeds. No automatic retry occurs:
    /// the operation may already have committed before a socket failure.
    pub fn set_pin(&self, root: Txid, pin: bool) -> Result<PinReceipt, Error> {
        self.inner.set_pin(root, pin).map_err(Error::from)
    }

    /// Request explicit local cache pruning and read the operator's removal
    /// count. This acknowledgement is not cryptographic evidence or a promise
    /// of future cache contents. Only HTTP 200 succeeds. No automatic retry
    /// occurs, including when a socket failure leaves the commit outcome unknown.
    pub fn prune_cache(&self) -> Result<PruneReceipt, Error> {
        self.inner.prune_cache().map_err(Error::from)
    }

    /// Read one bounded page of Wire records from the configured local operator.
    /// Entry parsing checks data consistency, not authorship or chain inclusion.
    /// Selected records and scanned coverage remain separate; `next == None`
    /// ends only the local result set and does not establish chain completeness.
    /// A snapshot is opaque. HTTP 409 returns `Error::Busy`: discard the partial
    /// traversal and explicitly restart. No paging, retry or readback is automatic.
    pub fn wire_page(&self, cursor: Option<&WireCursor>, limit: u32) -> Result<WirePage, Error> {
        self.inner.wire_page(cursor, limit).map_err(Error::from)
    }
}

/// Fetch data only from the explicitly configured local operator endpoint.
/// This adapter performs no peer or network discovery. The receiving engine
/// independently verifies the package against its own selected headers.
impl crate::retrieval::RecordSource for Client {
    fn fetch(&self, txid: Txid) -> Result<Option<crate::model::RecordPackage>, Error> {
        Ok(self.record(txid)?.map(|record| record.package))
    }
}
