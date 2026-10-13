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
    model::{
        ArchivedRecord, BookEntry, ChainPoint, ObjectStatus, Omission, PinReceipt, PruneReceipt,
        ServiceStatus,
    },
    names::{NamesCursor, NamesPage, NamesResolution, NamesStatus, NamesStep},
    projection::{WireCursor, WirePage},
};
use bitcoin::Txid;
use std::net::SocketAddr;
use urma_names::name::Name;

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

    /// Typed service status reported by the local operator, without verifying its claims.
    pub fn status(&self) -> Result<ServiceStatus, Error> {
        self.inner.status().map_err(Error::from)
    }

    /// Raw status JSON reported by the local operator, without verifying its claims.
    pub fn status_json(&self) -> Result<serde_json::Value, Error> {
        self.inner.status_json().map_err(Error::from)
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

    /// Recorded peer omissions; HTTP 404 is `Error::Invalid("overlay disabled")`.
    pub fn overlay_omissions(&self) -> Result<Vec<Omission>, Error> {
        self.inner.overlay_omissions().map_err(Error::from)
    }

    /// The peer book's routing hints; HTTP 404 is `Error::Invalid("overlay disabled")`.
    pub fn overlay_book(&self) -> Result<Vec<BookEntry>, Error> {
        self.inner.overlay_book().map_err(Error::from)
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

    /// Register an explicitly located genesis with the local operator. This is
    /// a local index acknowledgement, not independent evidence or permanent state.
    /// HTTP 409 remains Busy; a possibly committed operation is never retried.
    pub fn register_names(&self, genesis: Txid, block: ChainPoint) -> Result<NamesStatus, Error> {
        self.inner
            .register_names(genesis, block)
            .map_err(Error::from)
    }

    /// Request one local Names step and read operator outcomes. No independent
    /// proof, automatic stepping, retry or readback; HTTP 409 remains Busy.
    pub fn names_step(&self, genesis: Txid) -> Result<NamesStep, Error> {
        self.inner.names_step(genesis).map_err(Error::from)
    }

    /// Read operator Names progress. None means only locally unregistered (404),
    /// not global absence. No stepping or retry; HTTP 409 remains Busy.
    pub fn names_status(&self, genesis: Txid) -> Result<Option<NamesStatus>, Error> {
        self.inner.names_status(genesis).map_err(Error::from)
    }

    /// Read local operator resolution for a canonical name, not independent
    /// ownership evidence or permanent state. No stepping/retry; 409 remains Busy.
    pub fn names_resolve(&self, genesis: Txid, name: &Name) -> Result<NamesResolution, Error> {
        self.inner.names_resolve(genesis, name).map_err(Error::from)
    }

    /// Read one local operator Names page, not independent chain/registry evidence.
    /// The consumer checks its expected chain and metadata consistency across pages.
    /// No automatic paging, stepping or retry; 409 remains Busy and ends traversal.
    /// Absent continuation ends only the local snapshot, not chain completeness.
    pub fn names_view(
        &self,
        genesis: Txid,
        cursor: Option<&NamesCursor>,
        limit: u32,
    ) -> Result<NamesPage, Error> {
        self.inner
            .names_view(genesis, cursor, limit)
            .map_err(Error::from)
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
