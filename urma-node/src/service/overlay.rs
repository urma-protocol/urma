//! Overlay steps of the Service round: peer discovery, then inventory sync.
//! Each is optional, stop-guarded and keeps its own recorded error.
use super::Service;
use crate::{
    Error,
    model::OverlayStatus,
    peer_discovery::Discovery,
    peer_sync::{PeerSync, Scheduler},
    recorded::record,
};
use serde_json::Value;
use std::sync::atomic::Ordering;

impl Service {
    /// Fast inventory synchronization from configured overlay peers. Only
    /// run(true) schedules it; configuring peers does not dial or fetch.
    pub fn with_peer_sync(mut self, sync: PeerSync) -> Result<Self, Error> {
        self.peer_sync = Some(Scheduler::new(sync)?);
        Ok(self)
    }

    /// Automatic peer discovery from seeds and peer address exchange. Only
    /// run(true) schedules it, as its own bounded step before inventory sync.
    pub fn with_discovery(mut self, discovery: Discovery) -> Result<Self, Error> {
        self.discovery = Some(discovery);
        Ok(self)
    }

    pub(super) fn discover_peers(&self) {
        let Some(discovery) = &self.discovery else {
            return;
        };
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        let result = discovery.step(&self.engine, &self.stop);
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        record(&self.discovery_error, &result);
    }

    pub(super) fn sync_next_inventory(&self) {
        let Some(scheduler) = &self.peer_sync else {
            return;
        };
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        let result = self
            .refresh_sync_peers(scheduler)
            .and_then(|()| scheduler.step(&self.engine, &self.stop));
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        record(&self.inventory_error, &result);
    }

    /// With discovery, the inventory peers follow the book every step.
    fn refresh_sync_peers(&self, scheduler: &Scheduler) -> Result<(), Error> {
        let Some(discovery) = &self.discovery else {
            return Ok(());
        };
        let omitting = self.engine.omitting_peers()?;
        scheduler.refresh(discovery.sync_sources(&omitting)?)
    }

    /// The sync view with discovery counters attached when both run.
    pub(super) fn overlay_status(&self) -> Result<Option<OverlayStatus>, Error> {
        let Some(scheduler) = &self.peer_sync else {
            return Ok(None);
        };
        let mut overlay = scheduler.status(&self.engine)?;
        if let Some(discovery) = &self.discovery {
            overlay.discovery = Some(discovery.status()?);
        }
        Ok(Some(overlay))
    }

    pub(super) fn overlay_book(&self) -> Result<Value, Error> {
        match &self.discovery {
            Some(discovery) => discovery.book_json(),
            None => Err(Error::Invalid("peer discovery is not configured".into())),
        }
    }
}
