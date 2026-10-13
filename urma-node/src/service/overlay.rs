//! Overlay steps of the Service round: peer discovery, then inventory sync.
//! Each is optional, stop-guarded and keeps its own recorded error.
use super::Service;
use crate::{
    Error,
    model::{BookEntry, OverlayStatus},
    peer_discovery::Discovery,
    peer_sync::{PeerSync, Scheduler},
    recorded::{record, unix_seconds},
};
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
        let result = self
            .share_sync_backoff(discovery)
            .and_then(|()| discovery.step(&self.engine, &self.stop));
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        record(&self.discovery_error, &result);
    }

    /// Discovery must not redial a peer sync is holding off, or it would
    /// refill the slot an eviction or idle release just freed.
    fn share_sync_backoff(&self, discovery: &Discovery) -> Result<(), Error> {
        let Some(scheduler) = &self.peer_sync else {
            return Ok(());
        };
        discovery.hold_off(scheduler.backed_off(unix_seconds()?)?)
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
            .and_then(|()| scheduler.step(&self.engine, &self.stop))
            .and_then(|()| self.penalize_in_book(scheduler));
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        record(&self.inventory_error, &result);
    }

    /// Peers the scheduler backed off also back off in the book, so discovery
    /// stops dialing them; without discovery there is no book to tell.
    fn penalize_in_book(&self, scheduler: &Scheduler) -> Result<(), Error> {
        let penalized = scheduler.drain_penalized()?;
        match &self.discovery {
            Some(discovery) => discovery.penalize(&penalized),
            None => Ok(()),
        }
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

    /// `None` without discovery: the route answers 404 "overlay disabled".
    pub(super) fn overlay_book(&self) -> Result<Option<Vec<BookEntry>>, Error> {
        self.discovery.as_ref().map(Discovery::book).transpose()
    }
}
