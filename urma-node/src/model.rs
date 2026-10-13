//! Shared local API models, with archive-only capabilities kept in this crate.
pub use urma_node_client::model::*;

/// A capability issued by this archive for a particular selected block.
/// The epoch changes on a reorg; a worker cannot commit using an old ticket.
#[derive(Clone, Copy, Debug)]
pub struct ScanTicket {
    pub(crate) generation: u64,
    pub(crate) point: ChainPoint,
}

impl ScanTicket {
    pub fn point(self) -> ChainPoint {
        self.point
    }
}
