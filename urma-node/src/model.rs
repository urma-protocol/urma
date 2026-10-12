//! Shared local API models, with archive-only capabilities kept in this crate.
pub use urma_node_client::model::*;

/// A capability issued by this archive for a particular selected block.
/// The epoch changes on a reorg; a worker cannot commit using an old ticket.
#[derive(Clone, Copy, Debug)]
pub struct ScanTicket {
    pub(crate) generation: u64,
    pub(crate) point: ChainPoint,
}

/// A selected record placement a peer's coverage claimed but did not list.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Omission {
    pub peer: String,
    pub block: ChainPoint,
    pub position: u32,
    pub txid: bitcoin::Txid,
    pub generation: u64,
}

impl ScanTicket {
    pub fn point(self) -> ChainPoint {
        self.point
    }
}
