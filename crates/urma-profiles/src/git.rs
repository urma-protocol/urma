use bitcoin::Txid;
use urma_chain::observation::ChainId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLocator {
    pub chain: ChainId,
    pub root: Txid,
}

pub struct GitProfile;
impl GitProfile {
    pub const IDENTIFIER: [u8; 8] = *b"URMAGIT0";
}
