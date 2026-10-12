//! Local Names V0 projection of fully scanned selected history. These results
//! are operator index data, not portable proofs or pre-application coverage.
use crate::model::ChainPoint;
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use urma_names::state::{Outcome, Resolution};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesStatus {
    pub genesis: Txid,
    pub genesis_block: ChainPoint,
    pub projected: ChainPoint,
    pub generation: u64,
    pub selected_tip: Option<ChainPoint>,
    pub complete_to_tip: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesStep {
    pub status: NamesStatus,
    pub applied: Option<ChainPoint>,
    pub rolled_back: u64,
    pub outcomes: Vec<Outcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesResolution {
    pub status: NamesStatus,
    pub resolution: Resolution,
}
