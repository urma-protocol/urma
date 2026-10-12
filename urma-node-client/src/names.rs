//! Local Names V0 projection of fully scanned selected history. These results
//! are operator index data, not portable proofs or pre-application coverage.
use crate::{model::ChainPoint, projection::IndexSnapshot};
use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};
use urma_names::state::{Outcome, Resolution};

pub const MAX_NAMES_PAGE: u32 = 128;
/// Bounds one stored JSON state before decoding, including up to 255 approvers.
pub const MAX_NAMES_STATE_BYTES: usize = 64 * 1024;
/// Oversized pages fail as a whole; entries are never silently omitted.
pub const MAX_NAMES_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// Canonical traversal order is all names (ASCII), then pending TXIDs (display
/// hex). In particular, TXID internal byte order is not the wire cursor order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NamesKey {
    Name(urma_names::name::Name),
    Pending(Txid),
}

impl NamesKey {
    pub fn order_key(&self) -> (u8, String) {
        match self {
            Self::Name(name) => (0, name.to_string()),
            Self::Pending(txid) => (1, txid.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesCursor {
    pub genesis: Txid,
    pub snapshot: IndexSnapshot,
    pub after: NamesKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NamesEntry {
    Name {
        name: urma_names::name::Name,
        state: urma_names::state::NameState,
    },
    Pending {
        txid: Txid,
        record: urma_names::state::PendingRecord,
    },
}

impl NamesEntry {
    pub fn key(&self) -> NamesKey {
        match self {
            Self::Name { name, .. } => NamesKey::Name(name.clone()),
            Self::Pending { txid, .. } => NamesKey::Pending(*txid),
        }
    }
}

/// One immutable local projection page. A full traversal includes unbound and
/// suspended states and completed pending records; consumers must not omit them
/// when reproducing local resolution/review views. No undo, commit window or
/// autonomous scanner checkpoints are supplied. This is not a NamesIndex import
/// or portable proof. `next == None` ends this local snapshot only; completeness
/// through the selected tip is reported separately by `status`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesPage {
    pub snapshot: IndexSnapshot,
    pub chain_genesis: BlockHash,
    pub status: NamesStatus,
    pub rules: urma_names::payload::Genesis,
    pub entries: Vec<NamesEntry>,
    pub next: Option<NamesCursor>,
}

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
