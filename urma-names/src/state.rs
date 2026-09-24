use crate::{name::Name, payload::Payload};
use bitcoin::{Txid, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Reserved,
    Publication(Txid),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    pub owner: XOnlyPublicKey,
    pub target: Target,
    pub expiry: u64,
    pub claim_txid: Txid,
    pub last_txid: Txid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Binding {
    Unbound,
    Bound(Bound),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameState {
    pub binding: Binding,
    pub suspended: bool,
    pub suspend_votes: BTreeSet<XOnlyPublicKey>,
    pub restore_votes: BTreeSet<XOnlyPublicKey>,
}

impl NameState {
    pub fn unbound() -> Self {
        Self {
            binding: Binding::Unbound,
            suspended: false,
            suspend_votes: BTreeSet::new(),
            restore_votes: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    Request,
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecord {
    pub kind: PendingKind,
    pub name: Name,
    pub author: XOnlyPublicKey,
    pub target: Txid,
    pub sha256: [u8; 32],
    pub height: u64,
    pub approvals: BTreeSet<XOnlyPublicKey>,
    pub completed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub txid: Txid,
    pub vout: u32,
    pub height: u64,
    pub position: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub txid: Txid,
    pub author: XOnlyPublicKey,
    pub record_sha256: [u8; 32],
    pub payload: Payload,
    pub height: u64,
    pub position: u32,
    pub commit: Commit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    ForeignRegistry,
    CommitNotAfterGenesis,
    RevealWindow,
    Overflow,
    OpenRegistry,
    NotApprover,
    UnknownRecord,
    HashMismatch,
    Completed,
    Repeated,
    ZeroTarget,
    NameBound,
    NameUnbound,
    NotOwner,
    TargetChanged,
    NameSuspended,
    OwnerChanged,
    WrongPhase,
    LostRace,
}

impl Display for Rejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ForeignRegistry => "record addresses another registry",
            Self::CommitNotAfterGenesis => "commit is not after the genesis block",
            Self::RevealWindow => "reveal is outside the commit window",
            Self::Overflow => "expiry height overflow",
            Self::OpenRegistry => "approver record in an open registry",
            Self::NotApprover => "author is not an approver",
            Self::UnknownRecord => "approved record is not a known earlier request or update",
            Self::HashMismatch => "approval hash does not match the record",
            Self::Completed => "record already completed",
            Self::Repeated => "key already counted",
            Self::ZeroTarget => "zero target",
            Self::NameBound => "name is bound",
            Self::NameUnbound => "name is unbound",
            Self::NotOwner => "author is not the owner",
            Self::TargetChanged => "renewal target differs from the served target",
            Self::NameSuspended => "name is suspended",
            Self::OwnerChanged => "owner changed before completion",
            Self::WrongPhase => "record in the wrong suspension phase",
            Self::LostRace => "an older commit won the block",
        })
    }
}

impl std::error::Error for Rejection {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Applied,
    Pending,
    Inert(Rejection),
    Invalid(Rejection),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub txid: Txid,
    pub position: u32,
    pub verdict: Verdict,
}

impl Outcome {
    pub fn new(observation: &Observation, verdict: Verdict) -> Self {
        Self {
            txid: observation.txid,
            position: observation.position,
            verdict,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    Unbound,
    Bound(Bound),
    Suspended,
}
