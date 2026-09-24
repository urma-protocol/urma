use crate::{
    config::state_of,
    name::Name,
    payload::{Approval, Genesis, Mode, NameOp, OwnerOp, Payload},
    state::{
        Binding, Bound, NameState, Observation, Outcome, PendingKind, PendingRecord, Rejection,
        Resolution, Target, Verdict,
    },
};
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use urma_core::error::{Error, ensure};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Previous<T> {
    Absent,
    Present(T),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Delta {
    names: Vec<(Name, Previous<NameState>)>,
    pending: Vec<(Txid, Previous<PendingRecord>)>,
}

enum Admission {
    Admitted,
    Rejected(Rejection),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    genesis: Txid,
    genesis_height: u64,
    rules: Genesis,
    height: u64,
    names: BTreeMap<Name, NameState>,
    pending: BTreeMap<Txid, PendingRecord>,
    expiries: BTreeSet<(u64, Name)>,
    undo: Vec<Delta>,
}

fn commit_key(observation: &Observation) -> (u64, u32, u32) {
    (
        observation.commit.height,
        observation.commit.position,
        observation.commit.vout,
    )
}

fn target_of(op: &OwnerOp) -> Target {
    if op.is_reserving() {
        Target::Reserved
    } else {
        Target::Publication(op.target)
    }
}

impl Registry {
    pub fn new(genesis: Txid, genesis_height: u64, rules: Genesis) -> Result<Self, Error> {
        rules.validate()?;
        Ok(Self {
            genesis,
            genesis_height,
            rules,
            height: genesis_height,
            names: BTreeMap::new(),
            pending: BTreeMap::new(),
            expiries: BTreeSet::new(),
            undo: Vec::new(),
        })
    }

    pub fn genesis(&self) -> Txid {
        self.genesis
    }

    pub fn genesis_height(&self) -> u64 {
        self.genesis_height
    }

    pub fn rules(&self) -> &Genesis {
        &self.rules
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn names(&self) -> &BTreeMap<Name, NameState> {
        &self.names
    }

    pub fn pending(&self) -> &BTreeMap<Txid, PendingRecord> {
        &self.pending
    }

    pub fn reversible_blocks(&self) -> usize {
        self.undo.len()
    }

    pub fn resolve(&self, name: &Name) -> Resolution {
        let state = state_of(&self.names, name);
        if state.suspended {
            return Resolution::Suspended;
        }
        match state.binding {
            Binding::Unbound => Resolution::Unbound,
            Binding::Bound(bound) => Resolution::Bound(bound),
        }
    }

    pub fn connect(
        &mut self,
        height: u64,
        mut observations: Vec<Observation>,
    ) -> Result<Vec<Outcome>, Error> {
        let expected = self
            .height
            .checked_add(1)
            .ok_or_else(|| Error::Capacity("height overflow".into()))?;
        ensure!(
            height == expected,
            "expected block {expected}, got {height}"
        );
        ensure!(
            observations
                .iter()
                .all(|observation| observation.height == height),
            "observation outside block {height}"
        );
        observations.sort_by_key(|observation| observation.position);
        ensure!(
            observations
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position),
            "duplicate block position"
        );
        self.undo.push(Delta {
            names: Vec::new(),
            pending: Vec::new(),
        });
        self.height = height;
        self.expire(height);
        let mut outcomes = Vec::new();
        self.approver_records(&observations, &mut outcomes);
        if self.rules.mode == Mode::Open {
            self.claims(&observations, &mut outcomes);
        }
        self.owner_records(&observations, &mut outcomes);
        Ok(outcomes)
    }

    pub fn disconnect(&mut self) -> Result<u64, Error> {
        let Some(delta) = self.undo.pop() else {
            return Err(Error::Missing("no reversible block".into()));
        };
        for (name, previous) in delta.names {
            match previous {
                Previous::Present(state) => self.store(name, state),
                Previous::Absent => self.forget(&name),
            }
        }
        for (txid, previous) in delta.pending {
            match previous {
                Previous::Present(record) => {
                    self.pending.insert(txid, record);
                }
                Previous::Absent => {
                    self.pending.remove(&txid);
                }
            }
        }
        let height = self.height;
        self.height = height
            .checked_sub(1)
            .ok_or_else(|| Error::Capacity("height underflow".into()))?;
        Ok(height)
    }

    pub fn prune(&mut self, keep: usize) {
        let Some(excess) = self.undo.len().checked_sub(keep) else {
            return;
        };
        let kept = self.undo.split_off(excess);
        self.undo = kept;
    }

    fn admit(&self, observation: &Observation, registry: Txid) -> Admission {
        if registry != self.genesis {
            return Admission::Rejected(Rejection::ForeignRegistry);
        }
        if observation.commit.height <= self.genesis_height {
            return Admission::Rejected(Rejection::CommitNotAfterGenesis);
        }
        let Some(age) = observation.height.checked_sub(observation.commit.height) else {
            return Admission::Rejected(Rejection::RevealWindow);
        };
        if age < 1 || age > u64::from(self.rules.reveal_max_blocks) {
            return Admission::Rejected(Rejection::RevealWindow);
        }
        Admission::Admitted
    }

    fn admit_approver(&self, observation: &Observation, registry: Txid) -> Admission {
        if let Admission::Rejected(rejection) = self.admit(observation, registry) {
            return Admission::Rejected(rejection);
        }
        if self.rules.mode == Mode::Open {
            return Admission::Rejected(Rejection::OpenRegistry);
        }
        if !self.rules.is_approver(&observation.author) {
            return Admission::Rejected(Rejection::NotApprover);
        }
        Admission::Admitted
    }

    fn expiry_after(&self, height: u64) -> Option<u64> {
        height.checked_add(u64::from(self.rules.expiry_blocks))
    }

    fn remember_name(&mut self, name: &Name) {
        let Some(delta) = self.undo.last_mut() else {
            panic!("connect frame missing");
        };
        if delta.names.iter().any(|entry| entry.0 == *name) {
            return;
        }
        let Some(state) = self.names.get(name) else {
            delta.names.push((name.clone(), Previous::Absent));
            return;
        };
        delta
            .names
            .push((name.clone(), Previous::Present(state.clone())));
    }

    fn remember_pending(&mut self, txid: &Txid) {
        let Some(delta) = self.undo.last_mut() else {
            panic!("connect frame missing");
        };
        if delta.pending.iter().any(|entry| entry.0 == *txid) {
            return;
        }
        let Some(record) = self.pending.get(txid) else {
            delta.pending.push((*txid, Previous::Absent));
            return;
        };
        delta
            .pending
            .push((*txid, Previous::Present(record.clone())));
    }

    fn store(&mut self, name: Name, state: NameState) {
        let previous = state_of(&self.names, &name);
        match &previous.binding {
            Binding::Bound(bound) => {
                self.expiries.remove(&(bound.expiry, name.clone()));
            }
            Binding::Unbound => {}
        }
        match &state.binding {
            Binding::Bound(bound) => {
                self.expiries.insert((bound.expiry, name.clone()));
            }
            Binding::Unbound => {}
        }
        self.names.insert(name, state);
    }

    fn forget(&mut self, name: &Name) {
        let previous = state_of(&self.names, name);
        match &previous.binding {
            Binding::Bound(bound) => {
                self.expiries.remove(&(bound.expiry, name.clone()));
            }
            Binding::Unbound => {}
        }
        self.names.remove(name);
    }

    fn set_name(&mut self, name: Name, state: NameState) {
        self.remember_name(&name);
        self.store(name, state);
    }

    fn expire(&mut self, height: u64) {
        let due: Vec<(u64, Name)> = self
            .expiries
            .iter()
            .take_while(|entry| entry.0 <= height)
            .cloned()
            .collect();
        for (expiry, name) in due {
            let mut state = state_of(&self.names, &name);
            match state.binding {
                Binding::Bound(..) => {}
                Binding::Unbound => {
                    self.expiries.remove(&(expiry, name));
                    continue;
                }
            }
            state.binding = Binding::Unbound;
            self.set_name(name, state);
        }
    }

    fn approver_records(&mut self, observations: &[Observation], outcomes: &mut Vec<Outcome>) {
        for observation in observations {
            let verdict = match &observation.payload {
                Payload::Approve(approval) => self.approve(observation, approval),
                Payload::Suspend(op) => self.vote(observation, op, true),
                Payload::Restore(op) => self.vote(observation, op, false),
                Payload::Genesis(..)
                | Payload::Claim(..)
                | Payload::Update(..)
                | Payload::Renew(..) => continue,
            };
            outcomes.push(Outcome::new(observation, verdict));
        }
    }

    fn approve(&mut self, observation: &Observation, approval: &Approval) -> Verdict {
        if let Admission::Rejected(rejection) = self.admit_approver(observation, approval.registry)
        {
            return Verdict::Invalid(rejection);
        }
        let Some(found) = self.pending.get(&approval.record_txid) else {
            return Verdict::Invalid(Rejection::UnknownRecord);
        };
        let mut record = found.clone();
        if record.sha256 != approval.record_sha256 {
            return Verdict::Invalid(Rejection::HashMismatch);
        }
        if record.completed {
            return Verdict::Inert(Rejection::Completed);
        }
        if !record.approvals.insert(observation.author) {
            return Verdict::Inert(Rejection::Repeated);
        }
        self.remember_pending(&approval.record_txid);
        let verdict = if record.approvals.len() < usize::from(self.rules.threshold) {
            Verdict::Applied
        } else {
            record.completed = true;
            self.complete(observation, approval.record_txid, &record)
        };
        self.pending.insert(approval.record_txid, record);
        verdict
    }

    fn complete(
        &mut self,
        observation: &Observation,
        record_txid: Txid,
        record: &PendingRecord,
    ) -> Verdict {
        let mut state = state_of(&self.names, &record.name);
        match record.kind {
            PendingKind::Request => {
                if state.suspended {
                    return Verdict::Inert(Rejection::NameSuspended);
                }
                match state.binding {
                    Binding::Bound(..) => return Verdict::Inert(Rejection::NameBound),
                    Binding::Unbound => {}
                }
                let Some(expiry) = self.expiry_after(observation.height) else {
                    return Verdict::Invalid(Rejection::Overflow);
                };
                state.binding = Binding::Bound(Bound {
                    owner: record.author,
                    target: Target::Publication(record.target),
                    expiry,
                    claim_txid: record_txid,
                    last_txid: observation.txid,
                });
            }
            PendingKind::Update => {
                let Binding::Bound(bound) = &mut state.binding else {
                    return Verdict::Inert(Rejection::NameUnbound);
                };
                if bound.owner != record.author {
                    return Verdict::Inert(Rejection::OwnerChanged);
                }
                bound.target = Target::Publication(record.target);
                bound.last_txid = observation.txid;
            }
        }
        self.set_name(record.name.clone(), state);
        Verdict::Applied
    }

    fn vote(&mut self, observation: &Observation, op: &NameOp, suspend: bool) -> Verdict {
        if let Admission::Rejected(rejection) = self.admit_approver(observation, op.registry) {
            return Verdict::Invalid(rejection);
        }
        let mut state = state_of(&self.names, &op.name);
        if state.suspended == suspend {
            return Verdict::Inert(Rejection::WrongPhase);
        }
        let votes = if suspend {
            &mut state.suspend_votes
        } else {
            &mut state.restore_votes
        };
        if !votes.insert(observation.author) {
            return Verdict::Inert(Rejection::Repeated);
        }
        if votes.len() >= usize::from(self.rules.threshold) {
            state.suspended = suspend;
            state.suspend_votes.clear();
            state.restore_votes.clear();
        }
        self.set_name(op.name.clone(), state);
        Verdict::Applied
    }

    fn claims(&mut self, observations: &[Observation], outcomes: &mut Vec<Outcome>) {
        let mut candidates: BTreeMap<Name, Vec<usize>> = BTreeMap::new();
        for (index, observation) in observations.iter().enumerate() {
            let Payload::Claim(op) = &observation.payload else {
                continue;
            };
            if let Admission::Rejected(rejection) = self.admit(observation, op.registry) {
                outcomes.push(Outcome::new(observation, Verdict::Invalid(rejection)));
                continue;
            }
            match state_of(&self.names, &op.name).binding {
                Binding::Bound(..) => {
                    outcomes.push(Outcome::new(
                        observation,
                        Verdict::Inert(Rejection::NameBound),
                    ));
                    continue;
                }
                Binding::Unbound => {}
            }
            let Some(list) = candidates.get_mut(&op.name) else {
                candidates.insert(op.name.clone(), vec![index]);
                continue;
            };
            list.push(index);
        }
        for (name, indices) in candidates {
            self.assign(name, &indices, observations, outcomes);
        }
    }

    fn assign(
        &mut self,
        name: Name,
        indices: &[usize],
        observations: &[Observation],
        outcomes: &mut Vec<Outcome>,
    ) {
        let Some(winner) = indices
            .iter()
            .copied()
            .min_by_key(|index| commit_key(&observations[*index]))
        else {
            return;
        };
        let observation = &observations[winner];
        let Payload::Claim(op) = &observation.payload else {
            return;
        };
        let Some(expiry) = self.expiry_after(observation.height) else {
            outcomes.push(Outcome::new(
                observation,
                Verdict::Invalid(Rejection::Overflow),
            ));
            return;
        };
        let mut state = state_of(&self.names, &name);
        state.binding = Binding::Bound(Bound {
            owner: observation.author,
            target: target_of(op),
            expiry,
            claim_txid: observation.txid,
            last_txid: observation.txid,
        });
        self.set_name(name, state);
        for index in indices {
            let verdict = if *index == winner {
                Verdict::Applied
            } else {
                Verdict::Inert(Rejection::LostRace)
            };
            outcomes.push(Outcome::new(&observations[*index], verdict));
        }
    }

    fn owner_records(&mut self, observations: &[Observation], outcomes: &mut Vec<Outcome>) {
        for observation in observations {
            let verdict = match &observation.payload {
                Payload::Claim(op) => match self.rules.mode {
                    Mode::Administered => self.request(observation, op),
                    Mode::Open => continue,
                },
                Payload::Update(op) => self.update(observation, op),
                Payload::Renew(op) => self.renew(observation, op),
                Payload::Genesis(..) => Verdict::Invalid(Rejection::ForeignRegistry),
                Payload::Approve(..) | Payload::Suspend(..) | Payload::Restore(..) => continue,
            };
            outcomes.push(Outcome::new(observation, verdict));
        }
    }

    fn insert_pending(&mut self, observation: &Observation, kind: PendingKind, op: &OwnerOp) {
        self.remember_pending(&observation.txid);
        self.pending.insert(
            observation.txid,
            PendingRecord {
                kind,
                name: op.name.clone(),
                author: observation.author,
                target: op.target,
                sha256: observation.record_sha256,
                height: observation.height,
                approvals: BTreeSet::new(),
                completed: false,
            },
        );
    }

    fn request(&mut self, observation: &Observation, op: &OwnerOp) -> Verdict {
        if let Admission::Rejected(rejection) = self.admit(observation, op.registry) {
            return Verdict::Invalid(rejection);
        }
        if op.is_reserving() {
            return Verdict::Invalid(Rejection::ZeroTarget);
        }
        self.insert_pending(observation, PendingKind::Request, op);
        Verdict::Pending
    }

    fn update(&mut self, observation: &Observation, op: &OwnerOp) -> Verdict {
        if let Admission::Rejected(rejection) = self.admit(observation, op.registry) {
            return Verdict::Invalid(rejection);
        }
        let mut state = state_of(&self.names, &op.name);
        let Binding::Bound(bound) = &mut state.binding else {
            return Verdict::Invalid(Rejection::NameUnbound);
        };
        if bound.owner != observation.author {
            return Verdict::Invalid(Rejection::NotOwner);
        }
        match self.rules.mode {
            Mode::Open => {
                bound.target = target_of(op);
                bound.last_txid = observation.txid;
                self.set_name(op.name.clone(), state);
                Verdict::Applied
            }
            Mode::Administered => {
                if op.is_reserving() {
                    return Verdict::Invalid(Rejection::ZeroTarget);
                }
                self.insert_pending(observation, PendingKind::Update, op);
                Verdict::Pending
            }
        }
    }

    fn renew(&mut self, observation: &Observation, op: &OwnerOp) -> Verdict {
        if let Admission::Rejected(rejection) = self.admit(observation, op.registry) {
            return Verdict::Invalid(rejection);
        }
        let Some(expiry) = self.expiry_after(observation.height) else {
            return Verdict::Invalid(Rejection::Overflow);
        };
        let mut state = state_of(&self.names, &op.name);
        let Binding::Bound(bound) = &mut state.binding else {
            return Verdict::Invalid(Rejection::NameUnbound);
        };
        if bound.owner != observation.author {
            return Verdict::Invalid(Rejection::NotOwner);
        }
        match self.rules.mode {
            Mode::Open => bound.target = target_of(op),
            Mode::Administered => {
                if bound.target != Target::Publication(op.target) {
                    return Verdict::Invalid(Rejection::TargetChanged);
                }
            }
        }
        bound.expiry = expiry;
        bound.last_txid = observation.txid;
        self.set_name(op.name.clone(), state);
        Verdict::Applied
    }
}
