use crate::{node::Presence, publish::PublishReport};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Mempool,
    Confirmed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum State {
    Prepared,
    Missing,
    Mempool,
    Confirmed,
    SourceUnavailable { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub txid: String,
    pub role: String,
    pub state: State,
}

#[derive(Clone, Serialize)]
pub struct Progress {
    pub report: PublishReport,
    pub total: usize,
    pub observations: Vec<Observation>,
    pub retryable: bool,
}

impl Progress {
    pub fn reached(&self, target: Target) -> bool {
        self.observations.len() == self.total
            && self.observations.iter().all(|observation| match target {
                Target::Confirmed => observation.state == State::Confirmed,
                Target::Mempool => matches!(observation.state, State::Mempool | State::Confirmed),
            })
    }

    pub fn summary(&self) -> String {
        let count = |state: State| {
            self.observations
                .iter()
                .filter(|row| row.state == state)
                .count()
        };
        let unavailable = self
            .observations
            .iter()
            .filter(|row| matches!(row.state, State::SourceUnavailable { .. }))
            .count();
        format!(
            "{}/{} checked: {} confirmed, {} mempool, {} prepared/not submitted, {} missing, {} source unavailable",
            self.observations.len(),
            self.total,
            count(State::Confirmed),
            count(State::Mempool),
            count(State::Prepared),
            count(State::Missing),
            unavailable
        )
    }
}

pub(crate) fn state(presence: &Presence, attempted: bool) -> State {
    match presence {
        Presence::Confirmed { .. } => State::Confirmed,
        Presence::Mempool => State::Mempool,
        Presence::Missing if attempted => State::Missing,
        Presence::Missing => State::Prepared,
    }
}
