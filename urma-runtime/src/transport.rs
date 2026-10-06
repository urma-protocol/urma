use crate::config;
use crate::error::{Error, ensure};
use crate::remote::validate_result;
use serde_json::Value;
use std::{
    num::Saturating,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Evidence {
    LocalValidatingNode,
    LightClientInclusion,
    PublicProviderObservation,
}

impl Evidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalValidatingNode => "local_validating_node",
            Self::LightClientInclusion => "light_client_inclusion",
            Self::PublicProviderObservation => "public_provider_observation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockEncoding {
    Core,
    Esplora,
}

pub trait Provider: Send + Sync {
    fn label(&self) -> String;
    fn evidence(&self) -> Evidence;
    fn block_encoding(&self) -> BlockEncoding;
    fn supports(&self, method: &str) -> bool;
    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error>;
}

pub struct Answer {
    pub value: Value,
    pub label: String,
    pub encoding: BlockEncoding,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Standing {
    pub label: String,
    pub evidence: Evidence,
    pub failures: u32,
    pub blocked_for: Duration,
}

enum Outcome {
    Answered(Answer),
    Absent(String),
    Failed(String),
}

pub struct Router {
    slots: Vec<Slot>,
    race_tip: bool,
}

struct Slot {
    provider: Box<dyn Provider>,
    health: Mutex<Health>,
}

#[derive(Clone, Copy)]
struct Health {
    failures: Saturating<u32>,
    blocked_until: Instant,
}

impl Slot {
    fn health(&self) -> Health {
        match self.health.lock() {
            Ok(health) => *health,
            Err(poisoned) => {
                tracing::error!(provider = %self.provider.label(), "provider health lock poisoned");
                *poisoned.into_inner()
            }
        }
    }

    fn update(&self, change: impl FnOnce(&mut Health)) {
        match self.health.lock() {
            Ok(mut health) => change(&mut health),
            Err(poisoned) => {
                tracing::error!(provider = %self.provider.label(), "provider health lock poisoned");
                change(&mut poisoned.into_inner())
            }
        }
    }

    fn succeeded(&self, now: Instant) {
        self.update(|health| {
            health.failures = Saturating(0);
            health.blocked_until = now;
        });
    }

    fn failed(&self, now: Instant) {
        self.update(|health| {
            health.failures += Saturating(1);
            if health.failures.0 >= config::PROVIDER_BREAKER_FAILURES {
                health.blocked_until = now + config::PROVIDER_BREAKER_WINDOW;
                tracing::warn!(provider = %self.provider.label(), failures = health.failures.0, "provider circuit opened");
            }
        });
    }

    fn cooled(&self, now: Instant, wait: Duration) {
        self.update(|health| {
            health.blocked_until = now + wait.min(config::PROVIDER_RETRY_MAX);
        });
    }
}

impl Router {
    pub fn new(providers: Vec<Box<dyn Provider>>) -> Result<Self, Error> {
        ensure!(
            !providers.is_empty() && providers.len() <= config::MAX_PROVIDERS,
            "public transport requires between one and {} providers",
            config::MAX_PROVIDERS
        );
        let now = Instant::now();
        let mut slots = Vec::new();
        for provider in providers {
            slots.push(Slot {
                provider,
                health: Mutex::new(Health {
                    failures: Saturating(0),
                    blocked_until: now,
                }),
            });
        }
        Ok(Self {
            slots,
            race_tip: false,
        })
    }

    pub fn race_tip(mut self, enabled: bool) -> Self {
        self.race_tip = enabled;
        self
    }

    pub fn evidence(&self) -> Evidence {
        let mut weakest = Evidence::LightClientInclusion;
        for slot in &self.slots {
            weakest = weakest.max(slot.provider.evidence());
        }
        weakest
    }

    pub fn labels(&self) -> Vec<String> {
        self.slots
            .iter()
            .map(|slot| slot.provider.label())
            .collect()
    }

    pub fn standings(&self) -> Vec<Standing> {
        let now = Instant::now();
        self.slots
            .iter()
            .map(|slot| {
                let health = slot.health();
                Standing {
                    label: slot.provider.label(),
                    evidence: slot.provider.evidence(),
                    failures: health.failures.0,
                    blocked_for: if health.blocked_until > now {
                        health.blocked_until - now
                    } else {
                        Duration::ZERO
                    },
                }
            })
            .collect()
    }

    pub fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        Ok(self.answer(chain, method, args)?.value)
    }

    pub fn answer(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Answer, Error> {
        ensure!(
            config::PUBLIC_METHODS.contains(&method),
            "public transport supports chain reads and signed transaction submission only"
        );
        let candidates = self.candidates(method, Instant::now());
        ensure!(
            !candidates.is_empty(),
            "{method} on {chain:?}: no public provider is available for this method right now; retry shortly or configure a local node"
        );
        if self.race_tip && method == "getblockchaininfo" && candidates.len() > 1 {
            let width = candidates.len().min(config::TIP_RACE_WIDTH);
            return self.race(chain, &candidates[..width], method, args);
        }
        let mut failures = Vec::new();
        let mut absent = 0;
        for index in &candidates {
            match self.attempt(&self.slots[*index], chain, method, args) {
                Outcome::Answered(answer) => return Ok(answer),
                Outcome::Absent(message) => {
                    absent += 1;
                    failures.push(message);
                }
                Outcome::Failed(message) => failures.push(message),
            }
        }
        let message = format!(
            "{method} on {chain:?}: {}. Retry or configure a local node; check --testnet for test data.",
            failures.join("; ")
        );
        if absent > 0 {
            if absent < candidates.len() {
                tracing::warn!(
                    method,
                    absent,
                    failed = candidates.len() - absent,
                    %message,
                    "record absent from every provider that answered; other providers failed"
                );
            }
            return Err(Error::Missing(message));
        }
        Err(Error::Unsupported(message))
    }

    fn candidates(&self, method: &str, now: Instant) -> Vec<usize> {
        let mut ranked = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if !slot.provider.supports(method) {
                continue;
            }
            let health = slot.health();
            if health.blocked_until > now {
                continue;
            }
            ranked.push((slot.provider.evidence(), health.failures.0, index));
        }
        ranked.sort();
        let mut order = Vec::new();
        for (evidence, failures, index) in ranked {
            tracing::debug!(?evidence, failures, index, method, "provider candidate");
            order.push(index);
        }
        order
    }

    fn attempt(&self, slot: &Slot, chain: Chain, method: &str, args: &[Value]) -> Outcome {
        let label = slot.provider.label();
        let encoding = slot.provider.block_encoding();
        let evidence = slot.provider.evidence();
        let result = slot
            .provider
            .call(chain, method, args)
            .and_then(|value| validate_result(encoding, chain, method, args, value));
        match result {
            Ok(value) => {
                slot.succeeded(Instant::now());
                Outcome::Answered(Answer {
                    value,
                    label,
                    encoding,
                    evidence,
                })
            }
            Err(Error::Missing(message)) if absent_record(&message) => {
                slot.succeeded(Instant::now());
                tracing::warn!(provider = %label, %message, "record absent from one provider");
                Outcome::Absent(message)
            }
            Err(Error::RateLimited(wait)) => {
                slot.cooled(Instant::now(), wait);
                tracing::warn!(provider = %label, seconds = wait.as_secs(), "provider rate limited");
                Outcome::Failed(Error::RateLimited(wait).to_string())
            }
            Err(error) => {
                slot.failed(Instant::now());
                tracing::warn!(provider = %label, %error, "public provider unavailable");
                Outcome::Failed(error.to_string())
            }
        }
    }

    fn race(
        &self,
        chain: Chain,
        indices: &[usize],
        method: &str,
        args: &[Value],
    ) -> Result<Answer, Error> {
        let (sender, receiver) = mpsc::sync_channel(indices.len());
        std::thread::scope(|scope| {
            for index in indices {
                let sender = sender.clone();
                let slot = &self.slots[*index];
                scope.spawn(move || match sender.send(self.attempt(slot, chain, method, args)) {
                    Ok(()) => (),
                    Err(error) => {
                        tracing::warn!(%error, "tip race answer completed after another provider won")
                    }
                });
            }
            drop(sender);
            let mut failures = Vec::new();
            for outcome in receiver {
                match outcome {
                    Outcome::Answered(answer) => return Ok(answer),
                    Outcome::Absent(message) | Outcome::Failed(message) => failures.push(message),
                }
            }
            Err(Error::Unsupported(format!(
                "{method} on {chain:?}: {}",
                failures.join("; ")
            )))
        })
    }
}

fn absent_record(message: &str) -> bool {
    message == config::ABSENT_TRANSACTION || message == config::ABSENT_RECORD
}
