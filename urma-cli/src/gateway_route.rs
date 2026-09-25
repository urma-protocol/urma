use crate::gateway_http::{Refusal, State};
use bitcoin::Txid;
use std::time::{Duration, Instant};
use urma_names::state::{Resolution, Target};
use urma_web::package::{Package, Resource};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Serve(String),
    Redirect(String),
    Undeclared,
}

impl Route {
    pub(crate) const RESERVED: &'static str = "/.well-known/urma/";
}

pub(crate) fn split_target(target: &str) -> (&str, &str) {
    for (at, byte) in target.bytes().enumerate() {
        if byte == b'?' || byte == b'#' {
            return target.split_at(at);
        }
    }
    (target, "")
}

enum Lookup {
    Declared(String),
    Absent,
}

fn lookup(package: &Package, path: &str) -> Lookup {
    if path.starts_with(Route::RESERVED) {
        return Lookup::Absent;
    }
    match package.resolve(path) {
        Resource::File(file) => Lookup::Declared(file.path.clone()),
        Resource::Pinned(pin) => Lookup::Declared(pin.path.clone()),
        Resource::Undeclared => Lookup::Absent,
    }
}

pub(crate) fn route(package: &Package, target: &str) -> Route {
    let (path, query) = split_target(target);
    match lookup(package, path) {
        Lookup::Declared(declared) => return Route::Serve(declared),
        Lookup::Absent => {}
    }
    if path.is_empty() || path.ends_with('/') {
        return Route::Undeclared;
    }
    let directory = format!("{path}/");
    match lookup(package, &directory) {
        Lookup::Declared(..) => Route::Redirect(format!("{directory}{query}")),
        Lookup::Absent => Route::Undeclared,
    }
}

pub(crate) fn standing(
    host: &str,
    registry: Txid,
    resolution: Resolution,
    tip: u64,
) -> Result<Txid, Refusal> {
    let bound = match resolution {
        Resolution::Unbound => {
            return Err(Refusal::new(
                State::Unbound,
                format!("{host} is not bound in registry {registry}"),
            ));
        }
        Resolution::Suspended => {
            return Err(Refusal::new(
                State::Suspended,
                format!("{host} is suspended by the approvers of registry {registry}"),
            ));
        }
        Resolution::Bound(bound) => bound,
    };
    let Target::Publication(root) = bound.target else {
        return Err(Refusal::new(
            State::Reserved,
            format!("{host} is reserved in registry {registry} and names no publication"),
        ));
    };
    if bound.expiry <= tip {
        return Err(Refusal::new(
            State::Expired,
            format!(
                "{host} expired at block {} (chain tip {tip}) in registry {registry}",
                bound.expiry
            ),
        ));
    }
    Ok(root)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Freshness {
    pub(crate) max_lag: u64,
    pub(crate) max_age: Duration,
    pub(crate) retry: Duration,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Scan {
    Never,
    At(Instant),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Currency {
    Current,
    Behind(String),
}

impl Freshness {
    pub(crate) fn judge(&self, height: u64, tip: u64, scan: Scan, now: Instant) -> Currency {
        let Scan::At(scanned) = scan else {
            return Currency::Behind("no rescan has succeeded since the portal started".into());
        };
        let age = now.duration_since(scanned);
        if age >= self.max_age {
            return Currency::Behind(format!(
                "the last successful rescan was {} s ago; the bound is {} s",
                age.as_secs(),
                self.max_age.as_secs()
            ));
        }
        if tip > height && tip - height > self.max_lag {
            return Currency::Behind(format!(
                "the index is at height {height}, {} blocks behind the chain tip {tip}; the bound is {}",
                tip - height,
                self.max_lag
            ));
        }
        Currency::Current
    }

    pub(crate) fn refusal(&self, network: &str, reason: &str) -> Refusal {
        Refusal::new(
            State::IndexBehind,
            format!("the {network} names index is not current: {reason}"),
        )
        .with("Retry-After", self.retry.as_secs().to_string())
    }
}
