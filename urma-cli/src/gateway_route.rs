use crate::gateway_http::Refusal;
use bitcoin::Txid;
use urma_names::state::{Bound, Resolution, Target};
use urma_web::package::{Package, Resource};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Serve(String),
    Redirect(String),
    Undeclared,
}

pub(crate) fn split_target(target: &str) -> (&str, &str) {
    for (at, byte) in target.bytes().enumerate() {
        if byte == b'?' || byte == b'#' {
            return target.split_at(at);
        }
    }
    (target, "")
}

fn declared(package: &Package, path: &str) -> bool {
    match package.resolve(path) {
        Resource::File(..) | Resource::Pinned(..) => true,
        Resource::Undeclared => false,
    }
}

pub(crate) fn route(package: &Package, target: &str) -> Route {
    let (path, query) = split_target(target);
    if declared(package, path) {
        return Route::Serve(path.to_owned());
    }
    if path.is_empty() || path.ends_with('/') {
        return Route::Undeclared;
    }
    let directory = format!("{path}/");
    if declared(package, &directory) {
        return Route::Redirect(format!("{directory}{query}"));
    }
    Route::Undeclared
}

pub(crate) fn standing(
    host: &str,
    registry: Txid,
    resolution: Resolution,
    tip: u64,
) -> Result<(Bound, Txid), Refusal> {
    let bound = match resolution {
        Resolution::Unbound => {
            return Err(Refusal::new(
                404,
                "Not Found",
                format!("{host} is not bound in registry {registry}"),
            ));
        }
        Resolution::Suspended => {
            return Err(Refusal::new(
                451,
                "Unavailable For Legal Reasons",
                format!("{host} is suspended by the approvers of registry {registry}"),
            ));
        }
        Resolution::Bound(bound) => bound,
    };
    let Target::Publication(root) = bound.target else {
        return Err(Refusal::new(
            404,
            "Not Found",
            format!("{host} is reserved in registry {registry} and names no publication"),
        ));
    };
    if bound.expiry <= tip {
        return Err(Refusal::new(
            410,
            "Gone",
            format!(
                "{host} expired at block {} (chain tip {tip}) in registry {registry}",
                bound.expiry
            ),
        ));
    }
    Ok((bound, root))
}
