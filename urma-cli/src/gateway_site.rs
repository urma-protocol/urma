use crate::{
    gateway_file::{Declared, Provenance, Serving},
    gateway_host::{Host, Portal, SiteHost, authority, classify},
    gateway_http::{Refusal, Reply, Request, State},
    gateway_pages::{ListedName, Listing, ListingState, Subject, index_page, unavailable_page},
    gateway_proof::{RootEvidence, evidence, with_root},
    gateway_route::{Currency, Route, route, split_target},
    gateway_state::{Availability, Gateway, Network, Snapshot},
    names_cli::resolution,
    web_cli::web_error,
};
use bitcoin::{Txid, consensus::encode::serialize_hex};
use serde_json::Value;
use urma_names::state::{Resolution, Target};
use urma_web::{
    error::WebError,
    store::{Served, Verified},
};

struct WellKnown;

impl WellKnown {
    const PROOF: &'static str = "/.well-known/urma/proof";
    const ASK: &'static str = "/.well-known/urma/ask";
    const UNAVAILABLE: &'static str = "/unavailable";
}

struct Origin<'a> {
    network: &'a Network,
    root: Txid,
    verified: &'a Verified,
    provenance: Provenance,
}

pub(crate) fn respond(gateway: &Gateway, request: &Request) -> Reply {
    match handle(gateway, request) {
        Ok(reply) => {
            tracing::info!(target: "urma_gateway", status = reply.status, host = %request.host, target = %request.target, "request served");
            reply
        }
        Err(refusal) => {
            tracing::warn!(target: "urma_gateway", status = refusal.status(), state = refusal.state.label(), host = %request.host, target = %request.target, reason = %refusal.detail, "request refused");
            refusal.reply()
        }
    }
}

fn handle(gateway: &Gateway, request: &Request) -> Result<Reply, Refusal> {
    let host = authority(&request.host)
        .map_err(|cause| Refusal::new(State::BadRequest, cause.to_string()))?;
    let classified = classify(&host, &gateway.portal)
        .map_err(|cause| Refusal::new(State::NotAName, cause.to_string()))?;
    match classified {
        Host::Apex => apex(gateway, request),
        Host::Site(site) => site_reply(gateway, request, &site),
        Host::Foreign => Err(Refusal::new(
            State::Misdirected,
            format!(
                "{host} is neither {} nor a name host under it",
                gateway.portal.domain()
            ),
        )),
    }
}

fn parameters(query: &str, key: &str) -> Vec<String> {
    let mut values = Vec::new();
    let Some(pairs) = query.strip_prefix('?') else {
        return values;
    };
    for (name, value) in url::form_urlencoded::parse(pairs.as_bytes()) {
        if name == key {
            values.push(value.into_owned());
        }
    }
    values
}

fn apex(gateway: &Gateway, request: &Request) -> Result<Reply, Refusal> {
    let (path, query) = split_target(&request.target);
    match path {
        "/" => Ok(Reply::html(
            200,
            index_page(&gateway.portal, &listings(gateway)?),
        )),
        WellKnown::UNAVAILABLE => Ok(Reply::html(
            200,
            unavailable_page(&gateway.portal, &parameters(query, "u")),
        )),
        WellKnown::ASK => ask(gateway, query),
        other => Err(Refusal::new(
            State::NotAPortalPage,
            format!("{other} is not a portal page"),
        )),
    }
}

fn ask(gateway: &Gateway, query: &str) -> Result<Reply, Refusal> {
    let domains = parameters(query, "domain");
    let [domain] = domains.as_slice() else {
        return Err(Refusal::new(
            State::NotServable,
            "ask needs exactly one domain parameter".into(),
        ));
    };
    let denied = |cause: String| {
        Refusal::new(
            State::NotServable,
            format!("{domain:?} is not a servable name host: {cause}"),
        )
    };
    if domain.contains(':') || domain.len() > Portal::MAX_HOST_BYTES {
        return Err(denied("not a bare host name".into()));
    }
    let classified =
        classify(domain, &gateway.portal).map_err(|cause| denied(cause.to_string()))?;
    let Host::Site(site) = classified else {
        return Err(denied("not a name host of this portal".into()));
    };
    gateway
        .bound(&site)
        .map_err(|refusal| denied(refusal.detail))?;
    Ok(Reply::text(200, "ok\n"))
}

fn site_reply(gateway: &Gateway, request: &Request, site: &SiteHost) -> Result<Reply, Refusal> {
    let mut subject = Subject::new(site.name.to_string(), site.suffix.label());
    match name_reply(gateway, request, site, &mut subject) {
        Ok(reply) => Ok(reply),
        Err(refusal) => Err(refusal.about(subject)),
    }
}

fn name_reply(
    gateway: &Gateway,
    request: &Request,
    site: &SiteHost,
    subject: &mut Subject,
) -> Result<Reply, Refusal> {
    let network = gateway.network(site.suffix)?;
    subject.network = Some(network.name.clone());
    subject.registry = Some(network.genesis.to_string());
    let snapshot = gateway.snapshot(network)?;
    subject.index = Some(snapshot.point());
    if split_target(&request.target).0 == WellKnown::PROOF {
        return proof(gateway, site, network, &snapshot, subject);
    }
    let root = gateway.servable(site, network, &snapshot)?;
    let verified = gateway.publication(network, root)?;
    let origin = Origin {
        network,
        root,
        verified: &verified,
        provenance: provenance(subject, root, &verified),
    };
    serve_root(gateway, request, &origin)
}

fn provenance(subject: &Subject, root: Txid, verified: &Verified) -> Provenance {
    Provenance {
        subject: subject.clone(),
        root: root.to_string(),
        author: verified.author.clone(),
        payload_sha256: verified.payload_sha256.clone(),
    }
}

fn serve_root(gateway: &Gateway, request: &Request, origin: &Origin<'_>) -> Result<Reply, Refusal> {
    let path = split_target(&request.target).0;
    match route(&origin.verified.package, &request.target) {
        Route::Serve(declared) => file(gateway, request, origin, &declared),
        Route::Redirect(location) => Ok(origin
            .provenance
            .stamp(Reply::site(
                301,
                "text/html; charset=utf-8",
                gateway.settings.max_age,
                Vec::new(),
            ))
            .with("Location", location)),
        Route::Undeclared => Err(Refusal::new(
            State::Undeclared,
            format!("{path} is not in the declared set of {}", origin.root),
        )),
    }
}

fn store_refusal(what: &str, cause: WebError) -> Refusal {
    Refusal::new(
        State::VerificationFailed,
        format!(
            "{what} failed verification in the store: {}",
            web_error(cause)
        ),
    )
}

fn file(
    gateway: &Gateway,
    request: &Request,
    origin: &Origin<'_>,
    path: &str,
) -> Result<Reply, Refusal> {
    let served = match gateway.store.serve(origin.verified, &format!("/{path}")) {
        Ok(served) => served,
        Err(cause) => {
            gateway.refetch(origin.network, origin.root);
            return Err(store_refusal(path, cause));
        }
    };
    let Served::Resource {
        mime,
        sha256,
        bytes,
    } = served
    else {
        return Err(Refusal::new(
            State::Undeclared,
            format!("{path} is not in the declared set"),
        ));
    };
    let serving = Serving {
        portal: &gateway.portal,
        max_age: gateway.settings.max_age,
    };
    let declared = Declared {
        path: path.to_owned(),
        mime,
        sha256,
        bytes,
    };
    match serving.file(&origin.provenance, declared, request) {
        Ok(reply) => Ok(reply),
        Err(refusal) => {
            gateway.refetch(origin.network, origin.root);
            Err(refusal)
        }
    }
}

fn proof(
    gateway: &Gateway,
    site: &SiteHost,
    network: &Network,
    snapshot: &Snapshot,
    subject: &Subject,
) -> Result<Reply, Refusal> {
    let document = evidence(
        &gateway.portal,
        resolution(&snapshot.index, &site.name)?,
        &snapshot.tip_point(),
    );
    let root = match gateway.servable(site, network, snapshot) {
        Ok(root) => root,
        Err(refusal) => {
            tracing::warn!(target: "urma_gateway", state = refusal.state.label(), reason = %refusal.detail, "proof answered without root: the name is not servable");
            let mut reply = Reply::json(200, &document)?;
            for (name, value) in subject.headers() {
                reply = reply.with(name, value);
            }
            return Ok(reply);
        }
    };
    let verified = gateway.publication(network, root)?;
    let document = rooted(gateway, &verified, document)?;
    Ok(provenance(subject, root, &verified).stamp(Reply::json(200, &document)?))
}

fn rooted(gateway: &Gateway, verified: &Verified, document: Value) -> Result<Value, Refusal> {
    let publication = gateway
        .store
        .summary(verified)
        .map_err(|cause| store_refusal("publication summary", cause))?;
    let reveal = gateway
        .store
        .transaction(&publication.root)
        .map_err(|cause| store_refusal("root reveal", cause))?;
    let commit = gateway
        .store
        .transaction(&publication.commit)
        .map_err(|cause| store_refusal("root commit", cause))?;
    Ok(with_root(
        document,
        RootEvidence {
            publication: &publication,
            commit_hex: serialize_hex(&commit),
            reveal_hex: serialize_hex(&reveal),
        },
    ))
}

fn listings(gateway: &Gateway) -> Result<Vec<Listing>, Refusal> {
    let mut listings = Vec::new();
    for network in gateway.networks.values() {
        let state = match network.availability()? {
            Availability::Pending(reason) => ListingState::Pending(reason),
            Availability::Ready(snapshot) => listing_state(gateway, network, &snapshot),
        };
        listings.push(Listing {
            suffix: network.suffix.label(),
            network: network.name.clone(),
            registry: network.genesis.to_string(),
            state,
        });
    }
    Ok(listings)
}

fn listing_state(gateway: &Gateway, network: &Network, snapshot: &Snapshot) -> ListingState {
    match gateway.currency(snapshot) {
        Currency::Current => ListingState::Ready {
            index: snapshot.point(),
            tip: snapshot.tip,
            names: bound_names(&gateway.portal, network, snapshot),
        },
        Currency::Behind(reason) => ListingState::Behind {
            index: snapshot.point(),
            tip: snapshot.tip,
            reason,
        },
    }
}

fn bound_names(portal: &Portal, network: &Network, snapshot: &Snapshot) -> Vec<ListedName> {
    let mut names = Vec::new();
    for name in snapshot.index.registry.names().keys() {
        let Resolution::Bound(bound) = snapshot.index.registry.resolve(name) else {
            continue;
        };
        let Target::Publication(root) = bound.target else {
            continue;
        };
        if bound.expiry <= snapshot.tip {
            continue;
        }
        names.push(ListedName {
            name: name.to_string(),
            url: format!("{}/", portal.site_origin(name, network.suffix)),
            root: root.to_string(),
            expiry: bound.expiry,
        });
    }
    names
}
