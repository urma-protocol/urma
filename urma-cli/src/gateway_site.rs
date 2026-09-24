use crate::{
    gateway_host::{Host, Portal, SiteHost, authority, classify},
    gateway_http::{Refusal, Reply, Request},
    gateway_links::{Transformed, transform},
    gateway_pages::{ListedName, Listing, ListingState, index_page, unavailable_page},
    gateway_route::{Route, route, split_target},
    gateway_state::{Availability, Binding, Gateway, Network, Snapshot},
    web_cli::web_error,
};
use bitcoin::consensus::encode::serialize_hex;
use serde_json::json;
use sha2::{Digest, Sha256};
use urma_names::state::{Resolution, Target};
use urma_web::{
    error::WebError,
    grammar::is_entry_mime,
    store::{Served, Verified},
};

struct WellKnown;

impl WellKnown {
    const PROOF: &'static str = "/.well-known/urma/proof";
    const ASK: &'static str = "/.well-known/urma/ask";
    const UNAVAILABLE: &'static str = "/unavailable";
}

struct Origin<'a> {
    site: &'a SiteHost,
    network: &'a Network,
    binding: &'a Binding,
    verified: &'a Verified,
}

impl Origin<'_> {
    fn stamp(&self, reply: Reply) -> Reply {
        reply
            .with("URMA-Network", self.network.name.clone())
            .with("URMA-Registry", self.network.genesis.to_string())
            .with("URMA-Name", self.site.name.to_string())
            .with("URMA-Root", self.binding.root.to_string())
            .with("URMA-Author", self.verified.author.clone())
            .with("URMA-Payload-SHA256", self.verified.payload_sha256.clone())
    }
}

enum Body {
    Original(Vec<u8>),
    Rewritten(Vec<u8>),
}

pub(crate) fn respond(gateway: &Gateway, request: &Request) -> Reply {
    match handle(gateway, request) {
        Ok(reply) => {
            tracing::info!(target: "urma_gateway", status = reply.status, host = %request.host, target = %request.target, "request served");
            reply
        }
        Err(refusal) => {
            tracing::warn!(target: "urma_gateway", status = refusal.status, host = %request.host, target = %request.target, reason = %refusal.detail, "request refused");
            refusal.reply()
        }
    }
}

fn handle(gateway: &Gateway, request: &Request) -> Result<Reply, Refusal> {
    let host = authority(&request.host)
        .map_err(|cause| Refusal::new(400, "Bad Request", cause.to_string()))?;
    let classified = classify(&host, &gateway.portal)
        .map_err(|cause| Refusal::new(404, "Not Found", cause.to_string()))?;
    match classified {
        Host::Apex => apex(gateway, request),
        Host::Site(site) => site_reply(gateway, request, &site),
        Host::Foreign => Err(Refusal::new(
            421,
            "Misdirected Request",
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
            404,
            "Not Found",
            format!("{other} is not a portal page"),
        )),
    }
}

fn ask(gateway: &Gateway, query: &str) -> Result<Reply, Refusal> {
    let domains = parameters(query, "domain");
    let [domain] = domains.as_slice() else {
        return Err(Refusal::new(
            404,
            "Not Found",
            "ask needs exactly one domain parameter".into(),
        ));
    };
    let denied = |cause: String| {
        Refusal::new(
            404,
            "Not Found",
            format!("no certificate for {domain:?}: {cause}"),
        )
    };
    if domain.contains(':') || domain.len() > Portal::MAX_HOST_BYTES {
        return Err(denied("not a bare host name".into()));
    }
    let classified = classify(&domain.to_ascii_lowercase(), &gateway.portal)
        .map_err(|cause| denied(cause.to_string()))?;
    let Host::Site(site) = classified else {
        return Err(denied("not a name host of this portal".into()));
    };
    gateway
        .bound(&site)
        .map_err(|refusal| denied(refusal.detail))?;
    Ok(Reply::text(200, "ok\n"))
}

fn site_reply(gateway: &Gateway, request: &Request, site: &SiteHost) -> Result<Reply, Refusal> {
    let network = gateway.network(site.suffix)?;
    let binding = gateway.bound(site)?;
    let verified = gateway.publication(network, binding.root)?;
    let origin = Origin {
        site,
        network,
        binding: &binding,
        verified: &verified,
    };
    let path = split_target(&request.target).0;
    if path == WellKnown::PROOF {
        return proof(gateway, &origin);
    }
    match route(&verified.package, &request.target) {
        Route::Serve(declared) => file(gateway, request, &origin, &declared),
        Route::Redirect(location) => Ok(origin.stamp(
            Reply::new(
                301,
                "text/html; charset=utf-8",
                &format!("public, max-age={}", gateway.settings.max_age),
                Vec::new(),
            )
            .with("Location", location),
        )),
        Route::Undeclared => Err(Refusal::new(
            404,
            "Not Found",
            format!("{path} is not in the declared set of {}", binding.root),
        )),
    }
}

fn store_refusal(what: &str, cause: WebError) -> Refusal {
    Refusal::new(
        502,
        "Bad Gateway",
        format!(
            "{what} failed verification in the store: {}",
            web_error(cause)
        ),
    )
}

fn links(gateway: &Gateway, mime: &str, bytes: Vec<u8>) -> Body {
    if !is_entry_mime(mime) {
        return Body::Original(bytes);
    }
    match transform(&bytes, &gateway.portal, gateway.settings.html_memory) {
        Ok(Transformed::Rewritten(rewritten)) => Body::Rewritten(rewritten),
        Ok(Transformed::Unchanged) => Body::Original(bytes),
        Err(cause) => {
            tracing::warn!(target: "urma_gateway", error = %cause, "links-v1 transform failed; serving the verified original bytes");
            Body::Original(bytes)
        }
    }
}

fn file(
    gateway: &Gateway,
    request: &Request,
    origin: &Origin<'_>,
    path: &str,
) -> Result<Reply, Refusal> {
    let served = gateway
        .store
        .serve(origin.verified, path)
        .map_err(|cause| store_refusal(path, cause))?;
    let Served::Resource {
        mime,
        sha256,
        bytes,
    } = served
    else {
        return Err(Refusal::new(
            404,
            "Not Found",
            format!("{path} is not in the declared set"),
        ));
    };
    if hex::encode(Sha256::digest(&bytes)) != sha256 {
        return Err(Refusal::new(
            502,
            "Bad Gateway",
            format!("{path}: bytes differ from the declared SHA-256"),
        ));
    }
    let cache = format!("public, max-age={}", gateway.settings.max_age);
    let (reply, digest) = match links(gateway, &mime, bytes) {
        Body::Original(body) => (Reply::new(200, &mime, &cache, body), sha256),
        Body::Rewritten(body) => {
            let digest = hex::encode(Sha256::digest(&body));
            let reply = Reply::new(200, &mime, &cache, body)
                .with("URMA-Transform", "links-v1".into())
                .with("URMA-Original-SHA256", sha256);
            (reply, digest)
        }
    };
    let etag = format!("\"{digest}\"");
    let reply = origin
        .stamp(reply)
        .with("URMA-SHA256", digest)
        .with("ETag", etag.clone());
    if request.validates(&etag) {
        return Ok(reply.not_modified());
    }
    Ok(reply)
}

fn proof(gateway: &Gateway, origin: &Origin<'_>) -> Result<Reply, Refusal> {
    let summary = gateway
        .store
        .summary(origin.verified)
        .map_err(|cause| store_refusal("publication summary", cause))?;
    let reveal = gateway
        .store
        .transaction(&summary.root)
        .map_err(|cause| store_refusal("root reveal", cause))?;
    let commit = gateway
        .store
        .transaction(&summary.commit)
        .map_err(|cause| store_refusal("root commit", cause))?;
    let bound = &origin.binding.bound;
    let snapshot = &origin.binding.snapshot;
    let value = json!({
        "format": "URMA-PORTAL-PROOF-1",
        "portal": gateway.portal.domain(),
        "network": origin.network.name,
        "suffix": origin.site.suffix.label(),
        "registry": origin.network.genesis.to_string(),
        "name": origin.site.name.as_str(),
        "resolution": {
            "status": "bound",
            "height": snapshot.index.registry.height(),
            "block_hash": snapshot.index.tip_hash(),
            "chain_tip": snapshot.tip,
            "synced_at": snapshot.synced,
            "owner": bound.owner.to_string(),
            "target": origin.binding.root.to_string(),
            "claim_txid": bound.claim_txid.to_string(),
            "last_txid": bound.last_txid.to_string(),
            "expiry": bound.expiry,
        },
        "publication": {
            "root": summary.root,
            "commit": summary.commit,
            "author": summary.author,
            "label": summary.label,
            "entry": summary.entry,
            "payload_sha256": summary.payload_sha256,
            "payload_length": summary.payload_length,
            "root_reveal_hex": serialize_hex(&reveal),
            "root_commit_hex": serialize_hex(&commit),
            "files": summary.files,
            "pinned": summary.pinned,
        },
        "serving": {
            "transform": "links-v1",
            "rule": "only text/html responses may have urma:// navigation links rewritten; such responses carry URMA-Transform and URMA-Original-SHA256 (declared bytes), and URMA-SHA256 always names the bytes served",
        },
    });
    Ok(origin.stamp(Reply::json(200, &value)?))
}

fn listings(gateway: &Gateway) -> Result<Vec<Listing>, Refusal> {
    let mut listings = Vec::new();
    for network in gateway.networks.values() {
        let state = match network.availability()? {
            Availability::Pending(reason) => ListingState::Pending(reason),
            Availability::Ready(snapshot) => ListingState::Ready {
                height: snapshot.index.registry.height(),
                tip: snapshot.tip,
                block_hash: snapshot.index.tip_hash(),
                names: bound_names(&gateway.portal, network, &snapshot),
            },
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
