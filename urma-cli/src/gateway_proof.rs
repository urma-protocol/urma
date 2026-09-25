use crate::{
    gateway_file::Serving,
    gateway_host::{Portal, Suffix},
    gateway_pages::IndexPoint,
};
use serde_json::{Map, Value, json};
use urma_web::store::StoredPublication;

pub(crate) struct RootEvidence<'a> {
    pub(crate) publication: &'a StoredPublication,
    pub(crate) commit_hex: String,
    pub(crate) reveal_hex: String,
}

pub(crate) fn evidence(portal: &Portal, resolver: Value, tip: &IndexPoint) -> Value {
    let mut registries = Map::new();
    for suffix in Suffix::ALL {
        let genesis = portal.registries().get(&suffix).map(ToString::to_string);
        registries.insert(suffix.label().to_owned(), json!(genesis));
    }
    json!({
        "format": "URMA-PORTAL-PROOF-1",
        "portal": {
            "domain": portal.authority(),
            "transform": Serving::TRANSFORM,
            "registries": registries,
        },
        "resolver": resolver,
        "chain_tip": {"height": tip.height, "block_hash": tip.block_hash},
    })
}

pub(crate) fn with_root(mut proof: Value, root: RootEvidence<'_>) -> Value {
    let publication = root.publication;
    proof["root"] = json!({
        "txid": publication.root,
        "commit_hex": root.commit_hex,
        "reveal_hex": root.reveal_hex,
        "author": publication.author,
        "payload_sha256": publication.payload_sha256,
        "payload_length": publication.payload_length,
        "fetched_at": {"height": publication.tip_height, "block_hash": publication.tip_hash},
    });
    proof["declared"] = json!({
        "entry": publication.entry,
        "files": publication.files,
        "pinned": publication.pinned,
    });
    proof
}
