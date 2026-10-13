//! Read-only, optional local-operator Wire projection. One complete snapshot is
//! traversed into an in-memory index; failure discards it before local fallback.
use crate::config::ArchiveSettings;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_node_client::{Client, model::ArchiveStatus, projection::WireCursor};
use urma_runtime::error::{Error, ensure};
use urma_wire::index::Index;

const MAX_ROWS: usize = 50_000;
const MAX_PAGES: usize = 1024;
const TRAVERSAL_TIME: Duration = Duration::from_secs(30);
const PAGE: u32 = 128;
const TRUST: &str = "local operator projection; not portable chain or ownership evidence";

fn refused() -> Error {
    // Do not propagate server-controlled bodies or reflected credentials.
    Error::Invalid("optional Wire archive view unavailable".into())
}

/// Provenance of a Wire or Names answer read from the operator's archive.
pub(crate) fn operator_source(archive: &ArchiveStatus) -> Value {
    json!({"kind":"local-node-operator","indexed_through":archive.indexed_through,
        "peer_synced_through":archive.peer_synced_through,"generation":archive.generation,
        "trust":TRUST})
}

pub(crate) fn autonomous_source() -> Value {
    json!({"kind":"autonomous-local"})
}

pub(crate) fn client(settings: &ArchiveSettings) -> Result<Client, Error> {
    if !std::fs::symlink_metadata(&settings.token_file)?.is_file() {
        return Err(refused());
    }
    let bytes = urma_io::read_private(&settings.token_file, 256)?;
    let token = std::str::from_utf8(&bytes).map_err(|_| refused())?.trim();
    Client::new(settings.endpoint, token.to_owned()).map_err(|_| refused())
}

/// Full snapshot only, in selected height/position order. Time checks are
/// cooperative; an in-flight HTTP call keeps the client's own budget.
pub(crate) fn read(
    settings: &ArchiveSettings,
    expected: Option<Chain>,
) -> Result<(Index, Value), Error> {
    let deadline = Instant::now() + TRAVERSAL_TIME;
    let client = client(settings)?;
    let mut cursor: Option<WireCursor> = None;
    let mut first: Option<(String, ArchiveStatus)> = None;
    let mut entries = Vec::new();
    for _ in 0..MAX_PAGES {
        ensure!(
            Instant::now() < deadline,
            "optional Wire archive deadline passed"
        );
        let page = client
            .wire_page(cursor.as_ref(), PAGE)
            .map_err(|_| refused())?;
        for chain in expected.iter() {
            ensure!(
                page.archive.chain_genesis == chain.genesis()?.0,
                "operator archive belongs to another network"
            );
        }
        let added = entries.len().checked_add(page.records.len());
        ensure!(
            added.is_some_and(|rows| rows <= MAX_ROWS),
            "optional Wire archive row bound"
        );
        let snapshot = serde_json::to_string(&page.snapshot)?;
        match &first {
            Some((previous, _)) if *previous != snapshot => return Err(refused()),
            Some(_) => {}
            None => first = Some((snapshot, page.archive.clone())),
        }
        entries.extend(page.records.into_iter().map(|record| record.entry));
        let Some(next) = page.next else {
            let Some((_, archive)) = first else {
                return Err(refused());
            };
            let index = Index {
                format: Index::FORMAT.into(),
                genesis: archive.chain_genesis.to_string(),
                start: archive.application_start.height,
                blocks: Vec::new(),
                entries,
            };
            return Ok((index, operator_source(&archive)));
        };
        cursor = Some(next);
    }
    Err(refused())
}
