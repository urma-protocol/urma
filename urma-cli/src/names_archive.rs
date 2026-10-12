//! Read-only, optional local-operator Names projection. No scanner state is
//! synthesized; failure discards the attempted traversal before local fallback.
use crate::config::ArchiveSettings;
use bitcoin::Txid;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_names::{
    name::Name,
    state::{Binding, NameState, PendingRecord, Resolution},
};
use urma_node_client::{
    Client,
    names::{NamesEntry, NamesStatus},
};
use urma_runtime::error::{Error, ensure};

const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAGES: usize = 1024;
const TRAVERSAL_TIME: Duration = Duration::from_secs(30);

pub(crate) struct View {
    status: NamesStatus,
    names: BTreeMap<Name, NameState>,
    // Preserve legacy output order, distinct from displayed-hex wire ordering.
    pending: BTreeMap<Txid, PendingRecord>,
}

fn refused() -> Error {
    // Do not propagate server-controlled bodies or reflected credentials.
    Error::Invalid("optional Names archive view unavailable".into())
}

impl View {
    fn pending_rows(&self, name: Option<&Name>) -> Vec<Value> {
        self.pending
            .iter()
            .filter(|(_, row)| name.is_none_or(|name| row.name == *name))
            .map(|(txid, record)| json!({"txid":txid.to_string(),"record":record}))
            .collect()
    }

    pub(crate) fn resolve(&self, network: &str, name: &Name) -> Value {
        let resolution = match self.names.get(name) {
            Some(state) if state.suspended => Resolution::Suspended,
            Some(NameState {
                binding: Binding::Bound(bound),
                ..
            }) => Resolution::Bound(bound.clone()),
            _ => Resolution::Unbound,
        };
        json!({
            "network":network,"registry":self.status.genesis.to_string(),
            "genesis_height":self.status.genesis_block.height,"height":self.status.projected.height,
            "block_hash":self.status.projected.hash.to_string(),"name":name.as_str(),
            "resolution":resolution,"pending":self.pending_rows(Some(name)),"locally_cached":true,
        })
    }

    pub(crate) fn pending(&self, network: &str) -> Value {
        json!({"network":network,"registry":self.status.genesis.to_string(),
            "height":self.status.projected.height,"pending":self.pending_rows(None)})
    }
}

/// Full snapshot only. Time checks are cooperative; in-flight HTTP (at most the
/// client's five-second budget), filesystem I/O and JSON work are not preempted.
/// This read neither steps a registry nor proves the operator's chain claims.
pub(crate) fn read(
    settings: &ArchiveSettings,
    network: &str,
    genesis: Txid,
) -> Result<View, Error> {
    let deadline = Instant::now() + TRAVERSAL_TIME;
    let chain: Chain = serde_json::from_value(json!(network)).map_err(|_| refused())?;
    let chain_genesis = chain.genesis()?.0;
    if !std::fs::symlink_metadata(&settings.token_file)?.is_file() {
        return Err(refused());
    }
    let bytes = urma_io::read_private(&settings.token_file, 256)?;
    let token = std::str::from_utf8(&bytes).map_err(|_| refused())?.trim();
    let client = Client::new(settings.endpoint, token.to_owned()).map_err(|_| refused())?;
    let mut cursor = None;
    let mut metadata = None;
    let mut names = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut rows = 0usize;
    let mut bytes = 0usize;
    for _ in 0..MAX_PAGES {
        if Instant::now() >= deadline {
            return Err(refused());
        }
        let page = client
            .names_view(genesis, cursor.as_ref(), 128)
            .map_err(|_| refused())?;
        if Instant::now() >= deadline || page.chain_genesis != chain_genesis {
            return Err(refused());
        }
        page.rules.validate().map_err(|_| refused())?;
        let current = (
            page.snapshot.clone(),
            page.chain_genesis,
            serde_json::to_value(&page.status)?,
            page.rules.clone(),
        );
        if metadata
            .as_ref()
            .is_some_and(|previous| previous != &current)
        {
            return Err(refused());
        }
        metadata = Some(current);
        rows = rows.checked_add(page.entries.len()).ok_or_else(refused)?;
        bytes = bytes
            .checked_add(serde_json::to_vec(&page)?.len())
            .ok_or_else(refused)?;
        if rows > MAX_ROWS || bytes > MAX_BYTES {
            return Err(refused());
        }
        for entry in page.entries {
            let duplicate = match entry {
                NamesEntry::Name { name, state } => names.insert(name, state).is_some(),
                NamesEntry::Pending { txid, record } => pending.insert(txid, record).is_some(),
            };
            ensure!(!duplicate, "duplicate Names archive entry");
        }
        if Instant::now() >= deadline {
            return Err(refused());
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => {
                return Ok(View {
                    status: page.status,
                    names,
                    pending,
                });
            }
        }
    }
    Err(refused())
}
