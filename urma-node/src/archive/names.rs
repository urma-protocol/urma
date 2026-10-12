use super::{Archive, generation, point, sql_integer, unsigned};
use crate::{
    Error,
    model::{ChainPoint, SCAN_RULES_VERSION},
    names::*,
};
use bitcoin::Txid;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use urma_core::format::{PublicRecord, RecordKind, Urma};
use urma_names::{
    engine::{BlockDelta, Registry},
    name::Name,
    payload::{Genesis, Payload},
    projection::observation_from_record,
    state::{Binding, Commit, NameState, Observation, PendingRecord, Resolution},
};

pub(super) const SCHEMA: &str = "
CREATE TABLE names_registries (
 genesis TEXT PRIMARY KEY, genesis_height INTEGER NOT NULL CHECK(genesis_height>=0),
 genesis_hash TEXT NOT NULL REFERENCES headers(hash), rules BLOB NOT NULL,
 height INTEGER NOT NULL CHECK(height>=genesis_height), block_hash TEXT NOT NULL REFERENCES headers(hash)
);
CREATE TABLE names_states (
 registry TEXT NOT NULL REFERENCES names_registries(genesis), name TEXT NOT NULL,
 state BLOB NOT NULL, PRIMARY KEY(registry,name)
);
CREATE TABLE names_pending (
 registry TEXT NOT NULL REFERENCES names_registries(genesis), txid TEXT NOT NULL,
 state BLOB NOT NULL, PRIMARY KEY(registry,txid)
);
CREATE TABLE names_blocks (
 registry TEXT NOT NULL REFERENCES names_registries(genesis), height INTEGER NOT NULL,
 block_hash TEXT NOT NULL REFERENCES headers(hash), delta BLOB,
 PRIMARY KEY(registry,height)
);
CREATE TABLE names_outcomes (
 registry TEXT NOT NULL, height INTEGER NOT NULL, position INTEGER NOT NULL,
 txid TEXT NOT NULL, verdict BLOB NOT NULL, PRIMARY KEY(registry,height,position),
 FOREIGN KEY(registry,height) REFERENCES names_blocks(registry,height) ON DELETE CASCADE
);
PRAGMA user_version=4;";

const UNDO_BLOCKS: u64 = 1000;

impl Archive {
    pub(crate) fn names_view(
        &self,
        instance: &str,
        genesis: Txid,
        cursor: Option<&NamesCursor>,
        limit: u32,
    ) -> Result<NamesPage, Error> {
        if !(1..=MAX_NAMES_PAGE).contains(&limit) || cursor.is_some_and(|c| c.genesis != genesis) {
            return Err(invalid("invalid page limit or cursor registry"));
        }
        let snapshot = crate::projection::IndexSnapshot {
            instance: instance.into(),
            revision: self.db.query_row(
                "SELECT COALESCE(MAX(sequence),0) FROM events",
                [],
                |r| unsigned(r, 0),
            )?,
        };
        if cursor.is_some_and(|c| c.snapshot != snapshot) {
            return Err(Error::Busy(
                "Names snapshot changed; restart traversal".into(),
            ));
        }
        // Bound rules before names_status/metadata decodes them as well. State
        // and key bounds below also apply before allocating SQLite blobs in Rust.
        let bytes = self.db.query_row(
            "SELECT CASE WHEN length(CAST(rules AS BLOB))<=?2 THEN rules ELSE NULL END FROM names_registries WHERE genesis=?1",
            params![genesis.to_string(), MAX_NAMES_STATE_BYTES as i64],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        ).optional()?.ok_or_else(|| invalid("registry is not registered"))?
            .ok_or_else(|| invalid("stored rules exceed page bound"))?;
        let rules: Genesis = serde_json::from_slice(&bytes)?;
        rules.validate().map_err(invalid)?;
        let status = self
            .names_status(genesis)?
            .ok_or_else(|| invalid("registry is not registered"))?;
        let mut entries = Vec::new();
        let (phase, after) = cursor
            .map(|c| c.after.order_key())
            .unwrap_or((0, String::new()));
        for section in phase..=1 {
            let (table, column) = if section == 0 {
                ("names_states", "name")
            } else {
                ("names_pending", "txid")
            };
            // Identifiers above are fixed code, never request data. Each query
            // walks its indexed suffix; no full-map restore or UNION sort.
            let query = format!(
                "SELECT CASE WHEN length(CAST({column} AS BLOB))<=64 THEN {column} ELSE NULL END,
                 CASE WHEN length(CAST(state AS BLOB))<=?3 THEN state ELSE NULL END
                 FROM {table} WHERE registry=?1 AND {column}>?2
                 ORDER BY {column} LIMIT ?4"
            );
            let mut statement = self.db.prepare(&query)?;
            let mut rows = statement.query(params![
                genesis.to_string(),
                if section == phase { after.as_str() } else { "" },
                MAX_NAMES_STATE_BYTES as i64,
                (limit as usize + 1 - entries.len()) as i64,
            ])?;
            while let Some(row) = rows.next()? {
                let key = row
                    .get::<_, Option<String>>(0)?
                    .ok_or_else(|| invalid("stored key exceeds page bound"))?;
                let bytes = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .ok_or_else(|| invalid("stored state exceeds page bound"))?;
                entries.push(if section == 0 {
                    NamesEntry::Name {
                        name: Name::parse(&key).map_err(invalid)?,
                        state: serde_json::from_slice(&bytes)?,
                    }
                } else {
                    let txid: Txid = key.parse().map_err(invalid)?;
                    if txid.to_string() != key {
                        return Err(invalid("noncanonical stored TXID"));
                    }
                    NamesEntry::Pending {
                        txid,
                        record: serde_json::from_slice(&bytes)?,
                    }
                });
            }
            if entries.len() > limit as usize {
                break;
            }
        }
        let next = if entries.len() > limit as usize {
            entries.pop();
            Some(NamesCursor {
                genesis,
                snapshot: snapshot.clone(),
                after: entries.last().expect("nonzero limit").key(),
            })
        } else {
            None
        };
        let page = NamesPage {
            snapshot,
            chain_genesis: self.config.chain.genesis().map_err(invalid)?.0,
            status,
            rules,
            entries,
            next,
        };
        // Fail the whole page rather than silently omit an entry. This is below
        // the common HTTP 32 MiB ceiling and is not an overall SQL time bound.
        if serde_json::to_vec(&page)?.len() > MAX_NAMES_PAGE_BYTES {
            return Err(invalid("Names page exceeds byte bound"));
        }
        Ok(page)
    }
}

struct Metadata {
    genesis: ChainPoint,
    rules: Genesis,
    projected: ChainPoint,
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("Names projection: {error}"))
}

fn selected(db: &Connection, block: ChainPoint) -> Result<bool, Error> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM selected WHERE height=?1 AND hash=?2)",
        params![sql_integer(block.height)?, block.hash.to_string()],
        |r| r.get(0),
    )?)
}

fn scanned(db: &Connection, block: ChainPoint) -> Result<bool, Error> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM scans WHERE block_hash=?1 AND rules=?2 AND unresolved=0)",
        params![block.hash.to_string(), SCAN_RULES_VERSION],
        |r| r.get(0),
    )?)
}

fn metadata(db: &Connection, genesis: Txid) -> Result<Option<Metadata>, Error> {
    let row = db.query_row(
        "SELECT genesis_height,genesis_hash,rules,height,block_hash FROM names_registries WHERE genesis=?1",
        [genesis.to_string()], |r| Ok((point(r)?, r.get::<_, Vec<u8>>(2)?, unsigned(r,3)?, r.get::<_, String>(4)?)),
    ).optional()?;
    row.map(|(genesis, rules, height, hash)| {
        Ok(Metadata {
            genesis,
            rules: serde_json::from_slice(&rules)?,
            projected: ChainPoint {
                height,
                hash: hash.parse().map_err(invalid)?,
            },
        })
    })
    .transpose()
}

fn checkpoint(
    db: &Connection,
    genesis: Txid,
    meta: &Metadata,
    height: u64,
) -> Result<ChainPoint, Error> {
    if height == meta.genesis.height {
        return Ok(meta.genesis);
    }
    db.query_row(
        "SELECT height,block_hash FROM names_blocks WHERE registry=?1 AND height=?2",
        params![genesis.to_string(), sql_integer(height)?],
        point,
    )
    .optional()?
    .ok_or_else(|| {
        Error::Busy("Names reorg exceeds retained undo; explicit rebuild required".into())
    })
}

fn load_registry(db: &Connection, genesis: Txid, meta: &Metadata) -> Result<Registry, Error> {
    let mut names = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut stmt =
        db.prepare("SELECT name,state FROM names_states WHERE registry=?1 ORDER BY name")?;
    for row in stmt.query_map([genesis.to_string()], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (key, value) = row?;
        names.insert(
            Name::parse(&key).map_err(invalid)?,
            serde_json::from_slice::<NameState>(&value)?,
        );
    }
    let mut stmt =
        db.prepare("SELECT txid,state FROM names_pending WHERE registry=?1 ORDER BY txid")?;
    for row in stmt.query_map([genesis.to_string()], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (key, value) = row?;
        pending.insert(
            key.parse().map_err(invalid)?,
            serde_json::from_slice::<PendingRecord>(&value)?,
        );
    }
    let mut undo = Vec::new();
    let mut stmt = db.prepare(
        "SELECT height,delta FROM names_blocks WHERE registry=?1 AND height>?2 AND delta IS NOT NULL ORDER BY height",
    )?;
    for row in stmt.query_map(
        params![
            genesis.to_string(),
            sql_integer(meta.projected.height.saturating_sub(UNDO_BLOCKS))?
        ],
        |r| Ok((unsigned(r, 0)?, r.get::<_, Vec<u8>>(1)?)),
    )? {
        let (height, bytes) = row?;
        let delta: BlockDelta = serde_json::from_slice(&bytes)?;
        if delta.height != height {
            return Err(invalid("undo height mismatch"));
        }
        undo.push(delta);
    }
    Registry::from_parts(
        genesis,
        meta.genesis.height,
        meta.rules.clone(),
        meta.projected.height,
        names,
        pending,
        undo,
    )
    .map_err(invalid)
}

/// Normalized updates touch only keys recorded by the pure engine. Historical
/// deltas keep absent distinct from present-unbound, including expiry effects.
fn apply_delta(
    db: &Connection,
    registry: Txid,
    delta: &BlockDelta,
    forward: bool,
) -> Result<(), Error> {
    let registry = registry.to_string();
    for change in &delta.names {
        let value = if forward {
            &change.after
        } else {
            &change.before
        };
        match value {
            Some(value) => {
                db.execute("INSERT INTO names_states VALUES(?1,?2,?3) ON CONFLICT(registry,name) DO UPDATE SET state=excluded.state",
                params![registry,change.key.as_str(),serde_json::to_vec(value)?])?;
            }
            None => {
                db.execute(
                    "DELETE FROM names_states WHERE registry=?1 AND name=?2",
                    params![registry, change.key.as_str()],
                )?;
            }
        }
    }
    for change in &delta.pending {
        let value = if forward {
            &change.after
        } else {
            &change.before
        };
        match value {
            Some(value) => {
                db.execute("INSERT INTO names_pending VALUES(?1,?2,?3) ON CONFLICT(registry,txid) DO UPDATE SET state=excluded.state",
                params![registry,change.key.to_string(),serde_json::to_vec(value)?])?;
            }
            None => {
                db.execute(
                    "DELETE FROM names_pending WHERE registry=?1 AND txid=?2",
                    params![registry, change.key.to_string()],
                )?;
            }
        }
    }
    Ok(())
}

fn addresses_registry(payload: &Payload, genesis: Txid) -> bool {
    match payload {
        Payload::Genesis(_) => false,
        Payload::Claim(op) | Payload::Update(op) | Payload::Renew(op) => op.registry == genesis,
        Payload::Approve(op) => op.registry == genesis,
        Payload::Suspend(op) | Payload::Restore(op) => op.registry == genesis,
    }
}

fn observations(
    db: &Connection,
    registry: &Registry,
    chain: urma_chain::observation::Chain,
    block: ChainPoint,
) -> Result<Vec<Observation>, Error> {
    let genesis = registry.genesis();
    let first_commit = (registry.genesis_height() + 1).max(
        block
            .height
            .saturating_sub(u64::from(registry.rules().reveal_max_blocks)),
    );
    let mut stmt = db.prepare(
        "SELECT r.position,t.txid,r.author,
        CASE WHEN length(r.record)<=?2 THEN r.record ELSE NULL END,t.raw
        FROM records r JOIN transactions t ON t.wtxid=r.wtxid
        WHERE r.block_hash=?1 AND substr(r.record,6,1)=x'0c' ORDER BY r.position",
    )?;
    let mut result = Vec::new();
    for row in stmt.query_map(
        params![
            block.hash.to_string(),
            (Urma::PREFIX_BYTES + Urma::MAX_PUBLIC_BYTES) as i64
        ],
        |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        },
    )? {
        let (position, txid, author, bytes, raw) = row?;
        let bytes = bytes.ok_or_else(|| invalid("stored Names record exceeds byte bound"))?;
        // Like the autonomous scanner, malformed or foreign profile payloads
        // do not participate in this registry's state machine.
        let payload = PublicRecord::decode(&bytes).and_then(|record| Payload::from_record(&record));
        let Ok(payload) = payload else { continue };
        if !addresses_registry(&payload, genesis) {
            continue;
        }
        let reveal = urma_chain::decode::transaction(&raw, chain).map_err(invalid)?;
        if reveal.input.len() != 1 || reveal.compute_txid().to_string() != txid {
            return Err(invalid("stored reveal identity mismatch"));
        }
        let outpoint = reveal.input[0].previous_output;
        // TXID authenticates the exact spent output; this locator establishes
        // selected placement separately. It does not claim commit witness proof.
        let location = db
            .query_row(
                "SELECT s.height,l.position FROM locators l
            JOIN selected s ON s.hash=l.block_hash JOIN scans c ON c.block_hash=s.hash
            WHERE l.txid=?1 AND s.height<=?2 AND c.rules=?3 AND c.unresolved=0 AND s.height>=?4
            ORDER BY s.height,l.position LIMIT 1",
                params![
                    outpoint.txid.to_string(),
                    sql_integer(block.height)?,
                    SCAN_RULES_VERSION,
                    sql_integer(first_commit)?
                ],
                |r| Ok((unsigned(r, 0)?, r.get::<_, u32>(1)?)),
            )
            .optional()?;
        let Some(location) = location else {
            // A known placement outside the registry's live window is not
            // missing context. Like the autonomous scanner, omit that reveal
            // while still advancing the block and applying its expirations.
            let outside_window: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM locators l
                JOIN selected s ON s.hash=l.block_hash JOIN scans c ON c.block_hash=s.hash
                WHERE l.txid=?1 AND s.height<?2 AND c.rules=?3 AND c.unresolved=0)",
                params![
                    outpoint.txid.to_string(),
                    sql_integer(first_commit)?,
                    SCAN_RULES_VERSION
                ],
                |r| r.get(0),
            )?;
            if outside_window {
                continue;
            }
            return Err(Error::Busy(
                "Names commit has no fully scanned selected placement".into(),
            ));
        };
        let observation = observation_from_record(
            &bytes,
            txid.parse().map_err(invalid)?,
            author.parse().map_err(invalid)?,
            block.height,
            position,
            Commit {
                txid: outpoint.txid,
                vout: outpoint.vout,
                height: location.0,
                position: location.1,
            },
        )
        .map_err(invalid)?
        .ok_or_else(|| invalid("Names profile changed while projecting"))?;
        result.push(observation);
    }
    Ok(result)
}

impl Archive {
    pub(crate) fn names_page(&self, after: Option<Txid>) -> Result<Vec<Txid>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT genesis FROM names_registries
            WHERE (?1 IS NULL OR genesis>?1) ORDER BY genesis LIMIT 128",
        )?;
        stmt.query_map([after.map(|txid| txid.to_string())], |r| {
            r.get::<_, String>(0)
        })?
        .map(|row| row?.parse().map_err(invalid))
        .collect()
    }

    pub(crate) fn register_names(
        &mut self,
        genesis: Txid,
        block: ChainPoint,
    ) -> Result<NamesStatus, Error> {
        if block.height < self.config.application_start.height || !selected(&self.db, block)? {
            return Err(Error::Stale);
        }
        if let Some(old) = metadata(&self.db, genesis)? {
            if old.genesis != block {
                return Err(Error::Stale);
            }
            return self
                .names_status(genesis)?
                .ok_or_else(|| invalid("missing registered genesis"));
        }
        if !scanned(&self.db, block)? {
            return Err(Error::Busy(
                "Names genesis block is not fully scanned and resolved".into(),
            ));
        }
        let bytes = self
            .db
            .query_row(
                "SELECT r.record FROM records r JOIN transactions t ON t.wtxid=r.wtxid
            WHERE r.block_hash=?1 AND t.txid=?2 ORDER BY r.position LIMIT 1",
                params![block.hash.to_string(), genesis.to_string()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("authenticated Names genesis record is not local"))?;
        if RecordKind::parse(&bytes).map_err(invalid)? != RecordKind::ProfileRecord {
            return Err(invalid("not a Names genesis"));
        }
        let Payload::Genesis(rules) =
            Payload::from_record(&PublicRecord::decode(&bytes).map_err(invalid)?)
                .map_err(invalid)?
        else {
            return Err(invalid("not a Names genesis"));
        };
        let registry = Registry::new(genesis, block.height, rules.clone()).map_err(invalid)?;
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO names_registries VALUES(?1,?2,?3,?4,?2,?3)",
            params![
                genesis.to_string(),
                sql_integer(block.height)?,
                block.hash.to_string(),
                serde_json::to_vec(&rules)?
            ],
        )?;
        tx.execute("INSERT INTO events(generation,kind,height,block_hash) SELECT generation,'names',?1,?2 FROM state",
            params![sql_integer(block.height)?,block.hash.to_string()])?;
        tx.commit()?;
        self.names_cache = Some(registry);
        self.names_status(genesis)?
            .ok_or_else(|| invalid("missing registered genesis"))
    }

    pub(crate) fn names_status(&self, genesis: Txid) -> Result<Option<NamesStatus>, Error> {
        let Some(meta) = metadata(&self.db, genesis)? else {
            return Ok(None);
        };
        if !selected(&self.db, meta.genesis)? || !selected(&self.db, meta.projected)? {
            return Err(Error::Stale);
        }
        let tip = self
            .db
            .query_row(
                "SELECT height,hash FROM selected ORDER BY height DESC LIMIT 1",
                [],
                point,
            )
            .optional()?;
        Ok(Some(NamesStatus {
            genesis,
            genesis_block: meta.genesis,
            projected: meta.projected,
            generation: generation(&self.db)?,
            selected_tip: tip,
            complete_to_tip: tip == Some(meta.projected),
        }))
    }

    pub(crate) fn names_resolve(
        &self,
        genesis: Txid,
        name: &Name,
    ) -> Result<NamesResolution, Error> {
        let status = self
            .names_status(genesis)?
            .ok_or_else(|| invalid("registry is not registered"))?;
        let value = self
            .db
            .query_row(
                "SELECT state FROM names_states WHERE registry=?1 AND name=?2",
                params![genesis.to_string(), name.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let state = value
            .map(|v| serde_json::from_slice::<NameState>(&v))
            .transpose()?
            .unwrap_or_else(NameState::unbound);
        let resolution = if state.suspended {
            Resolution::Suspended
        } else {
            match state.binding {
                Binding::Unbound => Resolution::Unbound,
                Binding::Bound(bound) => Resolution::Bound(bound),
            }
        };
        Ok(NamesResolution { status, resolution })
    }

    pub(crate) fn names_step(&mut self, genesis: Txid) -> Result<NamesStep, Error> {
        let meta =
            metadata(&self.db, genesis)?.ok_or_else(|| invalid("registry is not registered"))?;
        if !selected(&self.db, meta.genesis)? {
            return Err(Error::Stale);
        }
        let mut registry = match self.names_cache.take() {
            Some(registry)
                if registry.genesis() == genesis && registry.height() == meta.projected.height =>
            {
                registry
            }
            _ => load_registry(&self.db, genesis, &meta)?,
        };
        // The working copy is kept out of the cache until the transaction has
        // committed. Every error drops it, including any successful rollback in RAM.
        let mut rollbacks = Vec::new();
        let mut current = meta.projected;
        while !selected(&self.db, current)? {
            if registry.reversible_blocks() == 0 {
                return Err(Error::Busy(
                    "Names reorg exceeds retained undo; explicit rebuild required".into(),
                ));
            }
            rollbacks.push(registry.disconnect_delta().map_err(invalid)?);
            current = checkpoint(&self.db, genesis, &meta, registry.height())?;
        }
        let next_height = current
            .height
            .checked_add(1)
            .ok_or_else(|| invalid("height overflow"))?;
        let next = self
            .db
            .query_row(
                "SELECT height,hash FROM selected WHERE height=?1",
                [sql_integer(next_height)?],
                point,
            )
            .optional()?;
        let next = match next {
            Some(block) if scanned(&self.db, block)? => Some(block),
            _ => None,
        };
        let applied = match next {
            Some(block) => {
                let observations = observations(&self.db, &registry, self.config.chain, block)?;
                Some(
                    registry
                        .connect_delta(block.height, observations)
                        .map_err(invalid)?,
                )
            }
            None => None,
        };
        let outcomes = applied
            .as_ref()
            .map(|a| a.outcomes.clone())
            .unwrap_or_default();
        if !rollbacks.is_empty() || applied.is_some() {
            let tx = self.db.transaction()?;
            for delta in &rollbacks {
                apply_delta(&tx, genesis, delta, false)?;
                tx.execute(
                    "DELETE FROM names_blocks WHERE registry=?1 AND height=?2",
                    params![genesis.to_string(), sql_integer(delta.height)?],
                )?;
            }
            if let (Some(block), Some(applied)) = (next, &applied) {
                apply_delta(&tx, genesis, &applied.delta, true)?;
                tx.execute(
                    "INSERT INTO names_blocks VALUES(?1,?2,?3,?4)",
                    params![
                        genesis.to_string(),
                        sql_integer(block.height)?,
                        block.hash.to_string(),
                        serde_json::to_vec(&applied.delta)?
                    ],
                )?;
                for outcome in &applied.outcomes {
                    tx.execute(
                        "INSERT INTO names_outcomes VALUES(?1,?2,?3,?4,?5)",
                        params![
                            genesis.to_string(),
                            sql_integer(block.height)?,
                            outcome.position,
                            outcome.txid.to_string(),
                            serde_json::to_vec(&outcome.verdict)?
                        ],
                    )?;
                }
                current = block;
            }
            tx.execute(
                "UPDATE names_registries SET height=?2,block_hash=?3 WHERE genesis=?1",
                params![
                    genesis.to_string(),
                    sql_integer(current.height)?,
                    current.hash.to_string()
                ],
            )?;
            if current.height >= UNDO_BLOCKS {
                // Retain the floor checkpoint in addition to 1000 undo frames.
                tx.execute(
                    "DELETE FROM names_blocks WHERE registry=?1 AND height<?2",
                    params![
                        genesis.to_string(),
                        sql_integer(current.height - UNDO_BLOCKS)?
                    ],
                )?;
                // The floor is a checkpoint only. Keeping its delta would make
                // older undo reappear after rolling back to the floor and reopening.
                tx.execute(
                    "UPDATE names_blocks SET delta=NULL WHERE registry=?1 AND height=?2",
                    params![
                        genesis.to_string(),
                        sql_integer(current.height - UNDO_BLOCKS)?
                    ],
                )?;
            }
            tx.execute("INSERT INTO events(generation,kind,height,block_hash) SELECT generation,'names',?1,?2 FROM state",params![sql_integer(current.height)?,current.hash.to_string()])?;
            tx.commit()?;
        }
        registry.prune(UNDO_BLOCKS as usize);
        self.names_cache = Some(registry);
        Ok(NamesStep {
            status: self
                .names_status(genesis)?
                .ok_or_else(|| invalid("missing registry"))?,
            applied: next,
            rolled_back: rollbacks.len() as u64,
            outcomes,
        })
    }
}
