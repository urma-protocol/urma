use crate::{
    gateway_http::{Refusal, Reply},
    gateway_route::{Currency, Scan},
};
use bitcoin::Txid;
use serde_json::{Value, json};
use std::time::Duration;

pub(crate) enum ResolutionHealth {
    Unavailable,
    Loaded {
        index_height: u64,
        chain_tip: u64,
        scan: Scan,
        currency: Currency,
        names_source: Value,
    },
}

pub(crate) struct NetworkHealth<'a> {
    pub(crate) network: &'a str,
    pub(crate) suffix: &'a str,
    pub(crate) registry: Txid,
    pub(crate) state: ResolutionHealth,
}

impl NetworkHealth<'_> {
    fn document(self) -> Value {
        let mut row = json!({"network": self.network, "suffix": self.suffix,
            "registry": self.registry.to_string(), "state": "unavailable"});
        match self.state {
            ResolutionHealth::Unavailable => {}
            ResolutionHealth::Loaded {
                index_height,
                chain_tip,
                scan,
                currency,
                names_source,
            } => {
                row["index_height"] = index_height.into();
                row["chain_tip"] = chain_tip.into();
                row["scan_age_seconds"] = match scan {
                    Scan::Never | Scan::ArchiveView(_) => Value::Null,
                    Scan::At(at) => at.elapsed().as_secs().into(),
                };
                row["view_age_seconds"] = match scan {
                    Scan::ArchiveView(at) => at.elapsed().as_secs().into(),
                    _ => Value::Null,
                };
                row["names_source"] = names_source;
                row["state"] = match currency {
                    Currency::Current => "ready".into(),
                    Currency::Behind(reason) => {
                        tracing::debug!(target: "urma_gateway", reason = %reason, "readiness index is behind");
                        "index-behind".into()
                    }
                };
            }
        }
        row
    }
}

pub(crate) fn readiness_reply<'a>(
    networks: impl Iterator<Item = NetworkHealth<'a>>,
    retry: Duration,
) -> Result<Reply, Refusal> {
    let networks: Vec<Value> = networks.map(NetworkHealth::document).collect();
    let ready = networks.iter().all(|row| row["state"] == "ready");
    let reply = Reply::json(
        if ready { 200 } else { 503 },
        &json!({"ready": ready, "networks": networks}),
    )?;
    Ok(if ready {
        reply
    } else {
        reply.with("Retry-After", retry.as_secs().to_string())
    })
}
