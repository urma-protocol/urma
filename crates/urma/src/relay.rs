use crate::config::Limits;
use crate::config::RELAY_MAX_BUDGET_SATS;
use crate::error::{Context, Error, bail, ensure};
use crate::{
    source::Source,
    transport::{self, Plan},
};
use bitcoin::{Network, Transaction, Txid, consensus::deserialize};
use serde_json::{Value, json};
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
enum Step {
    Commit,
    Reveals(Vec<usize>),
    Wait,
    Complete,
}

fn authorize(
    network: Network,
    planned_fee: u64,
    budget: u64,
    accept_provider_trust: bool,
) -> Result<(), Error> {
    ensure!(
        matches!(network, Network::Testnet4 | Network::Regtest),
        "relay supports only testnet4/regtest, never mainnet"
    );
    ensure!(
        accept_provider_trust,
        "relay requires explicit acceptance of provider chain-selection/unspentness trust"
    );
    ensure!(
        (1..=RELAY_MAX_BUDGET_SATS).contains(&budget) && planned_fee <= budget,
        "journal exceeds explicit relay fee budget"
    );
    Ok(())
}

fn missing_reveals(status: &Value) -> Result<Vec<usize>, Error> {
    let reveals = status["reveal_statuses"]
        .as_array()
        .context("missing reveal statuses")?;
    ensure!(
        !reveals.is_empty() && reveals.len() <= Limits::RECORDS,
        "invalid reveal status count"
    );
    let mut missing = Vec::new();
    for (index, reveal) in reveals.iter().enumerate() {
        match reveal["state"].as_str().context("missing reveal state")? {
            "unknown" => missing.push(index),
            "pending" | "confirmed" => (),
            _ => bail!("invalid reveal state"),
        }
    }
    Ok(missing)
}

fn next_step(status: &Value, allow_unconfirmed_commit: bool) -> Result<Step, Error> {
    match status["status"].as_str().context("missing source status")? {
        "prepared" => Ok(Step::Commit),
        "commit_pending" if allow_unconfirmed_commit => {
            ensure!(
                status["commit_status"]["state"] == "pending",
                "unconfirmed reveal requires a known pending commit"
            );
            let missing = missing_reveals(status)?;
            Ok(if missing.is_empty() {
                Step::Wait
            } else {
                Step::Reveals(missing)
            })
        }
        "commit_pending" | "confirming" => Ok(Step::Wait),
        "confirmed" => Ok(Step::Complete),
        "awaiting_reveals" => {
            ensure!(
                status["commit_status"]["state"] == "confirmed",
                "cannot reveal before commit confirmation"
            );
            Ok(Step::Reveals(missing_reveals(status)?))
        }
        _ => bail!("unsupported or inconsistent relay state"),
    }
}

pub fn broadcast_plan(
    url: &str,
    network: Network,
    plan: &Plan,
    budget: u64,
    accept_provider_trust: bool,
    allow_unconfirmed_commit: bool,
) -> Result<Value, Error> {
    authorize(network, plan.fee_sats, budget, accept_provider_trust)?;
    transport::validate_plan(plan)?;
    ensure!(
        plan.network == network.to_string(),
        "relay network differs from journal"
    );
    let source = Source::connect(url, &network)?;
    let before = source.status_plan(plan)?;
    let step = next_step(&before, allow_unconfirmed_commit)?;
    let mut submitted = Vec::new();
    let action = match step {
        Step::Commit => {
            source.confirmed_funding(plan)?;
            submitted.push(post_transaction(source.endpoint(), &plan.commit)?);
            "commit_submitted"
        }
        Step::Reveals(indices) => {
            let commit: Transaction = deserialize(&hex::decode(&plan.commit)?)?;
            for index in indices {
                ensure!(
                    index < plan.reveals.len(),
                    "source reveal index out of range"
                );
                source.require_unspent(commit.compute_txid(), u32::try_from(index)?)?;
                submitted.push(post_transaction(source.endpoint(), &plan.reveals[index])?);
            }
            "reveals_submitted"
        }
        Step::Wait => "waiting_for_confirmation",
        Step::Complete => "already_confirmed",
    };
    Ok(
        json!({"action": action, "submitted_txids": submitted, "network": network.to_string(),
        "fee_budget_sats": budget, "planned_fee_sats": plan.fee_sats, "before": before,
        "allow_unconfirmed_commit": allow_unconfirmed_commit,
        "note": "POST acceptance is not confirmation. Query status before advancing. Provider trusted for chain selection and unspentness."}),
    )
}

fn post_transaction(endpoint: &str, raw: &str) -> Result<String, Error> {
    ensure!(
        raw.len() <= 8_000_000,
        "transaction exceeds relay byte limit"
    );
    let tx: Transaction = deserialize(&hex::decode(raw)?)?;
    let expected = tx.compute_txid();
    let response = minreq::post(format!("{endpoint}/tx"))
        .with_timeout(20)
        .with_max_redirects(0)
        .with_max_headers_size(16_384)
        .with_max_status_line_length(1_024)
        .with_header("Content-Type", "text/plain")
        .with_body(raw)
        .send_lazy()
        .context("relay POST failed; submission may be uncertain, check status before retry")?;
    let status = response.status_code;
    let mut body = Vec::new();
    for byte in response.take(1025) {
        body.push(byte?.0);
    }
    ensure!(
        body.len() <= 1024,
        "relay response exceeds byte limit; check transaction status"
    );
    ensure!(status == 200, "relay HTTP {status}: {}", hex::encode(&body));
    let returned = Txid::from_str(std::str::from_utf8(&body)?.trim())
        .context("invalid relay txid; check transaction status")?;
    ensure!(
        returned == expected,
        "relay returned a different txid; check transaction status"
    );
    Ok(expected.to_string())
}
