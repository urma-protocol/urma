use crate::{detail, is_terminal, progress, stage};
use bitcoin::{
    Script, ScriptBuf,
    bech32::{Fe32, Hrp, segwit},
};
use urma_chain::observation::Chain;
use urma_runtime::error::{Context, Error};
use urma_runtime::{
    disk_plan::DiskPlan, node::Node, plan::PublicationPlan, publication::PublicPlan, quote::Quote,
};
use urma_wallet::account::Account;

pub(crate) fn currency(chain: Chain) -> &'static str {
    match chain {
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => "LTC",
        Chain::BitcoinMainnet | Chain::BitcoinTestnet4 | Chain::BitcoinRegtest => "BTC",
    }
}

/// Bech32 address of a witness script on `chain`, or the raw script when it
/// has no witness program (legacy or nonstandard outputs).
pub(crate) fn script_address(script: &Script, chain: Chain) -> String {
    let encoded = script.witness_version().and_then(|version| {
        let hrp = Hrp::parse(chain.address_hrp()).ok()?;
        segwit::encode(hrp, Fe32::from(version), &script.as_bytes()[2..]).ok()
    });
    match encoded {
        Some(address) => address,
        None => format!("script {}", hex::encode(script.as_bytes())),
    }
}

/// Approval lines for the first record: every funding input with its value and
/// paying address, then the return output that pays the account's 0/0 address.
/// The plan stores no derivation path; the address identifies the account key.
pub(crate) fn spending_summary(
    record: &PublicPlan,
    return_script: &str,
) -> Result<Vec<String>, Error> {
    let mut lines = Vec::new();
    for funding in &record.funding {
        let (outpoint, previous) = funding.prevout()?;
        lines.push(format!(
            "Input {outpoint}: {} base units from {}",
            previous.value.to_sat(),
            script_address(&previous.script_pubkey, record.chain)
        ));
    }
    let returned = ScriptBuf::from_hex(return_script)
        .map_err(|cause| Error::Invalid(format!("plan return script: {cause}")))?;
    lines.push(format!(
        "Return to {} (designated account address 0/0)",
        script_address(&returned, record.chain)
    ));
    Ok(lines)
}

pub(crate) fn plan_spending(plan: &PublicationPlan) -> Result<Vec<String>, Error> {
    let first = plan
        .records
        .first()
        .context("publication plan has no records")?;
    spending_summary(first, &plan.return_script)
}

pub(crate) fn disk_spending(plan: &DiskPlan) -> Result<Vec<String>, Error> {
    spending_summary(&plan.record(0)?, &plan.return_script)
}

pub(crate) fn amount(value: u64) -> String {
    format!("{}.{:08}", value / 100_000_000, value % 100_000_000)
}

pub(crate) fn preview(chain: Chain, quote: &Quote, ceiling: u64) {
    let unit = currency(chain);
    detail(
        2,
        format!(
            "Payload: {} bytes; data: {}; leaves: {}; root: 1. Retained value: {} base units per record, plus final change.",
            quote.payload_bytes, quote.parts, quote.leaves, quote.retained_value
        ),
    );
    if is_terminal() {
        progress(format!(
            "{} 256 KiB maximum per record; {} records, {} transactions (commit + reveal).",
            console::style("Multipart:").bold(),
            console::style(quote.records).cyan(),
            console::style(u64::from(quote.records) * 2).cyan()
        ));
        progress(format!(
            "{} {}",
            console::style("Estimated network fee:").bold(),
            console::style(format!("{} {unit}", amount(quote.maximum_fee)))
                .yellow()
                .bold()
        ));
        progress(format!(
            "{} {} {}",
            console::style("Funding required:").bold(),
            console::style(format!("{} {unit}", amount(quote.funding)))
                .green()
                .bold(),
            console::style("(includes value returned to your identity, not just fees)").dim()
        ));
        if ceiling < quote.maximum_fee {
            progress(format!(
                "Your fee limit is {} {unit}; the estimate exceeds it by {} {unit}.",
                console::style(amount(ceiling)).yellow(),
                console::style(amount(quote.maximum_fee - ceiling))
                    .red()
                    .bold()
            ));
        }
    } else {
        progress(format!(
            "Multipart: 256 KiB maximum per record; {} records, {} transactions (commit + reveal).",
            quote.records,
            u64::from(quote.records) * 2
        ));
        progress(format!(
            "Estimated network fee: {} {unit}.",
            amount(quote.maximum_fee)
        ));
        progress(format!(
            "Funding required: {} {unit} (includes value returned to your identity, not just fees).",
            amount(quote.funding)
        ));
        if ceiling < quote.maximum_fee {
            progress(format!(
                "Your fee limit is {} {unit}; the estimate exceeds it by {} {unit}.",
                amount(ceiling),
                amount(quote.maximum_fee - ceiling)
            ));
        }
    }
}

fn report_address(label: &str, address: &str) {
    if is_terminal() {
        progress(format!(
            "{} ({}): {}",
            console::style("Your funding address").bold(),
            console::style(label).dim(),
            console::style(address).cyan().bold()
        ));
    } else {
        progress(format!("Your funding address ({label}): {address}"));
    }
}

fn report_balance(unit: &str, balance: u64, count: usize) {
    if is_terminal() {
        progress(format!(
            "{} {} across {} payment(s).",
            console::style("Confirmed spendable balance:").bold(),
            console::style(format!("{} {unit}", amount(balance)))
                .green()
                .bold(),
            console::style(count).cyan()
        ));
    } else {
        progress(format!(
            "Confirmed spendable balance: {} {unit} across {count} payment(s).",
            amount(balance)
        ));
    }
}

pub(crate) fn check(
    node: &Node,
    funder: &Account,
    quote: &Quote,
    ceiling: u64,
) -> Result<(), Error> {
    let unit = currency(node.chain());
    report_address(node.chain().label(), &funder.receive_address()?);
    let view = stage("Checking confirmed spendable funds...", || {
        node.wallet(funder)
    })?;
    let mut balance = 0u64;
    for coin in &view.coins {
        balance = balance
            .checked_add(coin.value)
            .context("balance overflow")?;
    }
    report_balance(unit, balance, view.coins.len());
    detail(
        2,
        "Account-wide BIP84 balance (gap 20). Unconfirmed, immature and spent outputs are excluded.".into(),
    );
    if balance < quote.funding {
        if is_terminal() {
            progress(format!(
                "{} you are short by {}.",
                console::style("Insufficient funds:").yellow().bold(),
                console::style(format!("{} {unit}", amount(quote.funding - balance)))
                    .yellow()
                    .bold()
            ));
        } else {
            progress(format!(
                "Insufficient funds: you are short by {} {unit}.",
                amount(quote.funding - balance)
            ));
        }
    }
    if ceiling < quote.maximum_fee {
        return Err(Error::Capacity("estimated fee exceeds --max-fee; raise the limit or use git publish for an automatically calculated quote. Nothing was broadcast".into()));
    }
    if balance < quote.funding {
        return Err(Error::Missing("funding is not ready; the amounts and receiving address are shown above. Nothing was broadcast".into()));
    }
    if is_terminal() {
        progress(format!(
            "{} No broadcast yet.",
            console::style("Funding is sufficient for this quote.")
                .green()
                .bold()
        ));
    } else {
        progress("Funding is sufficient for this quote. No broadcast yet.".into());
    }
    Ok(())
}

pub(crate) fn preflight(node: &Node, directory: &std::path::Path) -> Result<(), Error> {
    use urma_runtime::{
        disk_plan::DiskPlan,
        publish::{MempoolCheck, test_accept},
    };
    let plan = DiskPlan::load(&directory.join("publication"))?;
    let first = plan.record(0)?;
    progress(
        "Checking the first funding transaction with testmempoolaccept (no broadcast)...".into(),
    );
    match test_accept(node, &first.commit)? {
        MempoolCheck::Allowed => progress("First commit accepted by node policy. Future dependent transactions are not yet mempool-verified.".into()),
        MempoolCheck::Rejected(reason) => return Err(Error::Invalid(format!("node mempool policy rejected first commit: {reason}; nothing was broadcast"))),
        MempoolCheck::Unavailable(reason) => {
            tracing::warn!(%reason, "prepare preflight unavailable");
            progress("Mempool preflight unavailable from this endpoint; this plan has no live node acceptance proof. Nothing was broadcast.".into());
        }
    }
    Ok(())
}
