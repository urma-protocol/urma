use crate::{detail, progress, stage};
use urma::error::{Context, Error};
use urma_chain::observation::Chain;
use urma_identity::identity::IdentitySigner;
use urma_runtime::{node::Node, quote::Quote};

pub(crate) fn currency(chain: Chain) -> &'static str {
    match chain {
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => "LTC",
        Chain::BitcoinTestnet4 | Chain::BitcoinRegtest => "BTC",
    }
}

pub(crate) fn amount(value: u64) -> String {
    format!("{}.{:08}", value / 100_000_000, value % 100_000_000)
}

pub(crate) fn preview(chain: Chain, quote: &Quote, ceiling: u64) {
    let unit = currency(chain);
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

pub(crate) fn check(
    node: &Node,
    signer: &impl IdentitySigner,
    quote: &Quote,
    ceiling: u64,
) -> Result<(), Error> {
    let unit = currency(node.chain());
    let address = urma_wallet::address::receive_address(signer, node.chain())?;
    progress(format!(
        "Your funding address ({}): {address}",
        node.chain().label()
    ));
    let outputs = stage("Checking confirmed spendable funds...", || {
        node.available_utxos(signer)
    })?;
    let mut balance = 0u64;
    let mut largest = 0u64;
    for output in &outputs {
        balance = balance
            .checked_add(output.value)
            .context("balance overflow")?;
        largest = largest.max(output.value);
    }
    progress(format!(
        "Confirmed spendable balance: {} {unit} across {} payment(s).",
        amount(balance),
        outputs.len()
    ));
    detail(
        2,
        format!(
            "Largest available payment: {} {unit}. Unconfirmed, immature and spent outputs are excluded.",
            amount(largest)
        ),
    );
    if balance < quote.funding {
        progress(format!(
            "Insufficient funds: you are short by {} {unit}.",
            amount(quote.funding - balance)
        ));
    }
    if largest < quote.funding {
        if balance >= quote.funding {
            progress("Your total balance is sufficient, but it is split across payments this version cannot combine.".into());
        }
        progress(format!(
            "This version needs one confirmed payment of at least {} {unit} to the address above. Adding only the shortfall as a separate payment may not suffice.",
            amount(quote.funding)
        ));
    }
    if ceiling < quote.maximum_fee {
        return Err(Error::Capacity("estimated fee exceeds --max-fee; raise the limit or use git publish for an automatically calculated quote. Nothing was broadcast".into()));
    }
    if largest < quote.funding {
        return Err(Error::Missing("funding is not ready; the amounts and receiving address are shown above. Nothing was broadcast".into()));
    }
    progress("Funding is sufficient for this quote. No broadcast yet.".into());
    Ok(())
}
