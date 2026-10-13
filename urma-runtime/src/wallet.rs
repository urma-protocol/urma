use crate::config;
use crate::error::{Context, Error, ensure};
use crate::node::Node;
use bitcoin::{Amount, Denomination, OutPoint};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use std::{cmp::Reverse, collections::HashMap};
use urma_wallet::{
    account::{Account, Branch, KeyPath},
    funding::Funding,
};

#[derive(Clone, Debug, Serialize)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: u64,
    pub height: u64,
    #[serde(serialize_with = "path_text")]
    pub path: KeyPath,
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletView {
    pub coins: Vec<Coin>,
    pub next_change: u32,
    pub reported: usize,
    pub verified: bool,
}

#[derive(Clone)]
pub struct FundingInput {
    pub funding: Funding,
    pub path: KeyPath,
}

pub struct Selection {
    pub inputs: Vec<FundingInput>,
    pub total: u64,
    pub next_change: u32,
}

fn path_text<S: Serializer>(path: &KeyPath, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{}/{}", path.branch.index(), path.index))
}

pub(crate) fn coin_amount(value: &Value) -> Result<Amount, Error> {
    let coins = value.as_f64().context("missing coin amount")?;
    Ok(Amount::from_float_in(coins, Denomination::Bitcoin)?)
}

fn covered(total: u64, inputs: usize, minimum: u64, per_input: u64) -> Result<bool, Error> {
    let needed = per_input
        .checked_mul(u64::try_from(inputs)?)
        .and_then(|inputs| inputs.checked_add(minimum))
        .context("funding target overflow")?;
    Ok(total >= needed)
}

impl Node {
    /// Unspent-only discovery: `next_change` is fresh until the change coin is
    /// spent; history-based discovery is a follow-up.
    pub fn wallet(&self, account: &Account) -> Result<WalletView, Error> {
        self.verify_network()?;
        ensure!(
            account.chain().genesis()? == self.chain().genesis()?,
            "funding account belongs to another chain"
        );
        let mut coins = match self.is_public() {
            true => self.routed_coins(account)?,
            false => self.local_coins(account)?,
        };
        coins.sort_by_key(|coin| (Reverse(coin.value), coin.outpoint));
        let next_change = coins
            .iter()
            .filter(|coin| coin.path.branch == Branch::Internal)
            .fold(0, |next, coin| next.max(coin.path.index + 1));
        let reported = coins.len();
        if reported > config::WALLET_VERIFY_OUTPUTS {
            tracing::warn!(
                reported,
                bound = config::WALLET_VERIFY_OUTPUTS,
                "wallet exceeds the per-output verification bound; view follows the provider's unspent rows"
            );
            return Ok(WalletView {
                coins,
                next_change,
                reported,
                verified: false,
            });
        }
        let mut live = Vec::new();
        for coin in coins {
            if self.live(account, &coin)? {
                live.push(coin);
            }
        }
        Ok(WalletView {
            coins: live,
            next_change,
            reported,
            verified: true,
        })
    }

    pub fn select_coins(
        &self,
        account: &Account,
        minimum: u64,
        per_input: u64,
    ) -> Result<Selection, Error> {
        let view = self.wallet(account)?;
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for coin in view.coins {
            if covered(total, chosen.len(), minimum, per_input)? {
                break;
            }
            ensure!(
                chosen.len() < config::WALLET_MAX_INPUTS,
                "funding needs more than {} inputs; consolidate the wallet first",
                config::WALLET_MAX_INPUTS
            );
            if !view.verified && !self.live(account, &coin)? {
                continue;
            }
            total = total.checked_add(coin.value).context("funding overflow")?;
            chosen.push(coin);
        }
        if !covered(total, chosen.len(), minimum, per_input)? {
            return Err(Error::Missing(
                "confirmed wallet coins do not cover the spend; fund the receive address and confirm first".into(),
            ));
        }
        let mut inputs = Vec::new();
        for coin in &chosen {
            inputs.push(FundingInput {
                funding: self.parent(account, coin)?,
                path: coin.path,
            });
        }
        Ok(Selection {
            inputs,
            total,
            next_change: view.next_change,
        })
    }

    fn local_coins(&self, account: &Account) -> Result<Vec<Coin>, Error> {
        let mut paths = HashMap::new();
        let mut descriptors = Vec::new();
        for branch in [Branch::External, Branch::Internal] {
            for index in 0..config::WALLET_RANGE {
                let path = KeyPath::new(branch, index);
                let script = hex::encode(account.script(path)?.as_bytes());
                descriptors.push(json!(format!("raw({script})")));
                paths.insert(script, path);
            }
        }
        let scan = self.call("scantxoutset", &[json!("start"), Value::Array(descriptors)])?;
        ensure!(scan["success"] == true, "UTXO scan did not complete");
        let rows = scan["unspents"].as_array().context("missing UTXO scan")?;
        ensure!(
            rows.len() <= config::WALLET_MAX_COINS,
            "UTXO client capacity exceeded"
        );
        let mut coins = Vec::new();
        for row in rows {
            let script = row["scriptPubKey"]
                .as_str()
                .context("missing UTXO script")?;
            let path = *paths
                .get(script)
                .context("UTXO scan returned a foreign script")?;
            coins.push(Coin {
                outpoint: OutPoint {
                    txid: row["txid"].as_str().context("missing UTXO txid")?.parse()?,
                    vout: u32::try_from(row["vout"].as_u64().context("missing UTXO vout")?)?,
                },
                value: coin_amount(&row["amount"])?.to_sat(),
                height: row["height"].as_u64().context("missing UTXO height")?,
                path,
            });
        }
        Ok(coins)
    }

    fn routed_coins(&self, account: &Account) -> Result<Vec<Coin>, Error> {
        let mut coins = Vec::new();
        for branch in [Branch::External, Branch::Internal] {
            let mut empty = 0;
            let mut index = 0;
            while empty < config::WALLET_GAP && index < config::WALLET_RANGE {
                let found = self.address_coins(account, KeyPath::new(branch, index))?;
                empty = match found.is_empty() {
                    true => empty + 1,
                    false => 0,
                };
                coins.extend(found);
                ensure!(
                    coins.len() <= config::WALLET_MAX_COINS,
                    "UTXO client capacity exceeded"
                );
                index += 1;
            }
        }
        Ok(coins)
    }

    fn address_coins(&self, account: &Account, path: KeyPath) -> Result<Vec<Coin>, Error> {
        let rows = self.call("addressutxos", &[json!(account.address(path)?)])?;
        let rows = rows.as_array().context("missing public UTXOs")?;
        let mut coins = Vec::new();
        for row in rows {
            if row["status"]["confirmed"] != true {
                continue;
            }
            coins.push(Coin {
                outpoint: OutPoint {
                    txid: row["txid"].as_str().context("missing UTXO txid")?.parse()?,
                    vout: u32::try_from(row["vout"].as_u64().context("missing UTXO index")?)?,
                },
                value: row["value"].as_u64().context("missing UTXO value")?,
                height: row["status"]["block_height"]
                    .as_u64()
                    .context("missing UTXO height")?,
                path,
            });
        }
        Ok(coins)
    }

    fn live(&self, account: &Account, coin: &Coin) -> Result<bool, Error> {
        let unspent = self.call(
            "gettxout",
            &[
                json!(coin.outpoint.txid),
                json!(coin.outpoint.vout),
                json!(true),
            ],
        )?;
        if unspent.is_null() {
            return Ok(false);
        }
        let confirmations = config::confirmations(&unspent)?;
        if confirmations < 1 || (unspent["coinbase"] == true && confirmations < 100) {
            return Ok(false);
        }
        ensure!(
            unspent["scriptPubKey"]["hex"] == hex::encode(account.script(coin.path)?.as_bytes()),
            "live coin script disagrees with its wallet path"
        );
        let amount = coin_amount(&unspent["value"])?;
        ensure!(
            amount.to_sat() == coin.value,
            "live coin value disagrees with the wallet scan"
        );
        Ok(true)
    }

    fn parent(&self, account: &Account, coin: &Coin) -> Result<Funding, Error> {
        let block = self.call("getblockhash", &[json!(coin.height)])?;
        let raw = self.call(
            "getrawtransaction",
            &[json!(coin.outpoint.txid), json!(false), block],
        )?;
        let funding = Funding {
            raw_transaction: raw.as_str().context("missing funding bytes")?.to_owned(),
            vout: coin.outpoint.vout,
        };
        let (outpoint, previous) = funding.prevout()?;
        ensure!(
            outpoint == coin.outpoint && previous.value.to_sat() == coin.value,
            "funding transaction disagrees with the scanned coin"
        );
        ensure!(
            previous.script_pubkey == account.script(coin.path)?,
            "funding transaction disagrees with the wallet path"
        );
        Ok(funding)
    }
}
