use crate::config;
use crate::error::{Context, Error, ensure};
use crate::remote::request;
use serde_json::{Value, json};
use std::time::Duration;

struct Api<'a> {
    base: &'a str,
    timeout: Duration,
}

impl Api<'_> {
    fn text(&self, path: &str) -> Result<String, Error> {
        Ok(String::from_utf8(request(
            minreq::get(format!("{}/{path}", self.base)),
            self.timeout,
        )?)?)
    }

    fn json_get(&self, path: &str) -> Result<Value, Error> {
        Ok(serde_json::from_str(&self.text(path)?)?)
    }

    fn transaction(&self, args: &[Value]) -> Result<Value, Error> {
        let txid = arg(args, 0)?;
        if args.get(1).context("missing transaction verbosity")? == &json!(false) {
            return Ok(json!(self.text(&format!("tx/{txid}/hex"))?));
        }
        let status = self.json_get(&format!("tx/{txid}/status"))?;
        if status["confirmed"] == false {
            return Ok(json!({"confirmations":0}));
        }
        ensure!(status["confirmed"] == true, "invalid transaction status");
        Ok(json!({"confirmations":self.confirmations(&status)?,"blockhash":status["block_hash"]}))
    }

    fn confirmations(&self, status: &Value) -> Result<u64, Error> {
        let tip: u64 = self.text("blocks/tip/height")?.parse()?;
        let height = status["block_height"]
            .as_u64()
            .context("missing inclusion height")?;
        tip.checked_sub(height)
            .and_then(|n| n.checked_add(1))
            .context("chain changed during source lookup")
    }

    fn txout(&self, args: &[Value]) -> Result<Value, Error> {
        let txid = arg(args, 0)?;
        let index = arg(args, 1)?;
        let spent = self.json_get(&format!("tx/{txid}/outspend/{index}"))?;
        if spent["spent"] == true {
            return Ok(Value::Null);
        }
        ensure!(spent["spent"] == false, "invalid outspend status");
        let tx = self.json_get(&format!("tx/{txid}"))?;
        let output = tx["vout"]
            .get(index.parse::<usize>()?)
            .context("missing output")?;
        let count = if tx["status"]["confirmed"] == true {
            self.confirmations(&tx["status"])?
        } else {
            0
        };
        let amount =
            bitcoin::Amount::from_sat(output["value"].as_u64().context("missing output value")?);
        Ok(
            json!({"confirmations":count,"coinbase":tx["vin"][0]["is_coinbase"],
            "value":serde_json::from_str::<Value>(&amount.to_string_in(bitcoin::Denomination::Bitcoin))?,
            "scriptPubKey":{"hex":output["scriptpubkey"]}}),
        )
    }

    fn broadcast(&self, args: &[Value]) -> Result<Value, Error> {
        let raw = arg(args, 0)?;
        ensure!(
            raw.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid transaction hex"
        );
        Ok(json!(String::from_utf8(request(
            minreq::post(format!("{}/tx", self.base))
                .with_header("Content-Type", "text/plain")
                .with_body(raw),
            self.timeout,
        )?)?))
    }
}

fn arg(args: &[Value], index: usize) -> Result<String, Error> {
    let value = args.get(index).context("missing source argument")?;
    let string = match value {
        Value::String(string) => string.clone(),
        Value::Number(number) => number.to_string(),
        _ => return Err(Error::Invalid("invalid source argument".into())),
    };
    ensure!(
        !string.is_empty() && string.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid source path"
    );
    Ok(string)
}

pub(crate) fn call(base: &str, method: &str, args: &[Value]) -> Result<Value, Error> {
    let api = Api {
        base,
        timeout: config::method_timeout(method),
    };
    match method {
        "getblockhash" => Ok(json!(api.text(&format!("block-height/{}", arg(args, 0)?))?)),
        "getblockchaininfo" => {
            let hash = api.text("blocks/tip/hash")?;
            let block = api.json_get(&format!("block/{hash}"))?;
            Ok(json!({"blocks":block["height"],"bestblockhash":hash,"initialblockdownload":false}))
        }
        "getrawtransaction" => api.transaction(args),
        "getblockheader" => api.json_get(&format!("block/{}", arg(args, 0)?)),
        "getblock" => Ok(json!(hex::encode(request(
            minreq::get(format!("{base}/block/{}/raw", arg(args, 0)?)),
            api.timeout,
        )?))),
        "getrawmempool" => api.json_get("mempool/txids"),
        "addressutxos" => api.json_get(&format!("address/{}/utxo", arg(args, 0)?)),
        "gettxout" => api.txout(args),
        "sendrawtransaction" => api.broadcast(args),
        _ => Err(Error::Unsupported(format!(
            "public explorer does not support {method}"
        ))),
    }
}
