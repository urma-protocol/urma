use crate::config;
use crate::error::{Context, Error, ensure};
use crate::transaction::decode;
use crate::transport::{BlockEncoding, Evidence, Provider};
use crate::{endpoints::PublicEndpoint, esplora};
use bitcoin::{Amount, BlockHash, Denomination, Txid};
use serde_json::{Value, json};
use std::{
    io::Read,
    sync::Mutex,
    time::{Duration, Instant},
};
use urma_chain::{
    decode::{self as chain_decode, DecodeError},
    observation::Chain,
    validation::BlockValidationError,
};

pub(crate) struct Remote {
    endpoint: PublicEndpoint,
    source: Mutex<Source>,
}

struct Source {
    endpoint: PublicEndpoint,
    network: NetworkState,
    last_request: Instant,
    retry_at: Instant,
    window_start: Instant,
    window_requests: u8,
}

#[derive(Clone, Copy)]
enum NetworkState {
    Unchecked,
    Verified,
    Rejected,
}

impl Remote {
    pub(crate) fn new(endpoint: PublicEndpoint) -> Result<Self, Error> {
        endpoint.validate()?;
        Ok(Self {
            endpoint: endpoint.clone(),
            source: Mutex::new(Source {
                endpoint,
                network: NetworkState::Unchecked,
                last_request: Instant::now(),
                retry_at: Instant::now(),
                window_start: Instant::now(),
                window_requests: 0,
            }),
        })
    }
}

impl Provider for Remote {
    fn label(&self) -> String {
        self.endpoint.url().to_owned()
    }

    fn evidence(&self) -> Evidence {
        Evidence::PublicProviderObservation
    }

    fn block_encoding(&self) -> BlockEncoding {
        match self.endpoint {
            PublicEndpoint::Rpc(_) => BlockEncoding::Core,
            PublicEndpoint::Esplora(_) => BlockEncoding::Esplora,
        }
    }

    fn supports(&self, method: &str) -> bool {
        match self.endpoint {
            PublicEndpoint::Rpc(_) => method != "addressutxos",
            PublicEndpoint::Esplora(_) => method != "testmempoolaccept",
        }
    }

    fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        let mut source = match self.source.lock() {
            Ok(source) => source,
            Err(poisoned) => {
                tracing::error!(endpoint = %self.endpoint.url(), "public source lock poisoned");
                poisoned.into_inner()
            }
        };
        source.call(chain, method, args)
    }
}

impl Source {
    fn call(&mut self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        let now = Instant::now();
        if now < self.retry_at {
            return Err(Error::RateLimited(self.retry_at.duration_since(now)));
        }
        ensure!(
            !matches!(self.network, NetworkState::Rejected),
            "public source network mismatch"
        );
        if matches!(self.network, NetworkState::Unchecked) {
            let genesis = self.request("getblockhash", &[json!(0)])?;
            if genesis != json!(chain.genesis()?.0.to_string()) {
                self.network = NetworkState::Rejected;
                return Err(Error::Invalid("public source network mismatch".into()));
            }
            let tip = self.request("getblockchaininfo", &[])?;
            validate_shape("getblockchaininfo", &tip)?;
            self.network = NetworkState::Verified;
        }
        if method == "getblockhash" && args.first().context("missing block height")? == &json!(0) {
            return Ok(json!(chain.genesis()?.0.to_string()));
        }
        self.request(method, args)
    }

    fn request(&mut self, method: &str, args: &[Value]) -> Result<Value, Error> {
        self.reserve_request()?;
        pace(self.last_request);
        self.last_request = Instant::now();
        let result = self.request_unchecked(method, args);
        match result {
            Err(Error::RateLimited(wait)) => {
                self.retry_at = Instant::now() + wait;
                Err(Error::RateLimited(wait))
            }
            Ok(value) => Ok(value),
            Err(cause) => Err(cause),
        }
    }

    fn reserve_request(&mut self) -> Result<(), Error> {
        if self.endpoint.url().contains(".gateway.tatum.io") {
            let elapsed = self.window_start.elapsed();
            if elapsed >= config::RPC_GATEWAY_WINDOW {
                self.window_start = Instant::now();
                self.window_requests = 0;
            }
            if self.window_requests >= config::RPC_GATEWAY_WINDOW_REQUESTS {
                let Some(remaining) = config::RPC_GATEWAY_WINDOW.checked_sub(elapsed) else {
                    return Err(Error::Invalid(
                        "public RPC window accounting overflow".into(),
                    ));
                };
                return Err(Error::RateLimited(remaining));
            }
            self.window_requests += 1;
        }
        Ok(())
    }

    fn request_unchecked(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        match &self.endpoint {
            PublicEndpoint::Esplora(url) => esplora::call(url, method, args),
            PublicEndpoint::Rpc(url) => {
                let bytes = request(
                    minreq::post(url)
                        .with_header("Content-Type", "application/json")
                        .with_body(serde_json::to_vec(
                            &json!({"jsonrpc":"2.0","id":1,"method":method,"params":args}),
                        )?),
                    config::method_timeout(method),
                )?;
                let response: Value = serde_json::from_slice(&bytes)?;
                if !response["error"].is_null() {
                    if response["error"]["code"] == -5 {
                        return Err(Error::Missing(config::ABSENT_TRANSACTION.into()));
                    }
                    return Err(Error::Unsupported(format!(
                        "public RPC {method} failed (code {})",
                        response["error"]["code"]
                    )));
                }
                Ok(response
                    .get("result")
                    .context("public RPC omitted result")?
                    .clone())
            }
        }
    }
}

pub(crate) fn request(request: minreq::Request, timeout: Duration) -> Result<Vec<u8>, Error> {
    let request = request
        .with_header("User-Agent", "urma/0.2")
        .with_timeout(timeout.as_secs().max(1))
        .with_max_redirects(0);
    let response = request.send_lazy()?;
    if response.status_code == 429 {
        return Err(Error::RateLimited(retry_after(&response)));
    }
    if response.status_code == 404 {
        return Err(Error::Missing(config::ABSENT_RECORD.into()));
    }
    ensure!(
        response.status_code == 200,
        "public source returned HTTP {}",
        response.status_code
    );
    let mut bytes = Vec::new();
    Read::take(response, 32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "public response exceeds capacity"
    );
    Ok(bytes)
}

fn retry_after(response: &minreq::ResponseLazy) -> Duration {
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("retry-after") {
            return retry_after_value(value);
        }
    }
    config::PROVIDER_RETRY_DEFAULT
}

fn retry_after_value(value: &str) -> Duration {
    match value.trim().parse::<u64>() {
        Ok(seconds) => {
            Duration::from_secs(seconds).clamp(Duration::from_secs(1), config::PROVIDER_RETRY_MAX)
        }
        Err(error) => {
            tracing::warn!(%error, value, "unparseable Retry-After header; using default cooldown");
            config::PROVIDER_RETRY_DEFAULT
        }
    }
}

pub(crate) fn validate_result(
    encoding: BlockEncoding,
    chain: Chain,
    method: &str,
    args: &[Value],
    value: Value,
) -> Result<Value, Error> {
    validate_shape(method, &value)?;
    if method == "getrawtransaction"
        && args.get(1).context("missing transaction verbosity")? == &json!(true)
    {
        validate_confirmations(&value)?;
    }
    if method == "getrawtransaction"
        && args.get(1).context("missing transaction verbosity")? == &json!(false)
    {
        let raw = value.as_str().context("missing transaction bytes")?;
        let transaction = chain_decode::transaction(&hex::decode(raw)?, chain)?;
        ensure!(
            json!(transaction.compute_txid()) == *args.first().context("missing transaction ID")?,
            "public source transaction hash mismatch"
        );
    }
    if method == "sendrawtransaction" {
        let raw = args.first().context("missing broadcast transaction")?;
        let raw = raw.as_str().context("invalid broadcast transaction")?;
        let transaction = decode(raw, raw.len())?;
        ensure!(
            value == json!(transaction.compute_txid()),
            "broadcast transaction ID mismatch"
        );
    }
    if method == "getblock" {
        validate_block(encoding, chain, args, &value)?;
    }
    Ok(value)
}

fn validate_block(
    encoding: BlockEncoding,
    chain: Chain,
    args: &[Value],
    value: &Value,
) -> Result<(), Error> {
    let raw = hex::decode(value.as_str().context("missing block bytes")?)?;
    let expected_hash = args
        .first()
        .context("missing block hash")?
        .as_str()
        .context("invalid block hash")?
        .parse()?;
    let decoded = match encoding {
        BlockEncoding::Core => chain_decode::block(&raw, chain, expected_hash),
        BlockEncoding::Esplora => chain_decode::esplora_block(&raw, chain, expected_hash),
    };
    decoded.map_err(|cause| match cause {
        DecodeError::Integrity(BlockValidationError::HashMismatch) => {
            Error::Invalid("public source block hash mismatch".into())
        }
        DecodeError::Integrity(BlockValidationError::MerkleRootMismatch) => {
            Error::Invalid("public source block merkle root mismatch".into())
        }
        cause => Error::from(cause),
    })?;
    Ok(())
}

fn block_hash(value: &Value) -> Result<(), Error> {
    value
        .as_str()
        .context("missing public block hash")?
        .parse::<BlockHash>()?;
    Ok(())
}

fn validate_confirmations(value: &Value) -> Result<(), Error> {
    let count = value["confirmations"]
        .as_i64()
        .context("invalid public confirmation count")?;
    if count > 0 {
        block_hash(&value["blockhash"])?;
    }
    Ok(())
}

fn validate_shape(method: &str, value: &Value) -> Result<(), Error> {
    match method {
        "getblockhash" => block_hash(value)?,
        "getblockchaininfo" => {
            value["blocks"]
                .as_u64()
                .context("invalid public chain height")?;
            block_hash(&value["bestblockhash"])?;
            ensure!(
                value["initialblockdownload"] == false,
                "public source is synchronizing or omitted synchronization state"
            );
        }
        "getblockheader" => {
            value["height"]
                .as_u64()
                .context("invalid public block height")?;
        }
        "getrawmempool" => {
            let rows = value.as_array().context("invalid public mempool list")?;
            ensure!(
                rows.len() <= 1_000_000,
                "public mempool response exceeds capacity"
            );
            for row in rows {
                row.as_str()
                    .context("invalid public mempool txid")?
                    .parse::<Txid>()?;
            }
        }
        "addressutxos" => validate_utxos(value)?,
        "gettxout" => validate_output(value)?,
        "testmempoolaccept" => {
            let rows = value
                .as_array()
                .context("invalid public preflight result")?;
            ensure!(rows.len() == 1, "invalid public preflight count");
            rows[0]["allowed"]
                .as_bool()
                .context("missing public preflight decision")?;
        }
        _ => (),
    }
    Ok(())
}

fn validate_utxos(value: &Value) -> Result<(), Error> {
    let rows = value.as_array().context("invalid public UTXO list")?;
    ensure!(
        rows.len() <= config::SOURCE_MAX_UTXOS,
        "UTXO client capacity exceeded"
    );
    for row in rows {
        row["txid"]
            .as_str()
            .context("missing public UTXO txid")?
            .parse::<Txid>()?;
        u32::try_from(row["vout"].as_u64().context("invalid public UTXO index")?)?;
        row["value"].as_u64().context("invalid public UTXO value")?;
        let confirmed = row["status"]["confirmed"]
            .as_bool()
            .context("invalid public UTXO status")?;
        if confirmed {
            row["status"]["block_height"]
                .as_u64()
                .context("invalid public UTXO height")?;
        }
    }
    Ok(())
}

fn validate_output(value: &Value) -> Result<(), Error> {
    if value.is_null() {
        return Ok(());
    }
    value["confirmations"]
        .as_u64()
        .context("invalid public output confirmations")?;
    value["coinbase"]
        .as_bool()
        .context("invalid public coinbase status")?;
    Amount::from_str_in(&value["value"].to_string(), Denomination::Bitcoin)?;
    let script = value["scriptPubKey"]["hex"]
        .as_str()
        .context("invalid public output script")?;
    ensure!(
        script.len() <= 20_000,
        "public output script exceeds capacity"
    );
    hex::decode(script)?;
    Ok(())
}

fn pace(last: Instant) {
    let delay = match config::PROVIDER_PACING.checked_sub(last.elapsed()) {
        Some(delay) => delay,
        None => return,
    };
    std::thread::sleep(delay);
}
