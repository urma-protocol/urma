use crate::{endpoints::PublicEndpoint, esplora};
use bitcoin::{Block, Transaction, consensus::deserialize};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    io::Read,
    time::{Duration, Instant},
};
use urma::error::{Context, Error, ensure};
use urma_chain::observation::Chain;

pub(crate) struct Source {
    endpoint: PublicEndpoint,
    network: Cell<NetworkState>,
    last_request: Cell<Instant>,
    retry_at: Cell<Instant>,
}

#[derive(Clone, Copy)]
enum NetworkState {
    Unchecked,
    Verified,
    Rejected,
}

impl Source {
    pub(crate) fn new(endpoint: PublicEndpoint) -> Result<Self, Error> {
        endpoint.validate()?;
        Ok(Self {
            endpoint,
            network: Cell::new(NetworkState::Unchecked),
            last_request: Cell::new(Instant::now()),
            retry_at: Cell::new(Instant::now()),
        })
    }

    pub(crate) fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        ensure!(
            Instant::now() >= self.retry_at.get(),
            "public source cooling down after rate limit"
        );
        ensure!(
            !matches!(self.network.get(), NetworkState::Rejected),
            "public source network mismatch"
        );
        if matches!(self.network.get(), NetworkState::Unchecked) {
            let genesis = self.request("getblockhash", &[json!(0)])?;
            if genesis != json!(chain.genesis()?.0.to_string()) {
                self.network.set(NetworkState::Rejected);
                return Err(Error::Invalid("public source network mismatch".into()));
            }
            let tip = self.request("getblockchaininfo", &[])?;
            ensure!(
                tip["initialblockdownload"] == false,
                "public source is still synchronizing"
            );
            self.network.set(NetworkState::Verified);
        }
        let value = self.request(method, args)?;
        validate_result(method, args, &value)?;
        Ok(value)
    }

    fn request(&self, method: &str, args: &[Value]) -> Result<Value, Error> {
        pace(self.last_request.get());
        self.last_request.set(Instant::now());
        let result = self.request_unchecked(method, args);
        match result {
            Err(Error::Io(cause)) if cause.kind() == std::io::ErrorKind::WouldBlock => {
                self.retry_at.set(Instant::now() + Duration::from_secs(60));
                Err(Error::Io(cause))
            }
            Ok(value) => Ok(value),
            Err(cause) => Err(cause),
        }
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
                )?;
                let response: Value = serde_json::from_slice(&bytes)?;
                if !response["error"].is_null() {
                    if response["error"]["code"] == -5 {
                        return Err(Error::Missing(
                            "transaction not found on selected network".into(),
                        ));
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

pub(crate) fn request(request: minreq::Request) -> Result<Vec<u8>, Error> {
    let request = request
        .with_header("User-Agent", "urma/0.1")
        .with_timeout(12)
        .with_max_redirects(0);
    let response = request.send_lazy()?;
    if response.status_code == 429 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "public source rate limited; retry after one minute",
        )));
    }
    if response.status_code == 404 {
        return Err(Error::Missing(
            "transaction or block not found on selected network".into(),
        ));
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

fn validate_result(method: &str, args: &[Value], value: &Value) -> Result<(), Error> {
    if method == "getrawtransaction"
        && args.get(1).context("missing transaction verbosity")? == &json!(false)
    {
        let raw = hex::decode(value.as_str().context("missing transaction bytes")?)?;
        let transaction: Transaction = deserialize(&raw)?;
        ensure!(
            json!(transaction.compute_txid()) == *args.first().context("missing transaction ID")?,
            "public source transaction hash mismatch"
        );
    }
    if method == "getblock" {
        let raw = hex::decode(value.as_str().context("missing block bytes")?)?;
        let block: Block = deserialize(&raw)?;
        ensure!(
            json!(block.block_hash()) == *args.first().context("missing block hash")?,
            "public source block hash mismatch"
        );
        ensure!(
            block.check_merkle_root(),
            "public source block merkle root mismatch"
        );
    }
    Ok(())
}

fn pace(last: Instant) {
    let delay = match Duration::from_millis(300).checked_sub(last.elapsed()) {
        Some(delay) => delay,
        None => return,
    };
    std::thread::sleep(delay);
}
