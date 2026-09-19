use crate::{endpoints::PublicEndpoint, remote::Source};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender, TrySendError},
};
use urma::error::{Error, ensure};
use urma_chain::observation::Chain;

pub(crate) struct Pool {
    workers: Vec<SyncSender<Request>>,
}

struct Request {
    chain: Chain,
    method: Arc<str>,
    args: Arc<[Value]>,
    cancelled: Arc<AtomicBool>,
    response: SyncSender<Result<Value, Error>>,
}

impl Pool {
    pub(crate) fn new(endpoints: Vec<PublicEndpoint>) -> Result<Self, Error> {
        ensure!(
            !endpoints.is_empty() && endpoints.len() <= 8,
            "public transport requires between one and eight providers"
        );
        let mut workers = Vec::new();
        for endpoint in endpoints {
            let source = Source::new(endpoint)?;
            let (sender, receiver) = mpsc::sync_channel::<Request>(8);
            std::thread::Builder::new()
                .name("urma-provider".into())
                .spawn(move || {
                    for request in receiver {
                        if request.cancelled.load(Ordering::Acquire) {
                            continue;
                        }
                        let result = source.call(request.chain, &request.method, &request.args);
                        if request.cancelled.load(Ordering::Acquire) {
                            continue;
                        }
                        match request.response.send(result) {
                            Ok(()) => (),
                            Err(error) => tracing::warn!(%error, "public request completed after another provider won"),
                        }
                    }
                })?;
            workers.push(sender);
        }
        Ok(Self { workers })
    }

    pub(crate) fn call(&self, chain: Chain, method: &str, args: &[Value]) -> Result<Value, Error> {
        ensure!(
            matches!(
                method,
                "getblockhash"
                    | "getblockchaininfo"
                    | "getrawtransaction"
                    | "getblockheader"
                    | "getblock"
                    | "getrawmempool"
                    | "gettxout"
                    | "addressutxos"
                    | "testmempoolaccept"
                    | "sendrawtransaction"
            ),
            "public transport supports chain reads and signed transaction submission only"
        );
        let (sender, receiver) = mpsc::sync_channel(self.workers.len());
        let cancelled = Arc::new(AtomicBool::new(false));
        let method: Arc<str> = method.into();
        let args: Arc<[Value]> = args.into();
        let mut queued = 0;
        for worker in &self.workers {
            let request = Request {
                chain,
                method: method.clone(),
                args: args.clone(),
                cancelled: cancelled.clone(),
                response: sender.clone(),
            };
            match worker.try_send(request) {
                Ok(()) => queued += 1,
                Err(error @ TrySendError::Full(_)) => {
                    tracing::warn!(%error, "public provider queue busy")
                }
                Err(error @ TrySendError::Disconnected(_)) => {
                    tracing::warn!(%error, "public provider stopped")
                }
            }
        }
        drop(sender);
        let mut failures = Vec::new();
        let mut missing = 0;
        for response in receiver {
            match response {
                Ok(value) => {
                    cancelled.store(true, Ordering::Release);
                    return Ok(value);
                }
                Err(Error::Missing(message)) => {
                    tracing::warn!(%message, "record absent from one provider");
                    missing += 1;
                    failures.push(message);
                }
                Err(error) => {
                    tracing::warn!(%error, "public provider unavailable");
                    failures.push(error.to_string());
                }
            }
        }
        cancelled.store(true, Ordering::Release);
        let message = format!(
            "{method} on {chain:?}: {}. Retry or configure a local node; check --testnet for test data.",
            failures.join("; ")
        );
        if queued > 0 && missing > 0 {
            return Err(Error::Missing(message));
        }
        Err(Error::Unsupported(message))
    }
}
