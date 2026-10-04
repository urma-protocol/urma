#[cfg(not(target_arch = "wasm32"))]
use crate::electrum::Electrum;
use crate::endpoints::PublicEndpoint;
use crate::error::Error;
#[cfg(not(target_arch = "wasm32"))]
use crate::p2p::P2pProvider;
#[cfg(not(target_arch = "wasm32"))]
use crate::pinning::Pins;
use crate::remote::Remote;
use crate::transport::Provider;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use urma_chain::observation::Chain;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn light_clients(
    chain: Chain,
    cache_dir: &Path,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    match chain {
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => {
            Ok(vec![Box::new(P2pProvider::new(chain, cache_dir)?)])
        }
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => {
            tracing::debug!(
                ?chain,
                "no light client provider for this chain; reads start at public providers"
            );
            Ok(Vec::new())
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn light_clients(chain: Chain) -> Vec<Box<dyn Provider>> {
    tracing::debug!(
        ?chain,
        "no light client provider on WASM; reads start at public providers"
    );
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn assemble(
    endpoints: Vec<PublicEndpoint>,
    pins: Arc<Pins>,
    light: Vec<Box<dyn Provider>>,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    let mut providers = light;
    for endpoint in endpoints {
        let provider: Box<dyn Provider> = match endpoint {
            PublicEndpoint::Electrum(_) => Box::new(Electrum::new(endpoint, pins.clone())?),
            PublicEndpoint::Rpc(_) | PublicEndpoint::Esplora(_) => Box::new(Remote::new(endpoint)?),
        };
        providers.push(provider);
    }
    Ok(providers)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn ephemeral(
    chain: Chain,
    endpoints: Vec<PublicEndpoint>,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    tracing::debug!(
        ?chain,
        "ephemeral public node has no cache directory; no light client"
    );
    assemble(endpoints, Arc::new(Pins::ephemeral()), Vec::new())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn ephemeral(
    chain: Chain,
    endpoints: Vec<PublicEndpoint>,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    let mut providers = light_clients(chain);
    for endpoint in endpoints {
        let provider: Box<dyn Provider> = match endpoint {
            PublicEndpoint::Electrum(url) => {
                return Err(Error::Unsupported(format!(
                    "electrum endpoint {url} needs a TCP socket, unavailable on WASM"
                )));
            }
            PublicEndpoint::Rpc(_) | PublicEndpoint::Esplora(_) => Box::new(Remote::new(endpoint)?),
        };
        providers.push(provider);
    }
    Ok(providers)
}
