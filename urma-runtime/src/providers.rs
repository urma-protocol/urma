#[cfg(not(target_arch = "wasm32"))]
use crate::electrum::{Electrum, Pins};
use crate::endpoints::PublicEndpoint;
use crate::error::Error;
use crate::remote::Remote;
use crate::transport::Provider;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use urma_chain::observation::Chain;

fn light_clients(chain: Chain) -> Vec<Box<dyn Provider>> {
    tracing::debug!(
        ?chain,
        "no light client provider registered; reads start at public providers"
    );
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn assemble(
    chain: Chain,
    endpoints: Vec<PublicEndpoint>,
    pins: Arc<Pins>,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    let mut providers = light_clients(chain);
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
    assemble(chain, endpoints, Arc::new(Pins::ephemeral()))
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
