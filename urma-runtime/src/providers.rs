#[cfg(not(target_arch = "wasm32"))]
use crate::electrum::Electrum;
use crate::endpoints::PublicEndpoint;
use crate::error::Error;
use crate::light::LightSync;
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

pub enum LightClient {
    Absent,
    #[cfg(not(target_arch = "wasm32"))]
    P2p(Arc<P2pProvider>),
}

impl LightClient {
    pub(crate) fn providers(&self) -> Vec<Box<dyn Provider>> {
        match self {
            Self::Absent => Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            Self::P2p(provider) => vec![Box::new(provider.clone())],
        }
    }

    pub(crate) fn state(&self) -> LightSync {
        match self {
            Self::Absent => LightSync::Absent,
            #[cfg(not(target_arch = "wasm32"))]
            Self::P2p(provider) => provider.state(),
        }
    }

    pub(crate) fn warm(&self) -> Result<(), Error> {
        match self {
            Self::Absent => {
                tracing::debug!("no light client to warm");
                Ok(())
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::P2p(provider) => provider.warm(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn light_clients(chain: Chain, cache_dir: &Path) -> Result<LightClient, Error> {
    match chain {
        Chain::LitecoinMainnet | Chain::LitecoinTestnet => Ok(LightClient::P2p(Arc::new(
            P2pProvider::new(chain, cache_dir)?,
        ))),
        Chain::BitcoinRegtest | Chain::BitcoinTestnet4 => {
            tracing::debug!(
                ?chain,
                "no light client provider for this chain; reads start at public providers"
            );
            Ok(LightClient::Absent)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn assemble(
    endpoints: Vec<PublicEndpoint>,
    pins: Arc<Pins>,
    light: &LightClient,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    let mut providers = light.providers();
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
    assemble(endpoints, Arc::new(Pins::ephemeral()), &LightClient::Absent)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn ephemeral(
    chain: Chain,
    endpoints: Vec<PublicEndpoint>,
) -> Result<Vec<Box<dyn Provider>>, Error> {
    tracing::debug!(?chain, "no light client provider on WASM");
    let mut providers = LightClient::Absent.providers();
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
