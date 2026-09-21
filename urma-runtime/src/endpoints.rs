use crate::error::{Error, ensure};
use urma_chain::observation::Chain;

#[derive(Clone, Debug)]
pub enum PublicEndpoint {
    Rpc(String),
    Esplora(String),
}

impl PublicEndpoint {
    pub fn url(&self) -> &str {
        match self {
            Self::Rpc(url) | Self::Esplora(url) => url,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(self.url())?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().iter().count() == 0
                && url.query().iter().count() == 0
                && url.fragment().iter().count() == 0,
            "public sources require HTTPS without embedded credentials"
        );
        Ok(())
    }
}

pub fn defaults(chain: Chain) -> Vec<PublicEndpoint> {
    match chain {
        Chain::LitecoinMainnet => vec![
            PublicEndpoint::Esplora("https://litecoinspace.org/api".into()),
            PublicEndpoint::Rpc("https://litecoin-mainnet.gateway.tatum.io".into()),
        ],
        Chain::LitecoinTestnet => vec![
            PublicEndpoint::Esplora("https://litecoinspace.org/testnet/api".into()),
            PublicEndpoint::Esplora("https://testnetscan.com/ltc-testnet/api".into()),
            PublicEndpoint::Rpc("https://litecoin-testnet.gateway.tatum.io".into()),
        ],
        Chain::BitcoinTestnet4 => vec![PublicEndpoint::Esplora(
            "https://mempool.space/testnet4/api".into(),
        )],
        Chain::BitcoinRegtest => Vec::new(),
    }
}
