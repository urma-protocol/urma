use crate::error::{Context, Error, ensure};
use urma_chain::observation::Chain;

#[derive(Clone, Debug)]
pub enum PublicEndpoint {
    Rpc(String),
    Esplora(String),
    Electrum(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Tls,
    PlainTcp,
}

#[derive(Clone, Debug)]
pub struct ElectrumTarget {
    pub host: String,
    pub port: u16,
    pub wire: Wire,
}

impl PublicEndpoint {
    pub fn url(&self) -> &str {
        match self {
            Self::Rpc(url) | Self::Esplora(url) | Self::Electrum(url) => url,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(self.url())?;
        ensure!(
            url.username().is_empty()
                && url.password().iter().count() == 0
                && url.query().iter().count() == 0
                && url.fragment().iter().count() == 0,
            "public sources never accept embedded credentials"
        );
        match self {
            Self::Rpc(_) | Self::Esplora(_) => {
                ensure!(url.scheme() == "https", "public sources require HTTPS");
            }
            Self::Electrum(_) => {
                self.electrum_target()?;
            }
        }
        Ok(())
    }

    pub fn electrum_target(&self) -> Result<ElectrumTarget, Error> {
        let url = url::Url::parse(self.url())?;
        let wire = match url.scheme() {
            "ssl" => Wire::Tls,
            "tcp" => Wire::PlainTcp,
            scheme => {
                return Err(Error::Invalid(format!(
                    "electrum endpoints use ssl:// or tcp://, not {scheme}://"
                )));
            }
        };
        ensure!(
            url.path().is_empty() || url.path() == "/",
            "electrum endpoints carry no path"
        );
        let host = url.host_str().context("electrum endpoint host missing")?;
        ensure!(
            host.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "electrum endpoint host must be a DNS name or IPv4 address"
        );
        Ok(ElectrumTarget {
            host: host.to_owned(),
            port: url.port().context("electrum endpoint port missing")?,
            wire,
        })
    }
}

pub fn defaults(chain: Chain) -> Vec<PublicEndpoint> {
    match chain {
        Chain::LitecoinMainnet => vec![
            PublicEndpoint::Electrum("ssl://electrum.ltc.xurious.com:50002".into()),
            PublicEndpoint::Electrum("ssl://electrum-ltc.bysh.me:50002".into()),
            PublicEndpoint::Electrum("ssl://backup.electrum-ltc.org:443".into()),
            PublicEndpoint::Electrum("ssl://electrum1.cipig.net:20063".into()),
            PublicEndpoint::Esplora("https://litecoinspace.org/api".into()),
            PublicEndpoint::Rpc("https://litecoin-mainnet.gateway.tatum.io".into()),
        ],
        Chain::LitecoinTestnet => vec![
            PublicEndpoint::Electrum("ssl://electrum-ltc.bysh.me:51002".into()),
            PublicEndpoint::Electrum("ssl://electrum.ltc.xurious.com:51002".into()),
            PublicEndpoint::Esplora("https://litecoinspace.org/testnet/api".into()),
            PublicEndpoint::Rpc("https://litecoin-testnet.gateway.tatum.io".into()),
        ],
        Chain::BitcoinTestnet4 => vec![PublicEndpoint::Esplora(
            "https://mempool.space/testnet4/api".into(),
        )],
        Chain::BitcoinRegtest => Vec::new(),
    }
}
