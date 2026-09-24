use crate::config;
use clap::Args;
use urma_chain::observation::Chain;
use urma_runtime::error::{Context, Error};
use urma_runtime::node::Node;

#[derive(Args)]
pub(crate) struct NodeArgs {
    #[arg(long, help = "Use Litecoin testnet instead of mainnet")]
    testnet: bool,
}

impl NodeArgs {
    pub(crate) fn chain(&self) -> Result<Chain, Error> {
        config::chain(self.testnet)
    }

    pub(crate) fn connect(&self) -> Result<Node, Error> {
        let chain = self.chain()?;
        match config::connection(chain)? {
            config::Connection::Local(local) => Node::connect(local),
            config::Connection::Public => Node::public(chain),
        }
    }
}

pub(crate) fn chain_name(chain: Chain) -> Result<String, Error> {
    Ok(serde_json::to_value(chain)?
        .as_str()
        .context("chain name")?
        .to_owned())
}
