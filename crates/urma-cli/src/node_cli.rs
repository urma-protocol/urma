use crate::public_cli::PublicChain;
use clap::Args;
use std::path::PathBuf;
use urma::error::Error;
use urma_runtime::node::{Node, NodeConfig};

#[derive(Args)]
pub(crate) struct NodeArgs {
    #[arg(long, value_enum, default_value = "litecoin-testnet")]
    pub(crate) chain: PublicChain,
    #[arg(long)]
    pub(crate) rpc_url: String,
    #[arg(long)]
    pub(crate) cookie: PathBuf,
}
impl NodeArgs {
    pub(crate) fn connect(&self) -> Result<Node, Error> {
        Node::connect(NodeConfig {
            chain: self.chain.into(),
            rpc_url: self.rpc_url.clone(),
            cookie_file: self.cookie.clone(),
        })
    }
}
