use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Chain {
    BitcoinRegtest,
    BitcoinTestnet4,
    LitecoinMainnet,
    LitecoinTestnet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainId(pub BlockHash);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub height: u64,
    pub hash: BlockHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Unknown,
    Mempool,
    Included(BlockRef),
    Orphaned(BlockRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InclusionTrust {
    ProviderClaim,
    ValidatingNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub chain: ChainId,
    pub txid: Txid,
    pub tip: BlockRef,
    pub placement: Placement,
    pub trust: InclusionTrust,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainUpdate {
    Advanced {
        previous: BlockRef,
        tip: BlockRef,
    },
    Reorganized {
        previous: BlockRef,
        ancestor: BlockRef,
        tip: BlockRef,
    },
}

impl Chain {
    pub fn label(self) -> &'static str {
        match self {
            Self::LitecoinMainnet => "Litecoin mainnet",
            Self::LitecoinTestnet => "Litecoin testnet",
            Self::BitcoinRegtest => "Bitcoin regtest",
            Self::BitcoinTestnet4 => "Bitcoin testnet4",
        }
    }

    pub fn genesis(self) -> Result<ChainId, bitcoin::hex::HexToArrayError> {
        let genesis = match self {
            Self::BitcoinRegtest => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash()
            }
            Self::BitcoinTestnet4 => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet4)
                    .block_hash()
            }
            Self::LitecoinMainnet => {
                "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2".parse()?
            }
            Self::LitecoinTestnet => {
                "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0".parse()?
            }
        };
        Ok(ChainId(genesis))
    }
}
