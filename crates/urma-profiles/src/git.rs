use bitcoin::Txid;
use urma_chain::observation::ChainId;
use urma_core::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLocator {
    pub chain: ChainId,
    pub root: Txid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitProfile {
    Unnamed,
    Named,
}
impl GitProfile {
    pub const UNNAMED_IDENTIFIER: [u8; 8] = *b"URMAGIT0";
    pub const NAMED_IDENTIFIER: [u8; 8] = *b"URMAGIT1";

    pub fn for_name(name: &str) -> Self {
        if name.is_empty() {
            Self::Unnamed
        } else {
            Self::Named
        }
    }

    pub fn identifier(self) -> [u8; 8] {
        match self {
            Self::Unnamed => Self::UNNAMED_IDENTIFIER,
            Self::Named => Self::NAMED_IDENTIFIER,
        }
    }

    pub fn revision(self) -> u8 {
        match self {
            Self::Unnamed => 0,
            Self::Named => 1,
        }
    }

    pub fn from_revision(revision: u8) -> Result<Self, Error> {
        match revision {
            0 => Ok(Self::Unnamed),
            1 => Ok(Self::Named),
            _ => Err(Error::Unsupported(format!(
                "Git descriptor revision {revision}"
            ))),
        }
    }
}
