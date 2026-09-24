use crate::name::Name;
use bitcoin::{Txid, XOnlyPublicKey, hashes::Hash};
use serde::{Deserialize, Serialize};
use urma_core::{
    error::{Error, ensure},
    format::PublicRecord,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Open,
    Administered,
}

impl Mode {
    fn byte(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Administered => 1,
        }
    }

    fn parse(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Self::Open),
            1 => Ok(Self::Administered),
            other => Err(Error::Unsupported(format!(
                "unsupported registry mode {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub mode: Mode,
    pub expiry_blocks: u32,
    pub reveal_max_blocks: u16,
    pub threshold: u8,
    pub approvers: Vec<XOnlyPublicKey>,
}

impl Genesis {
    pub const RULES: u8 = 2;
    pub const MAX_APPROVERS: usize = 255;
    pub const FIXED_BYTES: usize = 10;

    pub fn validate(&self) -> Result<(), Error> {
        ensure!(
            self.reveal_max_blocks >= 1,
            "reveal_max_blocks must be at least 1"
        );
        ensure!(
            self.expiry_blocks > u32::from(self.reveal_max_blocks),
            "expiry_blocks must exceed reveal_max_blocks"
        );
        match self.mode {
            Mode::Open => {
                ensure!(
                    self.threshold == 0 && self.approvers.is_empty(),
                    "open registries carry no threshold or approvers"
                );
            }
            Mode::Administered => {
                ensure!(
                    !self.approvers.is_empty() && self.approvers.len() <= Self::MAX_APPROVERS,
                    "administered registries need 1..255 approvers"
                );
                ensure!(
                    self.threshold >= 1 && usize::from(self.threshold) <= self.approvers.len(),
                    "threshold must be 1..=approver count"
                );
            }
        }
        ensure!(
            self.approvers
                .windows(2)
                .all(|pair| pair[0].serialize() < pair[1].serialize()),
            "approvers must be unique and ascending"
        );
        Ok(())
    }

    pub fn is_approver(&self, key: &XOnlyPublicKey) -> bool {
        self.approvers.contains(key)
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        bytes.push(Self::RULES);
        bytes.push(self.mode.byte());
        bytes.extend_from_slice(&self.expiry_blocks.to_le_bytes());
        bytes.extend_from_slice(&self.reveal_max_blocks.to_le_bytes());
        bytes.push(self.threshold);
        bytes.push(u8::try_from(self.approvers.len())?);
        for approver in &self.approvers {
            bytes.extend_from_slice(&approver.serialize());
        }
        Ok(())
    }

    fn decode(body: &[u8]) -> Result<Self, Error> {
        ensure!(body.len() >= Self::FIXED_BYTES, "truncated genesis");
        if body[0] != Self::RULES {
            return Err(Error::Unsupported(format!(
                "unsupported registry rules {}",
                body[0]
            )));
        }
        let count = usize::from(body[9]);
        ensure!(
            body.len() == Self::FIXED_BYTES + 32 * count,
            "genesis length does not match the approver count"
        );
        let approvers = body[Self::FIXED_BYTES..]
            .chunks(32)
            .map(XOnlyPublicKey::from_slice)
            .collect::<Result<Vec<XOnlyPublicKey>, bitcoin::secp256k1::Error>>()?;
        let genesis = Self {
            mode: Mode::parse(body[1])?,
            expiry_blocks: u32::from_le_bytes(body[2..6].try_into()?),
            reveal_max_blocks: u16::from_le_bytes(body[6..8].try_into()?),
            threshold: body[8],
            approvers,
        };
        genesis.validate()?;
        Ok(genesis)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerOp {
    pub registry: Txid,
    pub salt: [u8; 16],
    pub name: Name,
    pub target: Txid,
}

impl OwnerOp {
    pub const FIXED_BYTES: usize = 81;

    pub fn is_reserving(&self) -> bool {
        *self.target.as_byte_array() == [0; 32]
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        bytes.extend_from_slice(self.registry.as_byte_array());
        bytes.extend_from_slice(&self.salt);
        bytes.push(u8::try_from(self.name.as_str().len())?);
        bytes.extend_from_slice(self.name.as_str().as_bytes());
        bytes.extend_from_slice(self.target.as_byte_array());
        Ok(())
    }

    fn decode(body: &[u8]) -> Result<Self, Error> {
        ensure!(body.len() >= 49, "truncated owner record");
        let length = usize::from(body[48]);
        ensure!(
            body.len() == Self::FIXED_BYTES + length,
            "owner record length does not match the name length"
        );
        let name = Name::parse(std::str::from_utf8(&body[49..49 + length])?)?;
        Ok(Self {
            registry: Txid::from_byte_array(body[..32].try_into()?),
            salt: body[32..48].try_into()?,
            name,
            target: Txid::from_byte_array(body[49 + length..].try_into()?),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub registry: Txid,
    pub record_txid: Txid,
    pub record_sha256: [u8; 32],
}

impl Approval {
    pub const BODY_BYTES: usize = 96;

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.registry.as_byte_array());
        bytes.extend_from_slice(self.record_txid.as_byte_array());
        bytes.extend_from_slice(&self.record_sha256);
    }

    fn decode(body: &[u8]) -> Result<Self, Error> {
        ensure!(body.len() == Self::BODY_BYTES, "approval must be 97 bytes");
        Ok(Self {
            registry: Txid::from_byte_array(body[..32].try_into()?),
            record_txid: Txid::from_byte_array(body[32..64].try_into()?),
            record_sha256: body[64..].try_into()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameOp {
    pub registry: Txid,
    pub name: Name,
}

impl NameOp {
    pub const FIXED_BYTES: usize = 33;

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        bytes.extend_from_slice(self.registry.as_byte_array());
        bytes.push(u8::try_from(self.name.as_str().len())?);
        bytes.extend_from_slice(self.name.as_str().as_bytes());
        Ok(())
    }

    fn decode(body: &[u8]) -> Result<Self, Error> {
        ensure!(body.len() >= Self::FIXED_BYTES, "truncated name record");
        let length = usize::from(body[32]);
        ensure!(
            body.len() == Self::FIXED_BYTES + length,
            "name record length does not match the name length"
        );
        Ok(Self {
            registry: Txid::from_byte_array(body[..32].try_into()?),
            name: Name::parse(std::str::from_utf8(&body[Self::FIXED_BYTES..])?)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    Genesis(Genesis),
    Claim(OwnerOp),
    Update(OwnerOp),
    Renew(OwnerOp),
    Approve(Approval),
    Suspend(NameOp),
    Restore(NameOp),
}

impl Payload {
    pub const PROFILE: [u8; 8] = *b"URMANAM1";

    pub fn op(&self) -> u8 {
        match self {
            Self::Genesis(..) => 0,
            Self::Claim(..) => 1,
            Self::Update(..) => 2,
            Self::Renew(..) => 3,
            Self::Approve(..) => 4,
            Self::Suspend(..) => 5,
            Self::Restore(..) => 6,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![self.op()];
        match self {
            Self::Genesis(genesis) => genesis.encode(&mut bytes)?,
            Self::Claim(op) | Self::Update(op) | Self::Renew(op) => op.encode(&mut bytes)?,
            Self::Approve(approval) => approval.encode(&mut bytes),
            Self::Suspend(op) | Self::Restore(op) => op.encode(&mut bytes)?,
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Some((op, body)) = bytes.split_first() else {
            return Err(Error::Invalid("empty names payload".into()));
        };
        match *op {
            0 => Ok(Self::Genesis(Genesis::decode(body)?)),
            1 => Ok(Self::Claim(OwnerOp::decode(body)?)),
            2 => Ok(Self::Update(OwnerOp::decode(body)?)),
            3 => Ok(Self::Renew(OwnerOp::decode(body)?)),
            4 => Ok(Self::Approve(Approval::decode(body)?)),
            5 => Ok(Self::Suspend(NameOp::decode(body)?)),
            6 => Ok(Self::Restore(NameOp::decode(body)?)),
            other => Err(Error::Unsupported(format!(
                "unsupported names op {other:02x}"
            ))),
        }
    }

    pub fn to_record(&self) -> Result<PublicRecord, Error> {
        Ok(PublicRecord::ProfileRecord {
            profile: Self::PROFILE,
            payload: self.encode()?,
        })
    }

    pub fn from_record(record: &PublicRecord) -> Result<Self, Error> {
        match record {
            PublicRecord::ProfileRecord { profile, payload } if *profile == Self::PROFILE => {
                Self::decode(payload)
            }
            other => Err(Error::Unsupported(format!(
                "kind {:02x} record is not an URMANAM1 record",
                other.kind().byte()
            ))),
        }
    }
}
