use crate::{
    error::{Error, ensure},
    format::RecordKind,
};
use bitcoin::{Txid, hashes::Hash};
use sha2::{Digest, Sha256};

mod consistency;
mod inventory;
mod proof;
pub use consistency::MultipartConsistency;
pub use inventory::ManifestInventory;
pub use proof::{RecordRequest, VerifiedRecord};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    length: u64,
    parts: u32,
    leaves: u16,
}

impl Geometry {
    pub const RECORD_BYTES: usize = 256 * 1024;
    pub const DATA_BYTES: usize = Self::RECORD_BYTES - 12;
    pub const FANOUT: u16 = 511;
    pub const MAX_PARTS: u32 = 32_630;
    pub const MAX_OBJECT_BYTES: u64 = 8_553_279_476;
    pub const MAX_NODES: u32 = 32_695;

    pub fn new(length: u64) -> Result<Self, Error> {
        ensure!(
            length <= Geometry::MAX_OBJECT_BYTES,
            "multipart length outside bounds"
        );
        let parts = u32::try_from(length.div_ceil(u64::try_from(Geometry::DATA_BYTES)?).max(1))?;
        let leaves = u16::try_from(parts.div_ceil(u32::from(Geometry::FANOUT)))?;
        Ok(Self {
            length,
            parts,
            leaves,
        })
    }

    pub fn length(self) -> u64 {
        self.length
    }
    pub fn parts(self) -> u32 {
        self.parts
    }
    pub fn leaves(self) -> u16 {
        self.leaves
    }
    pub fn nodes(self) -> u32 {
        self.parts + u32::from(self.leaves) + 1
    }

    pub fn part_length(self, index: u32) -> Result<usize, Error> {
        ensure!(index < self.parts, "part index outside object");
        let offset = u64::from(index) * u64::try_from(Geometry::DATA_BYTES)?;
        Ok(usize::try_from(
            (self.length - offset).min(u64::try_from(Geometry::DATA_BYTES)?),
        )?)
    }

    pub fn leaf_entries(self, index: u16) -> Result<u16, Error> {
        ensure!(index < self.leaves, "leaf index outside object");
        Ok(u16::try_from(
            (self.parts - u32::from(index) * u32::from(Geometry::FANOUT))
                .min(u32::from(Geometry::FANOUT)),
        )?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildReference {
    pub txid: Txid,
    pub record_hash: [u8; 32],
}

impl ChildReference {
    pub fn new(txid: Txid, record: &[u8]) -> Result<Self, Error> {
        MultipartRecord::decode(record)?;
        Ok(Self {
            txid,
            record_hash: Sha256::digest(record).into(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPart {
    pub index: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafManifest {
    pub index: u16,
    pub entries: Vec<ChildReference>,
}

impl LeafManifest {
    pub fn first_index(&self) -> u32 {
        u32::from(self.index) * u32::from(Geometry::FANOUT)
    }

    pub fn validate(&self) -> Result<(), Error> {
        ensure!(self.index < Geometry::FANOUT, "leaf index outside bounds");
        ensure!(
            (1..=usize::from(Geometry::FANOUT)).contains(&self.entries.len()),
            "leaf entry count outside bounds"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootManifest {
    pub length: u64,
    pub payload_hash: [u8; 32],
    pub profile: [u8; 8],
    pub entries: Vec<ChildReference>,
}

impl RootManifest {
    pub fn geometry(&self) -> Result<Geometry, Error> {
        let geometry = Geometry::new(self.length)?;
        ensure!(
            self.entries.len() == usize::from(geometry.leaves()),
            "root leaf count disagrees with length"
        );
        Ok(geometry)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultipartRecord {
    Data(DataPart),
    Leaf(LeafManifest),
    Root(RootManifest),
}

impl MultipartRecord {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Data(_) => RecordKind::DataPart,
            Self::Leaf(_) => RecordKind::LeafManifest,
            Self::Root(_) => RecordKind::RootManifest,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.kind().prefix().to_vec();
        match self {
            Self::Data(part) => {
                ensure!(
                    part.index < Geometry::MAX_PARTS,
                    "part index outside bounds"
                );
                ensure!(
                    part.payload.len() <= Geometry::DATA_BYTES,
                    "data record exceeds cap"
                );
                bytes.extend_from_slice(&part.index.to_le_bytes());
                bytes.extend_from_slice(&part.payload);
            }
            Self::Leaf(leaf) => {
                leaf.validate()?;
                bytes.extend_from_slice(&leaf.index.to_le_bytes());
                bytes.extend_from_slice(&u16::try_from(leaf.entries.len())?.to_le_bytes());
                bytes.extend_from_slice(&leaf.first_index().to_le_bytes());
                encode_references(&mut bytes, &leaf.entries);
            }
            Self::Root(root) => {
                let geometry = root.geometry()?;
                bytes.extend_from_slice(&root.length.to_le_bytes());
                bytes.extend_from_slice(&root.payload_hash);
                bytes.extend_from_slice(&geometry.parts().to_le_bytes());
                bytes.extend_from_slice(&geometry.leaves().to_le_bytes());
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(&root.profile);
                encode_references(&mut bytes, &root.entries);
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let kind = RecordKind::parse(bytes)?;
        ensure!(
            bytes.len() <= Geometry::RECORD_BYTES,
            "multipart record exceeds cap"
        );
        match kind {
            RecordKind::DataPart => decode_data(bytes),
            RecordKind::LeafManifest => decode_leaf(bytes),
            RecordKind::RootManifest => decode_root(bytes),
            _ => Err(Error::Invalid("not a multipart record".into())),
        }
    }
}

fn encode_references(bytes: &mut Vec<u8>, entries: &[ChildReference]) {
    for entry in entries {
        bytes.extend_from_slice(entry.txid.as_byte_array());
        bytes.extend_from_slice(&entry.record_hash);
    }
}

fn decode_references(bytes: &[u8], count: u16) -> Result<Vec<ChildReference>, Error> {
    ensure!(
        (1..=Geometry::FANOUT).contains(&count),
        "reference count outside bounds"
    );
    ensure!(
        bytes.len() == usize::from(count) * 64,
        "incorrect reference bytes or trailing data"
    );
    bytes
        .as_chunks::<64>()
        .0
        .iter()
        .map(|entry| {
            Ok(ChildReference {
                txid: Txid::from_byte_array(entry[..32].try_into()?),
                record_hash: entry[32..].try_into()?,
            })
        })
        .collect()
}

fn decode_data(bytes: &[u8]) -> Result<MultipartRecord, Error> {
    ensure!(bytes.len() >= 12, "truncated data part");
    let index = u32::from_le_bytes(bytes[8..12].try_into()?);
    ensure!(index < Geometry::MAX_PARTS, "part index outside bounds");
    Ok(MultipartRecord::Data(DataPart {
        index,
        payload: bytes[12..].to_vec(),
    }))
}

fn decode_leaf(bytes: &[u8]) -> Result<MultipartRecord, Error> {
    ensure!(bytes.len() >= 16, "truncated leaf manifest");
    let index = u16::from_le_bytes(bytes[8..10].try_into()?);
    let count = u16::from_le_bytes(bytes[10..12].try_into()?);
    let first = u32::from_le_bytes(bytes[12..16].try_into()?);
    ensure!(
        index < Geometry::FANOUT && first == u32::from(index) * u32::from(Geometry::FANOUT),
        "noncanonical leaf position"
    );
    Ok(MultipartRecord::Leaf(LeafManifest {
        index,
        entries: decode_references(&bytes[16..], count)?,
    }))
}

fn decode_root(bytes: &[u8]) -> Result<MultipartRecord, Error> {
    ensure!(bytes.len() >= 64, "truncated root manifest");
    let length = u64::from_le_bytes(bytes[8..16].try_into()?);
    let geometry = Geometry::new(length)?;
    let parts = u32::from_le_bytes(bytes[48..52].try_into()?);
    let leaves = u16::from_le_bytes(bytes[52..54].try_into()?);
    ensure!(
        parts == geometry.parts() && leaves == geometry.leaves(),
        "noncanonical root geometry"
    );
    ensure!(bytes[54..56] == [0, 0], "nonzero root reserved field");
    Ok(MultipartRecord::Root(RootManifest {
        length,
        payload_hash: bytes[16..48].try_into()?,
        profile: bytes[56..64].try_into()?,
        entries: decode_references(&bytes[64..], leaves)?,
    }))
}
