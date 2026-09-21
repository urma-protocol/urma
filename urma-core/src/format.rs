use crate::error::{Error, bail, ensure};
use bitcoin::{Txid, hashes::Hash};

pub struct Urma;

impl Urma {
    pub const MAGIC: [u8; 4] = *b"URMA";
    pub const VERSION: u8 = 0;
    pub const PREFIX_BYTES: usize = 8;
    pub const CHUNK_BYTES: usize = 32_768;
    pub const PRIVATE_HEADER_BYTES: usize = 64;
    pub const METADATA_BYTES: usize = 48;
    pub const IV_BYTES: usize = 16;
    pub const BODY_OFFSET: usize = 80;
    pub const BODY_BYTES: usize = 32_816;
    pub const MAC_BYTES: usize = 32;
    pub const MAC_OFFSET: usize = 32_896;
    pub const PRIVATE_RECORD_BYTES: usize = 32_928;
    pub const MAX_PRIVATE_BYTES: u64 = 140_737_488_322_560;
    pub const MAX_PUBLIC_BYTES: usize = 32_768;
    pub const AVATAR_BYTES: usize = 512;
    pub const CONTAINER_HEADER_BYTES: usize = 12;
    pub const CONTENT_DOMAIN: &'static [u8] = b"URMA/V0/private/content";
    pub const AUTHENTICATION_DOMAIN: &'static [u8] = b"URMA/V0/private/authentication";
    pub const DISCOVERY_DOMAIN: &'static [u8] = b"URMA/V0/private/discovery";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Private = 1,
    Post = 2,
    Container = 3,
    Reply = 4,
    Profile = 5,
    Avatar = 6,
    DataPart = 7,
    LeafManifest = 8,
    RootManifest = 9,
}

impl RecordKind {
    pub fn byte(self) -> u8 {
        match self {
            Self::Private => 1,
            Self::Post => 2,
            Self::Container => 3,
            Self::Reply => 4,
            Self::Profile => 5,
            Self::Avatar => 6,
            Self::DataPart => 7,
            Self::LeafManifest => 8,
            Self::RootManifest => 9,
        }
    }

    pub fn prefix(self) -> [u8; 8] {
        [b'U', b'R', b'M', b'A', Urma::VERSION, self.byte(), 0, 0]
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(bytes.len() >= Urma::PREFIX_BYTES, "truncated URMA prefix");
        if bytes[..4] != Urma::MAGIC {
            return Err(Error::Unsupported("unsupported record marker".into()));
        }
        if bytes[4] != Urma::VERSION {
            return Err(Error::Unsupported("unsupported URMA version".into()));
        }
        if bytes[6..8] != [0, 0] {
            return Err(Error::Unsupported("unsupported URMA flags".into()));
        }
        match bytes[5] {
            1 => Ok(Self::Private),
            2 => Ok(Self::Post),
            3 => Ok(Self::Container),
            4 => Ok(Self::Reply),
            5 => Ok(Self::Profile),
            6 => Ok(Self::Avatar),
            7 => Ok(Self::DataPart),
            8 => Ok(Self::LeafManifest),
            9 => Ok(Self::RootManifest),
            kind => Err(Error::Unsupported(format!("unsupported URMA kind {kind}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Opaque,
    Text,
    Image,
    Audio,
    Video,
}

impl ContentType {
    pub fn code(self) -> u32 {
        match self {
            Self::Opaque => 0,
            Self::Text => 1,
            Self::Image => 2,
            Self::Audio => 3,
            Self::Video => 4,
        }
    }

    pub fn from_code(code: u32) -> Result<Self, Error> {
        match code {
            0 => Ok(Self::Opaque),
            1 => Ok(Self::Text),
            2 => Ok(Self::Image),
            3 => Ok(Self::Audio),
            4 => Ok(Self::Video),
            value => Err(Error::Unsupported(format!(
                "unsupported private content type {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicRecord {
    Post(String),
    Reply { target: Txid, text: String },
    Profile(String),
    Avatar(Box<[u8; 512]>),
}

impl PublicRecord {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Post(..) => RecordKind::Post,
            Self::Reply { .. } => RecordKind::Reply,
            Self::Profile(..) => RecordKind::Profile,
            Self::Avatar(..) => RecordKind::Avatar,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let body_size = match self {
            Self::Post(text) | Self::Profile(text) => text.len(),
            Self::Reply { text, .. } => text
                .len()
                .checked_add(32)
                .ok_or_else(|| Error::Invalid("reply size overflow".into()))?,
            Self::Avatar(pixels) => pixels.len(),
        };
        ensure!(
            body_size <= Urma::MAX_PUBLIC_BYTES - Urma::PREFIX_BYTES,
            "public record exceeds 32 KiB"
        );
        let mut bytes = Vec::with_capacity(Urma::PREFIX_BYTES + body_size);
        bytes.extend_from_slice(&self.kind().prefix());
        match self {
            Self::Post(text) | Self::Profile(text) => bytes.extend_from_slice(text.as_bytes()),
            Self::Reply { target, text } => {
                bytes.extend_from_slice(target.as_byte_array());
                bytes.extend_from_slice(text.as_bytes());
            }
            Self::Avatar(pixels) => bytes.extend_from_slice(pixels.as_slice()),
        }
        ensure!(
            bytes.len() <= Urma::MAX_PUBLIC_BYTES,
            "public record exceeds 32 KiB"
        );
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let kind = RecordKind::parse(bytes)?;
        ensure!(
            bytes.len() <= Urma::MAX_PUBLIC_BYTES,
            "public record exceeds 32 KiB"
        );
        let body = &bytes[Urma::PREFIX_BYTES..];
        match kind {
            RecordKind::Post => Ok(Self::Post(std::str::from_utf8(body)?.to_owned())),
            RecordKind::Profile => Ok(Self::Profile(std::str::from_utf8(body)?.to_owned())),
            RecordKind::Reply => {
                ensure!(body.len() >= 32, "truncated reply target");
                Ok(Self::Reply {
                    target: Txid::from_byte_array(body[..32].try_into()?),
                    text: std::str::from_utf8(&body[32..])?.to_owned(),
                })
            }
            RecordKind::Avatar => Ok(Self::Avatar(Box::new(body.try_into()?))),
            RecordKind::Private
            | RecordKind::Container
            | RecordKind::DataPart
            | RecordKind::LeafManifest
            | RecordKind::RootManifest => bail!("not an atomic public record"),
        }
    }
}

pub fn chunk_count(length: u64) -> Result<u32, Error> {
    ensure!(
        (1..=Urma::MAX_PRIVATE_BYTES).contains(&length),
        "private length outside representational bounds"
    );
    Ok(u32::try_from(
        length.div_ceil(u64::try_from(Urma::CHUNK_BYTES)?),
    )?)
}
