use crate::error::{Context, Error, bail, ensure};
use crate::format::{ContentType, RecordKind, Urma, chunk_count};
use aes::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type Cipher = ctr::Ctr128BE<aes::Aes256>;
type Authenticator = Hmac<Sha256>;

pub fn random_secret<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(key.as_mut())?;
    Ok(key)
}
fn derive(root: &[u8; 32], id: &[u8; 32], purpose: &[u8], output: &mut [u8]) -> Result<(), Error> {
    Hkdf::<Sha256>::new(Some(id), root)
        .expand(purpose, output)
        .map_err(|error| Error::Invalid(format!("HKDF expansion: {error}")))?;
    Ok(())
}
fn discovery_tag(root: &[u8; 32], id: &[u8; 32]) -> Result<[u8; 16], Error> {
    let mut tag = [0; 16];
    derive(root, id, Urma::DISCOVERY_DOMAIN, &mut tag)?;
    Ok(tag)
}
fn cipher(root: &[u8; 32], id: &[u8; 32], iv: &[u8; 16]) -> Result<Cipher, Error> {
    let mut key = Zeroizing::new([0; 32]);
    derive(root, id, Urma::CONTENT_DOMAIN, key.as_mut())?;
    Ok(Cipher::new((&*key).into(), iv.into()))
}
fn nonce(index: u32) -> [u8; 16] {
    let mut iv = [0; 16];
    iv[..8].copy_from_slice(&u64::from(index).to_be_bytes());
    iv
}
fn authenticator(root: &[u8; 32], id: &[u8; 32]) -> Result<Authenticator, Error> {
    let mut key = Zeroizing::new([0; 32]);
    derive(root, id, Urma::AUTHENTICATION_DOMAIN, key.as_mut())?;
    Ok(Authenticator::new_from_slice(key.as_ref())?)
}
pub fn seal<R: RngCore + CryptoRng>(
    root: &[u8; 32],
    plaintext: &[u8],
    content_type: ContentType,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, Error> {
    let count = chunk_count(u64::try_from(plaintext.len())?)?;
    let id = *random_secret(rng)?;
    let tag = discovery_tag(root, &id)?;
    let digest: [u8; 32] = Sha256::digest(plaintext).into();
    let mut records = Vec::new();
    records.try_reserve_exact(usize::try_from(count)?)?;
    for (position, chunk) in plaintext.chunks(Urma::CHUNK_BYTES).enumerate() {
        let index = u32::try_from(position)?;
        let mut record = Vec::with_capacity(Urma::PRIVATE_RECORD_BYTES);
        record.extend_from_slice(&RecordKind::Private.prefix());
        record.extend_from_slice(&id);
        record.extend_from_slice(&tag);
        record.extend_from_slice(&index.to_le_bytes());
        record.extend_from_slice(&count.to_le_bytes());
        let iv = nonce(index);
        record.extend_from_slice(&iv);
        let mut body = Zeroizing::new(vec![0; Urma::BODY_BYTES]);
        body[..32].copy_from_slice(&digest);
        body[32..40].copy_from_slice(&u64::try_from(plaintext.len())?.to_le_bytes());
        body[40..44].copy_from_slice(&content_type.code().to_le_bytes());
        body[Urma::METADATA_BYTES..Urma::METADATA_BYTES + chunk.len()].copy_from_slice(chunk);
        rng.try_fill_bytes(&mut body[Urma::METADATA_BYTES + chunk.len()..])?;
        cipher(root, &id, &iv)?.apply_keystream(&mut body);
        record.extend_from_slice(&body);
        let mut mac = authenticator(root, &id)?;
        mac.update(&record);
        record.extend_from_slice(&mac.finalize().into_bytes());
        records.push(record);
    }
    Ok(records)
}
pub struct PrivateChunk {
    pub id: [u8; 32],
    pub index: u32,
    pub count: u32,
    pub total: u64,
    pub digest: [u8; 32],
    pub content_type: ContentType,
    pub bytes: Zeroizing<Vec<u8>>,
    record_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateRecordHeader {
    pub id: [u8; 32],
    pub discovery_tag: [u8; 16],
    pub index: u32,
    pub count: u32,
}
pub enum RecordMatch {
    Unrelated,
    Authenticated(PrivateChunk),
}
pub fn inspect_header(record: &[u8]) -> Result<PrivateRecordHeader, Error> {
    ensure!(
        record.len() == Urma::PRIVATE_RECORD_BYTES,
        "invalid private record length"
    );
    ensure!(
        RecordKind::parse(record)? == RecordKind::Private,
        "not a private record"
    );
    let header = PrivateRecordHeader {
        id: record[8..40].try_into()?,
        discovery_tag: record[40..56].try_into()?,
        index: u32::from_le_bytes(record[56..60].try_into()?),
        count: u32::from_le_bytes(record[60..64].try_into()?),
    };
    ensure!(
        header.count > 0 && header.index < header.count,
        "invalid chunk bounds"
    );
    Ok(header)
}
pub fn open_record(root: &[u8; 32], record: &[u8]) -> Result<RecordMatch, Error> {
    if !record.starts_with(&Urma::MAGIC) {
        return Ok(RecordMatch::Unrelated);
    }
    match RecordKind::parse(record)? {
        RecordKind::Private => {}
        RecordKind::Post
        | RecordKind::Reply
        | RecordKind::Profile
        | RecordKind::Avatar
        | RecordKind::Container
        | RecordKind::DataPart
        | RecordKind::LeafManifest
        | RecordKind::WirePost
        | RecordKind::WireReply
        | RecordKind::ProfileRecord
        | RecordKind::RootManifest => return Ok(RecordMatch::Unrelated),
    }
    let header = inspect_header(record)?;
    if header.discovery_tag != discovery_tag(root, &header.id)? {
        return Ok(RecordMatch::Unrelated);
    }
    let mut mac = authenticator(root, &header.id)?;
    mac.update(&record[..Urma::MAC_OFFSET]);
    mac.verify_slice(&record[Urma::MAC_OFFSET..])
        .map_err(|error| Error::Invalid(format!("record authentication failed: {error}")))?;
    let iv = nonce(header.index);
    ensure!(
        record[Urma::PRIVATE_HEADER_BYTES..Urma::BODY_OFFSET] == iv,
        "noncanonical counter IV"
    );
    let mut body = Zeroizing::new(record[Urma::BODY_OFFSET..Urma::MAC_OFFSET].to_vec());
    cipher(root, &header.id, &iv)?.apply_keystream(&mut body);
    let total = u64::from_le_bytes(body[32..40].try_into()?);
    ensure!(
        chunk_count(total)? == header.count,
        "chunk count does not match encrypted file length"
    );
    let content_type = ContentType::from_code(u32::from_le_bytes(body[40..44].try_into()?))?;
    if body[44..48] != [0; 4] {
        return Err(Error::Unsupported(
            "unsupported private metadata flags".into(),
        ));
    }
    let remaining = total
        .checked_sub(u64::from(header.index) * u64::try_from(Urma::CHUNK_BYTES)?)
        .context("chunk offset exceeds original length")?;
    let size = usize::try_from(remaining.min(u64::try_from(Urma::CHUNK_BYTES)?))?;
    Ok(RecordMatch::Authenticated(PrivateChunk {
        id: header.id,
        index: header.index,
        count: header.count,
        total,
        digest: body[..32].try_into()?,
        content_type,
        bytes: Zeroizing::new(body[Urma::METADATA_BYTES..Urma::METADATA_BYTES + size].to_vec()),
        record_digest: Sha256::digest(record).into(),
    }))
}
pub struct PrivateObject {
    pub id: [u8; 32],
    pub count: u32,
    pub total: u64,
    pub content_type: ContentType,
    digest: [u8; 32],
    chunks: BTreeMap<u32, PrivateChunk>,
    conflict: bool,
}
impl PrivateObject {
    pub fn new(chunk: PrivateChunk) -> Self {
        Self {
            id: chunk.id,
            count: chunk.count,
            total: chunk.total,
            content_type: chunk.content_type,
            digest: chunk.digest,
            chunks: BTreeMap::from([(chunk.index, chunk)]),
            conflict: false,
        }
    }
    pub fn insert(&mut self, chunk: PrivateChunk) -> Result<(), Error> {
        if self.id != chunk.id
            || self.count != chunk.count
            || self.total != chunk.total
            || self.digest != chunk.digest
            || self.content_type != chunk.content_type
        {
            self.conflict = true;
            bail!("conflicting authenticated object metadata");
        }
        match self.chunks.entry(chunk.index) {
            std::collections::btree_map::Entry::Occupied(previous) => {
                if previous.get().record_digest != chunk.record_digest {
                    self.conflict = true;
                    bail!("conflicting authenticated record");
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(chunk);
            }
        }
        Ok(())
    }
    pub fn received(&self) -> usize {
        self.chunks.len()
    }
    pub fn is_conflicted(&self) -> bool {
        self.conflict
    }
    pub fn is_complete(&self) -> bool {
        match u32::try_from(self.chunks.len()) {
            Ok(count) => !self.conflict && count == self.count,
            Err(error) => panic!("chunk map exceeds u32 key space: {error}"),
        }
    }
    pub fn finish(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        ensure!(!self.conflict, "conflicting authenticated object");
        ensure!(
            u32::try_from(self.chunks.len())? == self.count,
            "incomplete object: {} of {} chunks",
            self.chunks.len(),
            self.count
        );
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(
            usize::try_from(self.total).context("object exceeds host capacity")?,
        )?;
        for index in 0..self.count {
            bytes.extend_from_slice(&self.chunks.get(&index).context("missing chunk")?.bytes);
        }
        ensure!(
            u64::try_from(bytes.len())? == self.total
                && Sha256::digest(&bytes).as_slice() == self.digest,
            "whole-file integrity failed"
        );
        Ok(bytes)
    }
}
pub fn pack(records: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let count = u32::try_from(records.len())?;
    ensure!(count > 0, "empty container");
    let first = inspect_header(&records[0])?;
    let capacity = records
        .len()
        .checked_mul(Urma::PRIVATE_RECORD_BYTES + 4)
        .and_then(|n| n.checked_add(Urma::CONTAINER_HEADER_BYTES))
        .context("container size overflow")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    bytes.extend_from_slice(&RecordKind::Container.prefix());
    bytes.extend_from_slice(&count.to_le_bytes());
    for record in records {
        ensure!(inspect_header(record)?.id == first.id, "mixed objects");
        bytes.extend_from_slice(&u32::try_from(record.len())?.to_le_bytes());
        bytes.extend_from_slice(record);
    }
    Ok(bytes)
}
pub fn unpack(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    ensure!(
        RecordKind::parse(bytes)? == RecordKind::Container,
        "not an offline container"
    );
    ensure!(
        bytes.len() >= Urma::CONTAINER_HEADER_BYTES,
        "truncated container"
    );
    let count = usize::try_from(u32::from_le_bytes(bytes[8..12].try_into()?))?;
    ensure!(count > 0, "empty container");
    let size = count
        .checked_mul(Urma::PRIVATE_RECORD_BYTES + 4)
        .and_then(|n| n.checked_add(Urma::CONTAINER_HEADER_BYTES))
        .context("container size overflow")?;
    ensure!(bytes.len() == size, "truncated or trailing container data");
    let mut records = Vec::new();
    records.try_reserve_exact(count)?;
    for entry in bytes[Urma::CONTAINER_HEADER_BYTES..]
        .as_chunks::<{ Urma::PRIVATE_RECORD_BYTES + 4 }>()
        .0
    {
        ensure!(
            u32::from_le_bytes(entry[..4].try_into()?)
                == u32::try_from(Urma::PRIVATE_RECORD_BYTES)?,
            "invalid container record length"
        );
        inspect_header(&entry[4..])?;
        records.push(entry[4..].to_vec());
    }
    let id = inspect_header(&records[0])?.id;
    for record in &records {
        ensure!(inspect_header(record)?.id == id, "mixed objects");
    }
    Ok(records)
}
fn required_chunk(root: &[u8; 32], record: &[u8]) -> Result<PrivateChunk, Error> {
    match open_record(root, record)? {
        RecordMatch::Authenticated(chunk) => Ok(chunk),
        RecordMatch::Unrelated => bail!("wrong key or unrelated record"),
    }
}
pub fn open(root: &[u8; 32], records: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (first, rest) = records.split_first().context("no records")?;
    let mut object = PrivateObject::new(required_chunk(root, first)?);
    for record in rest {
        object.insert(required_chunk(root, record)?)?;
    }
    object.finish()
}
