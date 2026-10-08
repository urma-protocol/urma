use crate::Error;
use urma_core::format::{PublicRecord, RecordKind, Urma};

pub enum CachedRecord {
    Current(PublicRecord),
    LegacyAvatar,
}

pub fn decode_cached(bytes: &[u8]) -> Result<CachedRecord, Error> {
    const LEGACY_AVATAR_BYTES: usize = 512;
    if bytes.len() == Urma::PREFIX_BYTES + LEGACY_AVATAR_BYTES
        && bytes[..Urma::PREFIX_BYTES] == RecordKind::Avatar.prefix()
    {
        tracing::warn!(
            bytes = bytes.len(),
            "legacy 512-byte avatar omitted from Wire views; cached bytes retained"
        );
        return Ok(CachedRecord::LegacyAvatar);
    }
    Ok(CachedRecord::Current(PublicRecord::decode(bytes)?))
}
