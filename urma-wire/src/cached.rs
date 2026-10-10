use crate::Error;
use urma_core::{
    error::Error as RecordError,
    format::{PublicRecord, RecordKind, Urma},
};

pub enum CachedRecord {
    Current(PublicRecord),
    LegacyAvatar,
    LegacyProfile,
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
    if bytes.len() > Urma::PREFIX_BYTES + Urma::MAX_PROFILE_BYTES
        && bytes.len() <= Urma::MAX_PUBLIC_BYTES
        && bytes[..Urma::PREFIX_BYTES] == RecordKind::Profile.prefix()
    {
        let profile =
            std::str::from_utf8(&bytes[Urma::PREFIX_BYTES..]).map_err(RecordError::from)?;
        tracing::warn!(
            bytes = profile.len(),
            "legacy profile longer than 128 UTF-8 bytes omitted from Wire views; cached bytes retained"
        );
        return Ok(CachedRecord::LegacyProfile);
    }
    Ok(CachedRecord::Current(PublicRecord::decode(bytes)?))
}
