use rand::{CryptoRng, RngCore};
use urma_core::container;
use urma_core::{error::Error, format::ContentType};
use urma_identity::keys::RecoverySecret;

pub struct FileOriginal<'a> {
    pub bytes: &'a [u8],
    pub content_type: ContentType,
}
pub struct CapturedOriginal<'a> {
    pub bytes: &'a [u8],
    pub content_type: ContentType,
}

pub fn seal_file<R: RngCore + CryptoRng>(
    secret: &RecoverySecret,
    original: FileOriginal<'_>,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, Error> {
    secret.with_bytes(|root| container::seal(root, original.bytes, original.content_type, rng))
}
pub fn seal_capture<R: RngCore + CryptoRng>(
    secret: &RecoverySecret,
    original: CapturedOriginal<'_>,
    rng: &mut R,
) -> Result<Vec<Vec<u8>>, Error> {
    secret.with_bytes(|root| container::seal(root, original.bytes, original.content_type, rng))
}
