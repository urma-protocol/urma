use rand::rngs::OsRng;
pub use urma_core::container::{
    PrivateChunk, PrivateObject, PrivateRecordHeader, RecordMatch, inspect_header, open,
    open_record, pack, unpack,
};
use urma_core::{container, error::Error, format::ContentType};
use zeroize::Zeroizing;

pub fn random_secret() -> Result<Zeroizing<[u8; 32]>, Error> {
    container::random_secret(&mut OsRng)
}
pub fn seal(
    root: &[u8; 32],
    plaintext: &[u8],
    content_type: ContentType,
) -> Result<Vec<Vec<u8>>, Error> {
    container::seal(root, plaintext, content_type, &mut OsRng)
}
