use urma::{
    backend::{self, RecordSource, Recovery},
    container,
    error::Error,
};
use urma_core::{error::Error as ProtocolError, format::ContentType};
use urma_identity::keys::RecoverySecret;

pub fn seal(
    secret: &RecoverySecret,
    plaintext: &[u8],
    content_type: ContentType,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    secret.with_bytes(|root| container::seal(root, plaintext, content_type))
}
pub fn recover(source: &dyn RecordSource, secret: &RecoverySecret) -> Result<Recovery, Error> {
    secret.with_bytes(|root| backend::recover(source, root))
}
