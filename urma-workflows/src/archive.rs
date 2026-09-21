use urma_core::{error::Error as ProtocolError, format::ContentType};
use urma_identity::keys::RecoverySecret;
use urma_runtime::{
    backend::{self, RecordSource, Recovery},
    container,
};

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

use std::path::Path;
use urma_runtime::error::{Error, ensure};
use zeroize::Zeroizing;

pub fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    let bytes = urma_io::read_private(path, 32).map_err(|cause| match cause {
        urma_io::Error::PrivatePermissions => Error::Invalid(format!(
            "recovery key must be private: chmod 600 {}",
            path.display()
        )),
        urma_io::Error::TooLarge { .. } => {
            Error::Invalid("recovery key must contain exactly 32 raw bytes".into())
        }
        cause => cause.into(),
    })?;
    ensure!(
        bytes.len() == 32,
        "recovery key must contain exactly 32 raw bytes"
    );
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}
