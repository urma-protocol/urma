use std::error::Error as _;
use urma_core::error::Error as ProtocolError;
use urma_identity::error::IdentityError;
use urma_runtime::error::Error;
use urma_wallet::wallet::WalletError;

#[test]
fn nested_protocol_errors_retain_the_original_cause() {
    let raw = hex::decode("zz").unwrap_err();
    let error = Error::Context {
        message: "publish".into(),
        cause: Box::new(Error::Wallet(WalletError::Protocol(ProtocolError::Hex(
            raw,
        )))),
    };
    let wallet = error.source().unwrap();
    let protocol = wallet.source().unwrap();
    let hex = protocol.source().unwrap();
    assert!(
        hex.source()
            .unwrap()
            .downcast_ref::<hex::FromHexError>()
            .is_some()
    );
}

#[test]
fn identity_and_io_errors_retain_causes_without_changing_display() {
    let cause = bitcoin::secp256k1::Error::InvalidSecretKey;
    let identity = IdentityError::Signing(cause);
    assert_eq!(identity.to_string(), "identity signing failed");
    assert!(
        identity
            .source()
            .unwrap()
            .downcast_ref::<bitcoin::secp256k1::Error>()
            .is_some()
    );
    let error = Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(Error::Invalid("invalid".into()).source().is_none());
    assert!(WalletError::BudgetExceeded.source().is_none());
}
