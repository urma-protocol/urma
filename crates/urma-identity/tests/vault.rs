use rand::{SeedableRng, rngs::StdRng};
use serde_json::Value;
use std::path::PathBuf;
use urma_identity::{
    identity::{IdentitySigner, IdentitySlot},
    keyring::Keyring,
    phrase::IdentityPhrase,
    vault::{EncryptedVault, UnlockCredential, UnlockedVault},
};

static_assertions::assert_not_impl_any!(IdentityPhrase: std::fmt::Debug, Clone, serde::Serialize, From<urma_identity::keys::RecoverySecret>);
static_assertions::assert_not_impl_any!(UnlockedVault: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(urma_identity::identity::IdentityKey: std::fmt::Debug, Clone, serde::Serialize, From<urma_identity::keys::RecoverySecret>);
static_assertions::assert_not_impl_any!(urma_identity::keys::RecoverySecret: IdentitySigner, From<IdentityPhrase>, From<urma_identity::identity::IdentityKey>);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/identity-vault-v1")
}
fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(dir().join("vectors.json")).unwrap()).unwrap()
}
fn phrase() -> IdentityPhrase {
    IdentityPhrase::parse(vectors()["phrase"].as_str().unwrap()).unwrap()
}
fn encrypted() -> EncryptedVault {
    EncryptedVault::from_bytes(&std::fs::read(dir().join("valid.vault")).unwrap()).unwrap()
}

#[test]
fn independent_vectors_and_phrase_only_recovery() {
    let v = vectors();
    let p = phrase();
    let recovered = Keyring::recover(&p).unwrap();
    assert_eq!(recovered.identities().len(), 64);
    assert_eq!(recovered.active_slot().index(), 0);
    for row in v["slots"].as_array().unwrap() {
        let slot = IdentitySlot::new(row["slot"].as_u64().unwrap() as u16).unwrap();
        let key = recovered.identity(slot).unwrap();
        assert_eq!(
            key.public_key().to_string(),
            row["public_key"].as_str().unwrap()
        );
        assert_eq!(key.author().0.to_string(), row["author"].as_str().unwrap());
    }
    let password = encrypted()
        .unlock(UnlockCredential::Password(v["password"].as_str().unwrap()))
        .unwrap();
    let recovery = encrypted()
        .unlock(UnlockCredential::RecoveryPhrase(&p))
        .unwrap();
    assert_eq!(
        password.keyring().identities(),
        recovery.keyring().identities()
    );
    assert_eq!(password.keyring().active_slot().index(), 1);
    assert_eq!(
        password.keyring().active().unwrap().public_key(),
        recovered
            .identity(IdentitySlot::new(1).unwrap())
            .unwrap()
            .public_key()
    );
    assert!(IdentitySlot::new(64).is_err());
    assert!(IdentityPhrase::parse(&"abandon ".repeat(24)).is_err());
}

#[test]
fn roundtrip_mutations_password_reset_and_encrypted_metadata() {
    let p = phrase();
    let mut opened = encrypted()
        .unlock(UnlockCredential::RecoveryPhrase(&p))
        .unwrap();
    let next = opened.keyring_mut().add("separate investigation").unwrap();
    assert_eq!(next.index(), 2);
    opened.keyring_mut().select(next).unwrap();
    opened.keyring_mut().rename(next, "editor").unwrap();
    assert!(opened.keyring_mut().add("main").is_err());
    assert!(opened.keyring_mut().rename(next, "reporter").is_err());
    let before = opened.keyring().active().unwrap().public_key();
    let mut rng = StdRng::seed_from_u64(93);
    let first = opened.seal(&mut rng).unwrap();
    let second = opened.seal(&mut rng).unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert!(!first.as_bytes().windows(6).any(|x| x == b"editor"));
    let changed = opened
        .reset_password("new public test password", &mut rng)
        .unwrap()
        .seal(&mut rng)
        .unwrap();
    let decoded = changed
        .unlock(UnlockCredential::Password("new public test password"))
        .unwrap();
    assert_eq!(decoded.keyring().active().unwrap().public_key(), before);
    let recovered = changed
        .unlock(UnlockCredential::RecoveryPhrase(&p))
        .unwrap();
    assert_eq!(
        recovered.keyring().identities(),
        decoded.keyring().identities()
    );
    assert_eq!(recovered.keyring().active_slot(), next);
    assert!(
        changed
            .unlock(UnlockCredential::Password(
                vectors()["password"].as_str().unwrap()
            ))
            .is_err()
    );
}

#[test]
fn negative_vectors_wrong_credentials_and_bounded_parser() {
    let p = phrase();
    let v = vectors();
    for name in v["negative"].as_array().unwrap() {
        let bytes = std::fs::read(dir().join(format!("{}.vault", name.as_str().unwrap()))).unwrap();
        if let Ok(vault) = EncryptedVault::from_bytes(&bytes) {
            assert!(
                vault.unlock(UnlockCredential::RecoveryPhrase(&p)).is_err(),
                "{name}"
            );
        }
    }
    let password = "private wrong password must not appear";
    let error = match encrypted().unlock(UnlockCredential::Password(password)) {
        Ok(_) => panic!("wrong password accepted"),
        Err(e) => e,
    };
    assert!(!format!("{error} {error:?}").contains(password));
    let other = IdentityPhrase::generate(&mut StdRng::seed_from_u64(35)).unwrap();
    assert!(
        encrypted()
            .unlock(UnlockCredential::RecoveryPhrase(&other))
            .is_err()
    );
    assert!(EncryptedVault::from_bytes(&vec![0; EncryptedVault::MAX_BYTES + 1]).is_err());
    for size in [0, 8, 192, 247] {
        assert!(EncryptedVault::from_bytes(&vec![0; size]).is_err());
    }
    let fresh = Keyring::create(&p, "default").unwrap();
    assert!(UnlockedVault::create(fresh, "short", &mut StdRng::seed_from_u64(0)).is_err());
}
