use rand::{SeedableRng, rngs::StdRng};
use serde_json::Value;
use std::path::PathBuf;
use urma_chain::observation::Chain;
use urma_identity::{
    identity::{IdentitySigner, IdentitySlot},
    keyring::Keyring,
    phrase::IdentityPhrase,
    root::Root,
    vault::{EncryptedVault, UnlockCredential, UnlockedVault},
};

static_assertions::assert_not_impl_any!(IdentityPhrase: std::fmt::Debug, Clone, serde::Serialize, From<urma_identity::keys::RecoverySecret>);
static_assertions::assert_not_impl_any!(UnlockedVault: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(Keyring: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(Root: std::fmt::Debug, Clone, serde::Serialize);
static_assertions::assert_not_impl_any!(urma_identity::identity::IdentityKey: std::fmt::Debug, Clone, serde::Serialize, From<urma_identity::keys::RecoverySecret>);
static_assertions::assert_not_impl_any!(urma_identity::keys::RecoverySecret: IdentitySigner, From<IdentityPhrase>, From<urma_identity::identity::IdentityKey>);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/identity-vault-v2")
}
fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(dir().join("vectors.json")).unwrap()).unwrap()
}
fn phrase() -> IdentityPhrase {
    IdentityPhrase::parse(vectors()["phrase"].as_str().unwrap()).unwrap()
}
fn password() -> String {
    vectors()["vault"]["password"].as_str().unwrap().into()
}
fn encrypted() -> EncryptedVault {
    EncryptedVault::from_bytes(&std::fs::read(dir().join("valid.vault")).unwrap()).unwrap()
}

#[test]
fn independent_vault_unlocks_with_password_and_phrase() {
    let v = vectors();
    let p = phrase();
    let names = v["vault"]["names"].as_array().unwrap();
    let by_password = encrypted()
        .unlock(UnlockCredential::Password(&password()))
        .unwrap();
    let by_phrase = encrypted()
        .unlock(UnlockCredential::RecoveryPhrase(&p))
        .unwrap();
    for opened in [&by_password, &by_phrase] {
        let keyring = opened.keyring();
        assert_eq!(keyring.identities().len(), names.len());
        for (entry, name) in keyring.identities().iter().zip(names) {
            assert_eq!(entry.name, name.as_str().unwrap());
        }
        assert_eq!(keyring.active_slot().index(), 1);
        assert_eq!(
            keyring.active().unwrap().author().0.to_string(),
            v["slots"][1]["author"].as_str().unwrap()
        );
        assert_eq!(
            keyring
                .root()
                .account_xpub(Chain::LitecoinMainnet)
                .unwrap()
                .to_string(),
            v["chains"][1]["account_xpub"].as_str().unwrap()
        );
    }
    assert_eq!(
        by_password.keyring().identities(),
        by_phrase.keyring().identities()
    );
    let sealed = by_password.seal(&mut StdRng::seed_from_u64(7)).unwrap();
    assert_eq!(sealed.as_bytes()[..176], encrypted().as_bytes()[..176]);
    assert_eq!(
        sealed.as_bytes()[8..10],
        EncryptedVault::VERSION.to_le_bytes()
    );
}

#[test]
fn roundtrip_mutations_password_reset_and_encrypted_metadata() {
    let p = phrase();
    let mut opened = encrypted()
        .unlock(UnlockCredential::RecoveryPhrase(&p))
        .unwrap();
    let next = opened.keyring_mut().add("separate investigation").unwrap();
    assert_eq!(next.index(), 2);
    assert_eq!(opened.keyring().active_slot().index(), 1);
    opened.keyring_mut().select(next).unwrap();
    opened.keyring_mut().rename(next, "editor").unwrap();
    assert!(opened.keyring_mut().add("main").is_err());
    assert!(opened.keyring_mut().rename(next, "reporter").is_err());
    assert!(
        opened
            .keyring_mut()
            .select(IdentitySlot::new(3).unwrap())
            .is_err()
    );
    let before = opened.keyring().active().unwrap().public_key();
    let mut rng = StdRng::seed_from_u64(93);
    let first = opened.seal(&mut rng).unwrap();
    let second = opened.seal(&mut rng).unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.as_bytes()[..176], second.as_bytes()[..176]);
    assert!(!first.as_bytes().windows(6).any(|x| x == b"editor"));
    let changed = opened
        .reset_password("new public test password", &mut rng)
        .unwrap()
        .seal(&mut rng)
        .unwrap();
    assert_ne!(changed.as_bytes()[24..40], first.as_bytes()[24..40]);
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
            .unlock(UnlockCredential::Password(&password()))
            .is_err()
    );
}

#[test]
fn fresh_vault_full_capacity_fits_bounds() {
    let mut rng = StdRng::seed_from_u64(11);
    let fresh = IdentityPhrase::generate(&mut rng).unwrap();
    assert_eq!(fresh.export_words().unwrap().split(' ').count(), 12);
    let mut keyring = Keyring::create(&fresh, "a").unwrap();
    let smallest = UnlockedVault::create(keyring, "public test password", &mut rng)
        .unwrap()
        .seal(&mut rng)
        .unwrap();
    assert_eq!(smallest.as_bytes().len(), EncryptedVault::MIN_BYTES);
    keyring = Keyring::create(&fresh, &"n".repeat(64)).unwrap();
    for index in 1..IdentitySlot::CAPACITY {
        keyring.add(&format!("{index:0>64}")).unwrap();
    }
    assert!(keyring.add("one too many").is_err());
    let largest = UnlockedVault::create(keyring, "public test password", &mut rng)
        .unwrap()
        .seal(&mut rng)
        .unwrap();
    assert_eq!(largest.as_bytes().len(), EncryptedVault::MAX_BYTES);
    let opened = largest
        .unlock(UnlockCredential::RecoveryPhrase(&fresh))
        .unwrap();
    assert_eq!(opened.keyring().identities().len(), 64);
}

#[test]
fn negative_vectors_wrong_credentials_and_bounded_parser() {
    let p = phrase();
    for (name, stage) in vectors()["negative"].as_object().unwrap() {
        let bytes = std::fs::read(dir().join(format!("{name}.vault"))).unwrap();
        match (stage.as_str().unwrap(), EncryptedVault::from_bytes(&bytes)) {
            ("parse", Err(_)) => {}
            ("unlock", Ok(vault)) => {
                assert!(
                    vault
                        .unlock(UnlockCredential::Password(&password()))
                        .is_err(),
                    "{name}"
                );
                assert!(
                    vault.unlock(UnlockCredential::RecoveryPhrase(&p)).is_err(),
                    "{name}"
                );
            }
            (stage, Ok(_)) => panic!("{name} parsed but must fail at {stage}"),
            (stage, Err(error)) => {
                panic!("{name} failed to parse ({error}) but must fail at {stage}")
            }
        }
    }
    let wrong = "private wrong password must not appear";
    let error = match encrypted().unlock(UnlockCredential::Password(wrong)) {
        Ok(_) => panic!("wrong password accepted"),
        Err(e) => e,
    };
    assert!(!format!("{error} {error:?}").contains(wrong));
    let other = IdentityPhrase::generate(&mut StdRng::seed_from_u64(35)).unwrap();
    assert!(
        encrypted()
            .unlock(UnlockCredential::RecoveryPhrase(&other))
            .is_err()
    );
    assert!(EncryptedVault::from_bytes(&vec![0; EncryptedVault::MAX_BYTES + 1]).is_err());
    for size in [0, 8, 192, EncryptedVault::MIN_BYTES - 1] {
        assert!(EncryptedVault::from_bytes(&vec![0; size]).is_err());
    }
    let fresh = Keyring::create(&p, "default").unwrap();
    assert!(UnlockedVault::create(fresh, "short", &mut StdRng::seed_from_u64(0)).is_err());
}
