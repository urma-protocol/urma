use std::{collections::BTreeMap, fs, os::unix::fs::symlink};
use tempfile::tempdir;
use urma_files::{
    capture::{Capture, Derivative, SessionState},
    catalog::Content,
    ingest::{IngestRequest, ingest},
    inventory,
    recover::{self, ObjectSource},
    safety,
};
use urma_identity::keys::RecoverySecret;
use urma_runtime::{backend, container};
use zeroize::Zeroizing;

#[test]
fn archive_roundtrip_independent_objects_and_partial_recovery() {
    let lab = tempdir().unwrap();
    let input = lab.path().join("documents");
    fs::create_dir(&input).unwrap();
    fs::create_dir(input.join("empty-directory")).unwrap();
    fs::write(input.join("empty-file"), []).unwrap();
    let original = vec![37u8; 40_000];
    fs::write(input.join("original.bin"), &original).unwrap();
    let secret = RecoverySecret::import(Zeroizing::new([42; 32]));
    let bundle = lab.path().join("bundle");
    let inventory = ingest(
        &secret,
        IngestRequest {
            inputs: &[input],
            output: &bundle,
            collection: "Evidence files",
            capture: Capture::Files,
        },
    )
    .unwrap();
    let catalog = recover::inspect_bundle(&bundle, &secret).unwrap();
    let source = ObjectSource::Encrypted {
        directory: &bundle,
        secret: &secret,
    };
    let output = lab.path().join("restored");
    assert!(
        recover::recover(source, &inventory.catalog, &output)
            .unwrap()
            .complete
    );
    assert_eq!(
        fs::read(output.join("documents/original.bin")).unwrap(),
        original
    );
    assert!(output.join("documents/empty-directory").is_dir());
    assert!(
        fs::read(output.join("documents/empty-file"))
            .unwrap()
            .is_empty()
    );
    let mut recovered = BTreeMap::new();
    for object in inventory::prepared_objects(&bundle).unwrap() {
        for record in object.records {
            assert_eq!(
                secret
                    .with_bytes(|root| backend::accept_record(root, &record, &mut recovered))
                    .unwrap(),
                0
            );
        }
    }
    let chain_output = lab.path().join("chain-recovery");
    assert!(
        recover::recover(
            ObjectSource::Authenticated {
                objects: &recovered
            },
            &inventory.catalog,
            &chain_output
        )
        .unwrap()
        .complete
    );
    let member = catalog
        .entries
        .iter()
        .find_map(|entry| match &entry.content {
            Content::File { object, .. } => Some(object),
            _ => None,
        })
        .unwrap();
    let records = inventory::load_object(&bundle, &member.id).unwrap();
    assert_eq!(
        secret
            .with_bytes(|root| container::open(root, &records))
            .unwrap()
            .as_slice(),
        original
    );
    fs::remove_file(bundle.join(format!("{}.urma", member.id))).unwrap();
    let partial =
        recover::recover(source, &inventory.catalog, &lab.path().join("partial")).unwrap();
    assert!(!partial.complete);
    assert_eq!(
        partial.missing_objects.as_slice(),
        std::slice::from_ref(&member.id)
    );
    assert!(recover::recover(source, &inventory.catalog, &output).is_err());
    assert!(safety::validate_path("../escape").is_err());
    assert!(safety::validate_path("A/CON.txt").is_err());
}

#[test]
fn capture_relationships_preserve_original_and_reject_symlinks() {
    let lab = tempdir().unwrap();
    let input = lab.path().join("capture");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("original.jpg"), b"selected original bytes").unwrap();
    fs::write(input.join("preview.jpg"), b"declared derivative bytes").unwrap();
    let secret = RecoverySecret::import(Zeroizing::new([93; 32]));
    let session = Capture::Session {
        id: "session-1".into(),
        state: SessionState::Closed,
        assertions: BTreeMap::from([(
            "context".into(),
            "Operator supplied statement; not proof of scene".into(),
        )]),
        originals: vec!["capture/original.jpg".into()],
        derivatives: vec![Derivative {
            original: "capture/original.jpg".into(),
            derived: "capture/preview.jpg".into(),
            transformation: "Operator declares reduced preview".into(),
        }],
    };
    let bundle = lab.path().join("capture-bundle");
    let inventory = ingest(
        &secret,
        IngestRequest {
            inputs: std::slice::from_ref(&input),
            output: &bundle,
            collection: "Capture session",
            capture: session.clone(),
        },
    )
    .unwrap();
    let catalog = recover::inspect_bundle(&bundle, &secret).unwrap();
    assert_eq!(catalog.capture, session);
    let output = lab.path().join("restored");
    assert!(
        recover::recover(
            ObjectSource::Encrypted {
                directory: &bundle,
                secret: &secret
            },
            &inventory.catalog,
            &output
        )
        .unwrap()
        .complete
    );
    assert_eq!(
        fs::read(output.join("capture/original.jpg")).unwrap(),
        b"selected original bytes"
    );
    symlink(input.join("original.jpg"), input.join("link.jpg")).unwrap();
    assert!(
        ingest(
            &secret,
            IngestRequest {
                inputs: &[input],
                output: &lab.path().join("rejected"),
                collection: "Unsafe",
                capture: Capture::Files
            }
        )
        .is_err()
    );
    assert!(!lab.path().join("rejected").exists());
}
