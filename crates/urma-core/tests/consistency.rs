use bitcoin::{Txid, hashes::Hash};
use sha2::{Digest, Sha256};
use urma_core::multipart::{
    ChildReference, DataPart, LeafManifest, MultipartConsistency, MultipartRecord, RootManifest,
};

fn records() -> Vec<MultipartRecord> {
    let data = MultipartRecord::Data(DataPart {
        index: 0,
        payload: b"payload".to_vec(),
    });
    let leaf = MultipartRecord::Leaf(LeafManifest {
        index: 0,
        entries: vec![
            ChildReference::new(Txid::from_byte_array([1; 32]), &data.encode().unwrap()).unwrap(),
        ],
    });
    let root = MultipartRecord::Root(RootManifest {
        length: 7,
        payload_hash: Sha256::digest(b"payload").into(),
        profile: *b"URMAFIL0",
        entries: vec![
            ChildReference::new(Txid::from_byte_array([2; 32]), &leaf.encode().unwrap()).unwrap(),
        ],
    });
    vec![data, leaf, root]
}

fn verify(records: &[MultipartRecord]) -> Result<(), urma_core::error::Error> {
    let mut consistency = MultipartConsistency::new();
    for (index, record) in records.iter().enumerate() {
        consistency.accept(
            &record.encode()?,
            Txid::from_byte_array([u8::try_from(index + 1).unwrap(); 32]),
        )?;
    }
    consistency.validate_count(3)
}

#[test]
fn consistency_checks_payload_references_and_geometry() {
    verify(&records()).unwrap();
    let mut altered = records();
    if let MultipartRecord::Root(root) = &mut altered[2] {
        root.payload_hash[0] ^= 1;
    }
    assert!(
        verify(&altered)
            .unwrap_err()
            .to_string()
            .contains("payload hash mismatch")
    );
    let mut altered = records();
    if let MultipartRecord::Leaf(leaf) = &mut altered[1] {
        leaf.entries[0].record_hash[0] ^= 1;
    }
    assert!(
        verify(&altered)
            .unwrap_err()
            .to_string()
            .contains("references differ")
    );
    let mut altered = records();
    if let MultipartRecord::Root(root) = &mut altered[2] {
        root.entries[0].txid = Txid::all_zeros();
    }
    assert!(
        verify(&altered)
            .unwrap_err()
            .to_string()
            .contains("references differ")
    );
    let mut altered = records();
    if let MultipartRecord::Root(root) = &mut altered[2] {
        root.length += 1;
    }
    assert!(
        verify(&altered)
            .unwrap_err()
            .to_string()
            .contains("geometry mismatch")
    );
    let mut altered = records();
    if let MultipartRecord::Data(data) = &mut altered[0] {
        data.index = 1;
    }
    assert!(verify(&altered).is_err());
    let mut consistency = MultipartConsistency::new();
    assert!(consistency.accept(b"invalid", Txid::all_zeros()).is_err());
    assert!(consistency.validate_count(2).is_err());
}
