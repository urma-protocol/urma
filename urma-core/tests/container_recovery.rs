use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use urma_core::{
    container::{self, PrivateObject, RecordMatch},
    error::Error,
    format::{ContentType, RecordKind, Urma},
};

struct FixtureRng(rand::rngs::mock::StepRng);
impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(bytes)
    }
}
impl CryptoRng for FixtureRng {}

fn sealed(root: &[u8; 32], original: &[u8], seed: u64) -> Vec<Vec<u8>> {
    let mut rng = FixtureRng(rand::rngs::mock::StepRng::new(seed, 17));
    container::seal(root, original, ContentType::Text, &mut rng).unwrap()
}
fn packed(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = RecordKind::Container.prefix().to_vec();
    bytes.extend_from_slice(&u32::try_from(records.len()).unwrap().to_le_bytes());
    for record in records {
        assert_eq!(record.len(), Urma::PRIVATE_RECORD_BYTES);
        bytes.extend_from_slice(&u32::try_from(record.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(record);
    }
    bytes
}
fn resign(root: &[u8; 32], record: &mut [u8]) {
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&record[8..40]), root)
        .expand(Urma::AUTHENTICATION_DOMAIN, &mut key)
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(&record[..Urma::MAC_OFFSET]);
    record[Urma::MAC_OFFSET..].copy_from_slice(&mac.finalize().into_bytes());
}
fn assert_refused(root: &[u8; 32], records: &[Vec<u8>], reason: &str) {
    match container::recover_container(root, &packed(records)) {
        Ok(result) => panic!("unexpected recovery of {} bytes", result.bytes.len()),
        Err(error) => assert!(error.to_string().contains(reason), "{error}"),
    }
}

#[test]
fn complete_shuffled_duplicates_return_authenticated_metadata_and_original() {
    let root = [9; 32];
    let original = vec![0xA7; Urma::CHUNK_BYTES + 5];
    let records = sealed(&root, &original, 1);
    let reordered = vec![records[1].clone(), records[0].clone(), records[1].clone()];
    let bytes = packed(&reordered);
    let recovered = container::recover_container(&root, &bytes).unwrap();
    assert_eq!(recovered.bytes.as_slice(), original);
    assert_eq!(
        recovered.id,
        container::inspect_header(&records[0]).unwrap().id
    );
    assert_eq!(recovered.count, 2);
    assert_eq!(recovered.total, u64::try_from(original.len()).unwrap());
    assert_eq!(
        recovered.digest,
        <[u8; 32]>::from(Sha256::digest(&original))
    );
    assert_eq!(recovered.content_type, ContentType::Text);
    assert_eq!(recovered.skipped_unrelated, 0);
    assert_eq!(recovered.rejected_records, 0);
    assert_eq!(container::unpack(&bytes).unwrap(), reordered);
    assert_eq!(
        container::open(&root, &reordered).unwrap().as_slice(),
        original
    );
}

#[test]
fn redundant_corruption_forged_duplicate_and_foreign_records_are_counted() {
    let root = [9; 32];
    let valid = sealed(&root, b"original", 1);
    let mut forged_duplicate = valid[0].clone();
    forged_duplicate[Urma::BODY_OFFSET + Urma::METADATA_BYTES] ^= 1;
    let mut bad_bounds = valid[0].clone();
    bad_bounds[60..64].fill(0);
    let foreign = sealed(&[7; 32], b"foreign", 2);
    let mut public = vec![0; Urma::PRIVATE_RECORD_BYTES];
    public[..8].copy_from_slice(&RecordKind::Post.prefix());
    let candidates = vec![
        forged_duplicate,
        foreign[0].clone(),
        valid[0].clone(),
        bad_bounds,
        public,
        valid[0].clone(),
    ];
    let recovered = container::recover_container(&root, &packed(&candidates)).unwrap();
    assert_eq!(recovered.bytes.as_slice(), b"original");
    assert_eq!(recovered.skipped_unrelated, 2);
    assert_eq!(recovered.rejected_records, 2);
    assert!(container::open(&root, &candidates).is_err());
    assert!(container::unpack(&packed(&candidates)).is_err());
}

#[test]
fn semantic_invalid_records_are_skipped_even_with_a_valid_mac() {
    let root = [9; 32];
    let valid = sealed(&root, b"four", 1);
    let mut candidates = Vec::new();
    for (offset, mask) in [
        (64, 1),
        (Urma::BODY_OFFSET + 32, 4),
        (Urma::BODY_OFFSET + 39, 0x80),
        (60, 3),
        (Urma::BODY_OFFSET + 40, 0xFF),
        (Urma::BODY_OFFSET + 44, 1),
    ] {
        let mut invalid = valid[0].clone();
        invalid[offset] ^= mask;
        resign(&root, &mut invalid);
        match container::open_record(&root, &invalid) {
            Err(Error::Invalid(reason) | Error::Unsupported(reason)) => assert!(!reason.is_empty()),
            Err(error) => panic!("unexpected error: {error}"),
            Ok(RecordMatch::Unrelated) => panic!("candidate was unrelated"),
            Ok(RecordMatch::Authenticated(chunk)) => {
                panic!("accepted invalid index {}", chunk.index)
            }
        }
        assert!(container::open(&root, &[invalid.clone(), valid[0].clone()]).is_err());
        candidates.push(invalid);
    }
    candidates.push(valid[0].clone());
    let recovered = container::recover_container(&root, &packed(&candidates)).unwrap();
    assert_eq!(recovered.bytes.as_slice(), b"four");
    assert_eq!(recovered.skipped_unrelated, 0);
    assert_eq!(recovered.rejected_records, 6);
}

#[test]
fn authenticated_padding_conflict_is_sticky_even_after_completion_in_either_order() {
    let root = [9; 32];
    let valid = sealed(&root, b"four", 1);
    let mut different = valid[0].clone();
    different[Urma::MAC_OFFSET - 1] ^= 1;
    resign(&root, &mut different);
    assert_eq!(
        container::open(&root, &[different.clone()])
            .unwrap()
            .as_slice(),
        b"four"
    );
    for records in [
        vec![valid[0].clone(), valid[0].clone(), different.clone()],
        vec![different.clone(), valid[0].clone(), valid[0].clone()],
    ] {
        assert_refused(&root, &records, "conflicting authenticated record");
        assert!(container::open(&root, &records).is_err());
    }
    let chunk = match container::open_record(&root, &valid[0]).unwrap() {
        RecordMatch::Authenticated(chunk) => chunk,
        RecordMatch::Unrelated => panic!("valid chunk unrelated"),
    };
    let mut object = PrivateObject::new(chunk);
    assert!(object.is_complete());
    let conflicting = match container::open_record(&root, &different).unwrap() {
        RecordMatch::Authenticated(chunk) => chunk,
        RecordMatch::Unrelated => panic!("valid conflicting chunk unrelated"),
    };
    assert!(object.insert(conflicting).is_err());
    assert!(object.is_conflicted());
    assert!(!object.is_complete());
    assert!(object.finish().is_err());
}

#[test]
fn incompatible_authenticated_metadata_is_never_resolved_arbitrarily() {
    let root = [9; 32];
    let original = vec![3; Urma::CHUNK_BYTES + 4];
    let valid = sealed(&root, &original, 1);
    let mut different_type = valid[1].clone();
    different_type[Urma::BODY_OFFSET + 40] ^= 1;
    resign(&root, &mut different_type);
    for records in [
        vec![valid[0].clone(), valid[1].clone(), different_type.clone()],
        vec![different_type.clone(), valid[0].clone(), valid[1].clone()],
    ] {
        assert_refused(&root, &records, "conflicting authenticated object metadata");
    }
}

#[test]
fn two_authenticated_ids_are_refused_even_if_only_one_is_complete() {
    let root = [9; 32];
    let complete = sealed(&root, b"complete", 1);
    let partial = sealed(&root, &vec![7; Urma::CHUNK_BYTES + 1], 2);
    let other_complete = sealed(&root, b"other", 3);
    for other in [&partial[0], &other_complete[0]] {
        for records in [
            vec![complete[0].clone(), other.clone()],
            vec![other.clone(), complete[0].clone()],
        ] {
            assert_refused(&root, &records, "multiple authenticated objects");
            assert!(container::unpack(&packed(&records)).is_err());
            assert!(container::open(&root, &records).is_err());
        }
    }
    let mut forged_other = partial[0].clone();
    forged_other[Urma::MAC_OFFSET] ^= 1;
    let recovered =
        container::recover_container(&root, &packed(&[complete[0].clone(), forged_other])).unwrap();
    assert_eq!(recovered.bytes.as_slice(), b"complete");
    assert_eq!(recovered.rejected_records, 1);
}

#[test]
fn no_authenticated_object_missing_indices_and_final_hash_fail_without_bytes() {
    let root = [9; 32];
    let valid = sealed(&root, b"four", 1);
    let mut bad_mac = valid[0].clone();
    bad_mac[Urma::MAC_OFFSET] ^= 1;
    assert_refused(&root, &[bad_mac], "no authenticated object");
    assert_refused(&[8; 32], &valid, "no authenticated object");
    let partial = sealed(&root, &vec![8; Urma::CHUNK_BYTES + 1], 2);
    assert_refused(
        &root,
        &[partial[0].clone(), partial[0].clone()],
        "incomplete object",
    );
    let mut bad_digest = valid[0].clone();
    bad_digest[Urma::BODY_OFFSET] ^= 1;
    resign(&root, &mut bad_digest);
    assert_refused(&root, &[bad_digest], "whole-file integrity failed");
}

#[test]
fn framing_is_exact_and_strict_validation_order_is_preserved() {
    let root = [9; 32];
    let valid = sealed(&root, b"four", 1);
    let canonical = packed(&valid);
    let mut invalid_frames = Vec::new();
    for offset in [0, 4, 5, 6, 8, 12] {
        let mut bytes = canonical.clone();
        bytes[offset] ^= 1;
        invalid_frames.push(bytes);
    }
    invalid_frames.push(canonical[..canonical.len() - 1].to_vec());
    let mut trailing = canonical.clone();
    trailing.push(0);
    invalid_frames.push(trailing);
    invalid_frames.push(packed(&[]));
    let mut enormous_count = canonical.clone();
    enormous_count[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    invalid_frames.push(enormous_count);
    for bytes in invalid_frames {
        assert!(container::unpack(&bytes).is_err());
        assert!(container::recover_container(&root, &bytes).is_err());
    }
    for length in 0..Urma::CONTAINER_HEADER_BYTES {
        assert!(container::recover_container(&root, &canonical[..length]).is_err());
    }
    let mut invalid_first = valid[0].clone();
    invalid_first[60..64].fill(0);
    let mut dual_error = packed(&[invalid_first, valid[0].clone()]);
    dual_error[Urma::CONTAINER_HEADER_BYTES + Urma::PRIVATE_RECORD_BYTES + 4] ^= 1;
    assert!(
        container::unpack(&dual_error)
            .unwrap_err()
            .to_string()
            .contains("invalid chunk bounds")
    );
    match container::recover_container(&root, &dual_error) {
        Err(error) => assert!(
            error
                .to_string()
                .contains("invalid container record length")
        ),
        Ok(result) => panic!("accepted damaged framing for {} bytes", result.bytes.len()),
    }
}

#[test]
fn internal_kdf_errors_keep_their_type_and_source() {
    let mut output = vec![0; 255 * 32 + 1];
    let failure = Hkdf::<Sha256>::new(Some(&[1; 32]), &[2; 32])
        .expand(b"oversized internal output", &mut output)
        .unwrap_err();
    let error = Error::from(failure);
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .is::<hkdf::InvalidLength>()
    );
    assert!(matches!(error, Error::Kdf(..)));
}
