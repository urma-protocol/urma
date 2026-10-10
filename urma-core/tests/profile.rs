use bitcoin::{
    Txid,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
};
use urma_core::{
    envelope,
    format::{PublicRecord, RecordKind, Urma},
};

#[test]
fn profile_ascii_boundaries_limit_payload_bytes_on_encode_and_decode() {
    assert_eq!(Urma::MAX_PROFILE_BYTES, 128);
    for size in [0, 1, 127, 128, 129, 32760] {
        let text = "a".repeat(size);
        let record = PublicRecord::Profile(text.clone());
        let raw = [RecordKind::Profile.prefix().to_vec(), text.into_bytes()].concat();
        if size <= 128 {
            let encoded = record.encode().unwrap();
            assert_eq!(encoded, raw);
            assert_eq!(encoded.len(), 8 + size);
            assert_eq!(PublicRecord::decode(&raw).unwrap(), record);
        } else {
            assert!(record.encode().is_err());
            assert!(PublicRecord::decode(&raw).is_err());
        }
    }
}

#[test]
fn profile_limit_counts_utf8_bytes_instead_of_characters() {
    for text in [
        "ț".repeat(64),
        "😀".repeat(32),
        format!("{}a", "ț".repeat(63)),
    ] {
        assert!(text.len() <= 128);
        let record = PublicRecord::Profile(text);
        let encoded = record.encode().unwrap();
        assert_eq!(PublicRecord::decode(&encoded).unwrap(), record);
    }
    for text in [
        format!("{}a", "ț".repeat(64)),
        "ț".repeat(65),
        format!("{}a", "😀".repeat(32)),
    ] {
        assert!(text.chars().count() <= 128);
        assert!(text.len() > 128);
        let raw = [
            RecordKind::Profile.prefix().to_vec(),
            text.as_bytes().to_vec(),
        ]
        .concat();
        assert!(PublicRecord::Profile(text).encode().is_err());
        assert!(PublicRecord::decode(&raw).is_err());
    }
}

#[test]
fn profile_preserves_empty_nul_whitespace_and_unicode_without_normalization() {
    for text in ["", "\0", "  \0é e\u{301}\r\n\t  ", "😀\u{200d}😀"] {
        let record = PublicRecord::Profile(text.to_owned());
        let bytes = record.encode().unwrap();
        assert_eq!(&bytes[..8], b"URMA\x00\x05\x00\x00");
        assert_eq!(&bytes[8..], text.as_bytes());
        let decoded = PublicRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }
    for body in [
        vec![0xFF],
        [vec![b'a'; 127], vec![0xC3]].concat(),
        vec![0x80; 128],
    ] {
        let bytes = [RecordKind::Profile.prefix().to_vec(), body].concat();
        assert!(PublicRecord::decode(&bytes).is_err());
    }
}

#[test]
fn profile_cap_does_not_reduce_post_reply_or_kind_0c_limits() {
    let target = Txid::from_byte_array([7; 32]);
    for record in [
        PublicRecord::Post("a".repeat(32760)),
        PublicRecord::Reply {
            target,
            text: "a".repeat(32728),
        },
        PublicRecord::ProfileRecord {
            profile: *b"PROFILE1",
            payload: vec![0xFF; 32752],
        },
    ] {
        let encoded = record.encode().unwrap();
        assert_eq!(encoded.len(), 32768);
        assert_eq!(PublicRecord::decode(&encoded).unwrap(), record);
    }
}

#[test]
fn profile_envelope_validation_applies_the_same_payload_limit() {
    let signer = Keypair::from_seckey_slice(&Secp256k1::new(), &[7; 32]).unwrap();
    for size in [0, 127, 128, 129] {
        let bytes = [RecordKind::Profile.prefix().to_vec(), vec![b'a'; size]].concat();
        if size <= 128 {
            envelope::build(&bytes, &signer).unwrap();
        } else {
            assert!(envelope::build(&bytes, &signer).is_err());
        }
    }
}
