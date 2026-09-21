use bitcoin::{Txid, hashes::Hash};
use urma_core::{
    format::{PublicRecord, RecordKind},
    topics::Topics,
};

fn topics() -> Topics {
    Topics {
        wire: "rosint".into(),
        hashtags: vec!["documents".into(), "investigation".into()],
    }
}

#[test]
fn structured_vectors_preserve_text_target_and_boundaries() {
    let post = PublicRecord::WirePost {
        topics: Topics {
            wire: "x".into(),
            hashtags: vec!["a".into()],
        },
        text: "é\0\n".into(),
    };
    let bytes = post.encode().unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "55524d41000a000001780101610400c3a9000a"
    );
    assert_eq!(PublicRecord::decode(&bytes).unwrap(), post);
    for length in 0..bytes.len() {
        assert!(PublicRecord::decode(&bytes[..length]).is_err());
    }
    let reply = PublicRecord::WireReply {
        target: Txid::from_byte_array([7; 32]),
        topics: topics(),
        text: " exact\r\n".into(),
    };
    assert_eq!(
        PublicRecord::decode(&reply.encode().unwrap()).unwrap(),
        reply
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(PublicRecord::decode(&extra).is_err());
    let mut invalid_utf8 = bytes;
    *invalid_utf8.last_mut().unwrap() = 255;
    assert!(PublicRecord::decode(&invalid_utf8).is_err());
}

#[test]
fn canonical_labels_and_counts_are_enforced_on_both_paths() {
    for wire in ["A", "/rosint", "-x", "a/b", "é", &"a".repeat(33)] {
        assert!(
            PublicRecord::WirePost {
                topics: Topics {
                    wire: wire.into(),
                    hashtags: vec![]
                },
                text: String::new()
            }
            .encode()
            .is_err()
        );
    }
    for tags in [vec!["a", "a"], vec!["b", "a"], vec![""], vec!["a"; 9]] {
        assert!(
            Topics {
                wire: "".into(),
                hashtags: tags.into_iter().map(String::from).collect()
            }
            .encode_body("")
            .is_err()
        );
    }
    for body in [
        vec![33],
        vec![0, 9],
        vec![0, 1, 0],
        vec![1, b'A', 0, 0, 0],
        vec![0, 2, 1, b'b', 1, b'a', 0, 0],
        vec![0, 2, 1, b'a', 1, b'a', 0, 0],
    ] {
        let mut bytes = RecordKind::WirePost.prefix().to_vec();
        bytes.extend(body);
        assert!(PublicRecord::decode(&bytes).is_err());
    }
    let tags = (0..8).map(|i| format!("{i}{}", "a".repeat(31))).collect();
    assert!(
        Topics {
            wire: "x".repeat(32),
            hashtags: tags
        }
        .encode_body("")
        .is_ok()
    );
}

#[test]
fn cap_empty_metadata_and_legacy_are_unambiguous() {
    let topics = Topics {
        wire: String::new(),
        hashtags: vec![],
    };
    for target in [None, Some(Txid::all_zeros())] {
        let limit = 32768 - 8 - 4 - if target.is_some() { 32 } else { 0 };
        for (size, valid) in [(limit, true), (limit + 1, false), (65536, false)] {
            let record = match target {
                None => PublicRecord::WirePost {
                    topics: topics.clone(),
                    text: "x".repeat(size),
                },
                Some(target) => PublicRecord::WireReply {
                    target,
                    topics: topics.clone(),
                    text: "x".repeat(size),
                },
            };
            assert_eq!(record.encode().is_ok(), valid);
            if valid {
                assert_eq!(
                    PublicRecord::decode(&record.encode().unwrap()).unwrap(),
                    record
                );
            }
        }
    }
    let post = PublicRecord::Post("/rosint #investigation\0\n".into());
    let bytes = post.encode().unwrap();
    assert_eq!(&bytes[..8], &RecordKind::Post.prefix());
    assert_eq!(&bytes[8..], b"/rosint #investigation\0\n");
    assert_eq!(PublicRecord::decode(&bytes).unwrap(), post);
    let reply = PublicRecord::Reply {
        target: Txid::all_zeros(),
        text: "legacy".into(),
    };
    assert_eq!(
        PublicRecord::decode(&reply.encode().unwrap()).unwrap(),
        reply
    );
}
