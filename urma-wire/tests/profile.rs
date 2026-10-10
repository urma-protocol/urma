use bitcoin::{
    Block, BlockHash, Transaction, Txid,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
};
use urma_core::format::{PublicRecord, RecordKind, Urma};
use urma_wire::{
    cached::{CachedRecord, decode_cached},
    index::{self, Checkpoint, Entry, Index},
    reader::Reader,
    view,
};

fn author() -> bitcoin::XOnlyPublicKey {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[4; 32])
        .unwrap()
        .x_only_public_key()
        .0
}
fn raw_profile(text: &str) -> Vec<u8> {
    [
        RecordKind::Profile.prefix().to_vec(),
        text.as_bytes().to_vec(),
    ]
    .concat()
}
fn entry(at: u8, bytes: &[u8]) -> Entry {
    Entry {
        height: 0,
        position: u32::from(at),
        txid: Txid::from_byte_array([at; 32]).to_string(),
        author: author().to_string(),
        record: hex::encode(bytes),
    }
}
fn mixed_index() -> Index {
    Index {
        format: "URMA-WIRE-INDEX-2".into(),
        genesis: BlockHash::all_zeros().to_string(),
        start: 0,
        blocks: Vec::new(),
        entries: vec![
            entry(1, &raw_profile(&"ț".repeat(64))),
            entry(
                2,
                &PublicRecord::Post("still visible".into()).encode().unwrap(),
            ),
            entry(3, &raw_profile(&"x".repeat(129))),
            entry(4, &raw_profile(&"x".repeat(32760))),
        ],
    }
}

#[test]
fn oversized_legacy_profiles_preserve_cache_bytes_and_supported_views_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("index.json");
    let index = mixed_index();
    index.persist(&path).unwrap();
    let original = std::fs::read(&path).unwrap();
    let loaded = Index::load(&path).unwrap();
    assert_eq!(loaded.entries.len(), 4);
    for (before, after) in index.entries.iter().zip(&loaded.entries) {
        assert_eq!(before.record, after.record);
        assert_eq!(before.txid, after.txid);
        assert_eq!(before.author, after.author);
    }
    let feed = view::records(&loaded, 2).unwrap();
    assert_eq!(feed.len(), 2);
    assert_eq!(feed[0]["payload"]["text"], "still visible");
    assert_eq!(feed[1]["payload"]["name"], "ț".repeat(64));
    assert_eq!(view::records(&loaded, 1).unwrap(), vec![feed[0].clone()]);
    let identity = view::identity(&loaded, author()).unwrap();
    assert_eq!(identity["profile"]["name"], "ț".repeat(64));
    assert_eq!(identity["profile"]["txid"], loaded.entries[0].txid);
    for old in &loaded.entries[2..] {
        let error = view::record(&loaded, old.txid.parse().unwrap()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("legacy profile longer than 128 UTF-8 bytes")
        );
    }
    assert_eq!(
        view::record(&loaded, loaded.entries[0].txid.parse().unwrap()).unwrap(),
        feed[1]
    );
    loaded.persist(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(
        Index::load(&path).unwrap().entries[3].record,
        index.entries[3].record
    );
}

#[test]
fn legacy_only_profile_is_omitted_without_fabricating_a_name() {
    let mut index = mixed_index();
    index.entries.remove(0);
    assert!(view::identity(&index, author()).unwrap()["profile"].is_null());
    let feed = view::records(&index, 3).unwrap();
    assert_eq!(feed.len(), 1);
    assert_eq!(feed[0]["payload"]["text"], "still visible");
    assert_eq!(
        index.entries[1].record,
        hex::encode(raw_profile(&"x".repeat(129)))
    );
}

#[test]
fn cached_profile_exception_requires_exact_prefix_old_bounds_and_valid_utf8() {
    for size in [0, 127, 128, 129, 32760, 32761] {
        let bytes = raw_profile(&"x".repeat(size));
        if size <= 128 {
            assert!(
                matches!(decode_cached(&bytes).unwrap(), CachedRecord::Current(PublicRecord::Profile(text)) if text.len() == size)
            );
        } else if size <= 32760 {
            assert!(matches!(
                decode_cached(&bytes).unwrap(),
                CachedRecord::LegacyProfile
            ));
            assert!(PublicRecord::decode(&bytes).is_err());
        } else {
            assert!(decode_cached(&bytes).is_err());
        }
    }
    assert!(matches!(
        decode_cached(&raw_profile(&"ț".repeat(65))).unwrap(),
        CachedRecord::LegacyProfile
    ));
    for offset in [0, 4, 5, 6, 7] {
        let mut malformed = raw_profile(&"x".repeat(129));
        malformed[offset] = 0xFF;
        assert!(decode_cached(&malformed).is_err());
    }
    for length in [128, 129, 32760] {
        let mut bytes = raw_profile(&"x".repeat(length));
        bytes[Urma::PREFIX_BYTES] = 0xFF;
        assert!(decode_cached(&bytes).is_err());
    }
    let opaque = PublicRecord::ProfileRecord {
        profile: *b"PROFILE1",
        payload: vec![0xFF; 129],
    };
    assert!(
        matches!(decode_cached(&opaque.encode().unwrap()).unwrap(), CachedRecord::Current(PublicRecord::ProfileRecord { payload, .. }) if payload.len() == 129)
    );
}

#[test]
fn malformed_profile_or_legacy_identity_metadata_still_refuses_without_rewriting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("index.json");
    let mut bad_utf8 = raw_profile(&"x".repeat(129));
    bad_utf8[Urma::PREFIX_BYTES] = 0xFF;
    for malformed in [
        "not-hex".into(),
        hex::encode(bad_utf8),
        hex::encode(raw_profile(&"x".repeat(32761))),
    ] {
        let mut index = mixed_index();
        index.entries[3].record = malformed;
        index.persist(&path).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert!(Index::load(&path).is_err());
        assert!(view::records(&index, 2).is_err());
        assert!(view::identity(&index, author()).is_err());
        assert!(view::record(&index, index.entries[3].txid.parse().unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    for corrupt_author in [false, true] {
        let mut index = mixed_index();
        if corrupt_author {
            index.entries[3].author = "not-a-key".into();
        } else {
            index.entries[3].txid = "not-a-txid".into();
        }
        index.persist(&path).unwrap();
        assert!(Index::load(&path).is_err());
    }
}

struct UnchangedTip(BlockHash);
impl Reader for UnchangedTip {
    type Error = std::io::Error;
    fn genesis(&self) -> Result<BlockHash, Self::Error> {
        Ok(self.0)
    }
    fn tip_height(&self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn block_hash(&self, height: u64) -> Result<BlockHash, Self::Error> {
        assert_eq!(height, 0);
        Ok(self.0)
    }
    fn block(&self, height: u64) -> Result<(Block, BlockHash), Self::Error> {
        Err(std::io::Error::other(format!(
            "unexpected rescan at {height}"
        )))
    }
    fn transaction(&self, txid: Txid) -> Result<Transaction, Self::Error> {
        Err(std::io::Error::other(format!(
            "unexpected proof fetch {txid}"
        )))
    }
}

#[test]
fn sync_resumes_legacy_profile_cache_without_rescanning_or_rewriting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("index.json");
    let genesis =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let mut index = mixed_index();
    index.genesis = genesis.to_string();
    index.blocks.push(Checkpoint {
        height: 0,
        hash: genesis.to_string(),
    });
    index.persist(&path).unwrap();
    let original = std::fs::read(&path).unwrap();
    let (report, loaded) = index::sync(&UnchangedTip(genesis), &path, 0, 1, |_, _| {
        panic!("unchanged tip must not apply blocks")
    })
    .unwrap();
    assert_eq!(report.scanned, 0);
    assert_eq!(report.rolled_back, 0);
    assert_eq!(loaded.entries[3].record, index.entries[3].record);
    assert_eq!(view::records(&loaded, 2).unwrap().len(), 2);
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
