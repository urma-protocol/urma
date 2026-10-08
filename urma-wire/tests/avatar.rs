use bitcoin::{
    Block, BlockHash, Transaction, Txid,
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1},
};
use urma_core::format::{PublicRecord, RecordKind};
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

fn legacy() -> Vec<u8> {
    [b"URMA\x00\x06\x00\x00".to_vec(), vec![0xAB; 512]].concat()
}

fn entry(at: u8, bytes: &[u8]) -> Entry {
    Entry {
        height: u64::from(at),
        position: 0,
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
            entry(
                1,
                &PublicRecord::Profile("Reporter".into()).encode().unwrap(),
            ),
            entry(
                2,
                &PublicRecord::Post("still visible".into()).encode().unwrap(),
            ),
            entry(
                3,
                &PublicRecord::Avatar(Box::new([0x12; 128]))
                    .encode()
                    .unwrap(),
            ),
            entry(4, &legacy()),
        ],
    }
}

#[test]
fn legacy_avatar_cache_restart_preserves_bytes_and_mixed_feed_stays_available() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wire-index.json");
    let index = mixed_index();
    index.persist(&path).unwrap();
    let raw = std::fs::read(&path).unwrap();
    let loaded = Index::load(&path).unwrap();
    assert_eq!(loaded.entries.len(), 4);
    assert_eq!(loaded.entries[3].record, hex::encode(legacy()));
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    let feed = view::records(&loaded, 2).unwrap();
    assert_eq!(feed.len(), 2);
    assert_eq!(feed[0]["payload"]["kind"], "avatar");
    assert_eq!(feed[0]["payload"]["pixels_hex"], hex::encode([0x12; 128]));
    assert_eq!(feed[1]["payload"]["text"], "still visible");
    assert_eq!(view::records(&loaded, 1).unwrap().len(), 1);
    let identity = view::identity(&loaded, author()).unwrap();
    assert_eq!(identity["profile"]["name"], "Reporter");
    assert_eq!(identity["avatar"]["pixels_hex"], hex::encode([0x12; 128]));
    let old_txid = loaded.entries[3].txid.parse().unwrap();
    let error = view::record(&loaded, old_txid).unwrap_err();
    assert!(error.to_string().contains("legacy 512-byte avatar"));
    let new_txid = loaded.entries[2].txid.parse().unwrap();
    assert_eq!(view::record(&loaded, new_txid).unwrap(), feed[0]);
    loaded.persist(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    assert_eq!(
        Index::load(&path).unwrap().entries[3].record,
        hex::encode(legacy())
    );
}

#[test]
fn a_legacy_only_avatar_is_omitted_without_fabricating_a_current_avatar() {
    let mut index = mixed_index();
    index.entries.remove(2);
    let feed = view::records(&index, 3).unwrap();
    assert_eq!(feed.len(), 2);
    assert_eq!(feed[0]["payload"]["text"], "still visible");
    let identity = view::identity(&index, author()).unwrap();
    assert_eq!(identity["profile"]["name"], "Reporter");
    assert!(identity["avatar"].is_null());
    assert_eq!(index.entries[2].record, hex::encode(legacy()));
}

#[test]
fn cached_decoder_only_exempts_the_exact_canonical_legacy_avatar() {
    assert!(matches!(
        decode_cached(&legacy()).unwrap(),
        CachedRecord::LegacyAvatar
    ));
    assert!(PublicRecord::decode(&legacy()).is_err());
    let current = PublicRecord::Avatar(Box::new([0x12; 128]));
    let CachedRecord::Current(decoded) = decode_cached(&current.encode().unwrap()).unwrap() else {
        panic!("current avatar classified as legacy");
    };
    assert_eq!(decoded, current);
    for offset in [0, 4, 5, 6, 7] {
        let mut bytes = legacy();
        bytes[offset] = 0xFF;
        assert!(decode_cached(&bytes).is_err());
    }
    for size in [127, 129, 511, 513] {
        let bytes = [RecordKind::Avatar.prefix().to_vec(), vec![0x12; size]].concat();
        assert!(decode_cached(&bytes).is_err());
    }
    let post = PublicRecord::Post("x".repeat(512));
    assert!(
        matches!(decode_cached(&post.encode().unwrap()).unwrap(), CachedRecord::Current(PublicRecord::Post(text)) if text.len() == 512)
    );
}

#[test]
fn unrelated_corruption_is_not_silently_skipped_and_cache_is_retained() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wire-index.json");
    let malformed_post = [RecordKind::Post.prefix().to_vec(), vec![0xFF]].concat();
    for malformed in [
        "not-hex".to_owned(),
        hex::encode(malformed_post),
        hex::encode([RecordKind::Avatar.prefix().to_vec(), vec![0x12; 129]].concat()),
    ] {
        let mut index = mixed_index();
        index.entries[3].record = malformed;
        index.persist(&path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(Index::load(&path).is_err());
        assert!(view::records(&index, 2).is_err());
        assert!(view::identity(&index, author()).is_err());
        let txid = index.entries[3].txid.parse().unwrap();
        assert!(view::record(&index, txid).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), raw);
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

struct NoNewBlocksReader(BlockHash);

impl Reader for NoNewBlocksReader {
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
    fn block(&self, _height: u64) -> Result<(Block, BlockHash), Self::Error> {
        Err(std::io::Error::other(
            "cache restart must not rescan a block",
        ))
    }
    fn transaction(&self, _txid: Txid) -> Result<Transaction, Self::Error> {
        Err(std::io::Error::other(
            "cache restart must not fetch a proof",
        ))
    }
}

#[test]
fn sync_resumes_a_mixed_legacy_cache_without_rescanning_or_rewriting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wire-index.json");
    let hash = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let mut index = mixed_index();
    index.genesis = hash.to_string();
    index.blocks.push(Checkpoint {
        height: 0,
        hash: hash.to_string(),
    });
    for entry in &mut index.entries {
        entry.height = 0;
    }
    index.persist(&path).unwrap();
    let raw = std::fs::read(&path).unwrap();
    let (report, loaded) = index::sync(&NoNewBlocksReader(hash), &path, 0, 1, |_, _| {
        panic!("unchanged tip must not apply a new block");
    })
    .unwrap();
    assert_eq!(report.scanned, 0);
    assert_eq!(report.rolled_back, 0);
    assert_eq!(loaded.entries.len(), 4);
    assert_eq!(loaded.entries[3].record, hex::encode(legacy()));
    assert_eq!(view::records(&loaded, 2).unwrap().len(), 2);
    assert_eq!(std::fs::read(&path).unwrap(), raw);
}
