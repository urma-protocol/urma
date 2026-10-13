use crate::{
    Error,
    cached::{CachedRecord, decode_cached},
    ensure,
    index::{Entry, Index},
};
use bitcoin::{
    Script,
    bech32::{Fe32, Hrp, segwit},
};
use serde_json::{Value, json};
use urma_chain::observation::Chain;
use urma_core::format::PublicRecord;

pub fn records(index: &Index, limit: usize) -> Result<Vec<Value>, Error> {
    ensure!((1..=1000).contains(&limit), "feed limit must be 1..1000");
    let mut records = Vec::new();
    for entry in index.entries.iter().rev() {
        match decode_cached(&hex::decode(&entry.record)?)? {
            CachedRecord::Current(record) => records.push(render(index, entry, record)?),
            CachedRecord::LegacyAvatar | CachedRecord::LegacyProfile => continue,
        }
        if records.len() == limit {
            break;
        }
    }
    Ok(records)
}
pub fn record(index: &Index, txid: bitcoin::Txid) -> Result<Value, Error> {
    let txid = txid.to_string();
    let entry = index
        .entries
        .iter()
        .find(|entry| entry.txid == txid)
        .ok_or_else(|| Error::Missing("record is not in the confirmed local index".into()))?;
    match decode_cached(&hex::decode(&entry.record)?)? {
        CachedRecord::Current(record) => render(index, entry, record),
        CachedRecord::LegacyAvatar => Err(Error::Invalid(
            "legacy 512-byte avatar is unsupported; cached record bytes are preserved".into(),
        )),
        CachedRecord::LegacyProfile => Err(Error::Invalid(
            "legacy profile longer than 128 UTF-8 bytes is unsupported; cached record bytes are preserved".into(),
        )),
    }
}
pub fn identity(index: &Index, author: bitcoin::XOnlyPublicKey) -> Result<Value, Error> {
    let author = author.to_string();
    let mut profile = Value::Null;
    let mut avatar = Value::Null;
    for entry in index
        .entries
        .iter()
        .rev()
        .filter(|entry| entry.author == author)
    {
        let record = match decode_cached(&hex::decode(&entry.record)?)? {
            CachedRecord::Current(record) => record,
            CachedRecord::LegacyAvatar | CachedRecord::LegacyProfile => continue,
        };
        match record {
            PublicRecord::Profile(name) if profile.is_null() => {
                profile = json!({"txid":entry.txid,"name":name});
            }
            PublicRecord::Avatar(pixels) if avatar.is_null() => {
                avatar = json!({"txid":entry.txid,"pixels_hex":hex::encode(*pixels)});
            }
            other => tracing::trace!(
                kind = other.kind().byte(),
                "identity projection already selected or unrelated record"
            ),
        }
        if !profile.is_null() && !avatar.is_null() {
            break;
        }
    }
    let mut address = Value::Null;
    for entry in index
        .entries
        .iter()
        .rev()
        .filter(|entry| entry.author == author)
    {
        if let Some(found) = author_address(index, entry)? {
            address = Value::String(found);
            break;
        }
    }
    Ok(
        json!({"author":author,"author_address":address,"profile":profile,"avatar":avatar,"genesis":index.genesis}),
    )
}

fn index_chain(index: &Index) -> Option<Chain> {
    const CHAINS: [Chain; 5] = [
        Chain::BitcoinMainnet,
        Chain::LitecoinMainnet,
        Chain::BitcoinTestnet4,
        Chain::BitcoinRegtest,
        Chain::LitecoinTestnet,
    ];
    CHAINS.into_iter().find(|chain| {
        chain
            .genesis()
            .is_ok_and(|genesis| genesis.0.to_string() == index.genesis)
    })
}

/// Address of the entry's return output on the index chain: the address the
/// funding wallet designated for this publication. Null for an unknown chain,
/// an entry without a return output or a non-witness script.
fn author_address(index: &Index, entry: &Entry) -> Result<Option<String>, Error> {
    let (Some(chain), Some(script)) = (index_chain(index), entry.return_script.as_ref()) else {
        return Ok(None);
    };
    let bytes = hex::decode(script)?;
    let Some(version) = Script::from_bytes(&bytes).witness_version() else {
        return Ok(None);
    };
    let invalid = |cause: String| Error::Invalid(format!("return script address: {cause}"));
    let hrp = Hrp::parse(chain.address_hrp()).map_err(|e| invalid(e.to_string()))?;
    let encoded = segwit::encode(hrp, Fe32::from(version), &bytes[2..])
        .map_err(|e| invalid(e.to_string()))?;
    Ok(Some(encoded))
}
fn render(index: &Index, entry: &Entry, record: PublicRecord) -> Result<Value, Error> {
    let payload = match record {
        PublicRecord::Post(text) => json!({"kind":"post","text":text}),
        PublicRecord::WirePost { topics, text } => {
            json!({"kind":"post","text":text,"wire":topics.wire,"hashtags":topics.hashtags})
        }
        PublicRecord::WireReply {
            target,
            topics,
            text,
        } => {
            json!({"kind":"reply","reply_to":target.to_string(),"text":text,"wire":topics.wire,"hashtags":topics.hashtags})
        }
        PublicRecord::Reply { target, text } => {
            json!({"kind":"reply","reply_to":target.to_string(),"text":text})
        }
        PublicRecord::Profile(name) => json!({"kind":"profile","name":name}),
        PublicRecord::Avatar(pixels) => json!({"kind":"avatar","pixels_hex":hex::encode(*pixels)}),
        PublicRecord::ProfileRecord { .. } => {
            return Err(Error::Invalid("kind 0C is not a Wire record".into()));
        }
    };
    Ok(
        json!({"txid":entry.txid,"author":entry.author,"author_address":author_address(index, entry)?,"height":entry.height,"position":entry.position,"payload":payload}),
    )
}
