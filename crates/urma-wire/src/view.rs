use crate::{
    Error, ensure,
    index::{Entry, Index},
};
use serde_json::{Value, json};
use urma_core::format::PublicRecord;

pub fn records(index: &Index, limit: usize) -> Result<Vec<Value>, Error> {
    ensure!((1..=1000).contains(&limit), "feed limit must be 1..1000");
    index.entries.iter().rev().take(limit).map(render).collect()
}
pub fn record(index: &Index, txid: bitcoin::Txid) -> Result<Value, Error> {
    let txid = txid.to_string();
    let entry = index
        .entries
        .iter()
        .find(|entry| entry.txid == txid)
        .ok_or_else(|| Error::Missing("record is not in the confirmed local index".into()))?;
    render(entry)
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
        match PublicRecord::decode(&hex::decode(&entry.record)?)? {
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
    Ok(json!({"author":author,"profile":profile,"avatar":avatar,"genesis":index.genesis}))
}
fn render(entry: &Entry) -> Result<Value, Error> {
    let payload = match PublicRecord::decode(&hex::decode(&entry.record)?)? {
        PublicRecord::Post(text) => json!({"kind":"post","text":text}),
        PublicRecord::Reply { target, text } => {
            json!({"kind":"reply","reply_to":target.to_string(),"text":text})
        }
        PublicRecord::Profile(name) => json!({"kind":"profile","name":name}),
        PublicRecord::Avatar(pixels) => json!({"kind":"avatar","pixels_hex":hex::encode(*pixels)}),
    };
    Ok(
        json!({"txid":entry.txid,"author":entry.author,"height":entry.height,"position":entry.position,"payload":payload}),
    )
}
