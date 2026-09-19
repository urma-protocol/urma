use bitcoin::{Txid, hashes::Hash};
use urma::error::{Context, Error};
use urma_core::multipart::{
    ChildReference, DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest,
};
use urma_identity::identity::IdentitySigner;

pub struct Quote {
    pub records: u32,
    pub maximum_fee: u64,
    pub funding: u64,
}

pub fn multipart(length: u64, signer: &impl IdentitySigner, rate: u64) -> Result<Quote, Error> {
    let geometry = Geometry::new(length)?;
    let public = signer.public_key().inner.x_only_public_key().0;
    let script = urma_wallet::signing::script(signer)?;
    let mut fees = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for index in 0..geometry.nodes() {
        let record = sample(geometry, index)?.encode()?;
        let fee = match fees.get(&record.len()) {
            Some(fee) => *fee,
            None => {
                let fee = urma::publication::quote_record(&record, public, &script, rate)?;
                fees.insert(record.len(), fee);
                fee
            }
        };
        total = total.checked_add(fee).context("quote overflow")?;
    }
    let funding = total
        .checked_add(u64::from(geometry.nodes()) * 1000 + 1000)
        .context("quote funding overflow")?;
    Ok(Quote {
        records: geometry.nodes(),
        maximum_fee: total,
        funding,
    })
}

fn references(count: usize) -> Result<Vec<ChildReference>, Error> {
    let mut result = Vec::new();
    for index in 0..count {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(u64::try_from(index)? + 1).to_le_bytes());
        result.push(ChildReference {
            txid: Txid::from_byte_array(id),
            record_hash: [0; 32],
        });
    }
    Ok(result)
}

fn sample(geometry: Geometry, index: u32) -> Result<MultipartRecord, Error> {
    if index < geometry.parts() {
        return Ok(MultipartRecord::Data(DataPart {
            index: 0,
            payload: vec![0; geometry.part_length(index)?],
        }));
    }
    let leaf = index - geometry.parts();
    if leaf < u32::from(geometry.leaves()) {
        return Ok(MultipartRecord::Leaf(LeafManifest {
            index: u16::try_from(leaf)?,
            entries: references(usize::from(geometry.leaf_entries(u16::try_from(leaf)?)?))?,
        }));
    }
    Ok(MultipartRecord::Root(RootManifest {
        length: geometry.length(),
        payload_hash: [0; 32],
        profile: [0; 8],
        entries: references(usize::from(geometry.leaves()))?,
    }))
}
