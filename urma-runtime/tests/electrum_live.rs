use bitcoin::{Transaction, consensus::deserialize, hashes::Hash};
use serde_json::{Value, json};
use std::sync::Arc;
use urma_chain::observation::Chain;
use urma_runtime::{
    electrum::Electrum, endpoints::PublicEndpoint, pinning::Pins, transport::Provider,
};

fn scripthash(script: &bitcoin::Script) -> String {
    let mut digest = bitcoin::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array();
    digest.reverse();
    hex::encode(digest)
}

fn segwit_address(script: &bitcoin::Script, hrp: &str) -> Option<String> {
    if !script.is_witness_program() {
        return None;
    }
    let program = &script.as_bytes()[2..];
    let version = bech32::Fe32::try_from(script.as_bytes()[0].saturating_sub(0x50)).ok()?;
    bech32::segwit::encode(bech32::Hrp::parse(hrp).unwrap(), version, program).ok()
}

fn recent_coinbase_payout(
    provider: &Electrum,
    chain: Chain,
    tip: u64,
    hrp: &str,
) -> (u64, String, u32, String, Transaction) {
    for height in (tip.saturating_sub(24)..=tip).rev() {
        let txid = provider
            .probe(
                chain,
                "blockchain.transaction.id_from_pos",
                json!([height, 0]),
            )
            .unwrap();
        let txid = txid.as_str().unwrap().to_owned();
        let raw = provider
            .probe(chain, "blockchain.transaction.get", json!([txid]))
            .unwrap();
        let transaction: Transaction =
            deserialize(&hex::decode(raw.as_str().unwrap()).unwrap()).unwrap();
        assert!(transaction.is_coinbase());
        for (vout, output) in transaction.output.iter().enumerate() {
            if let Some(address) = segwit_address(&output.script_pubkey, hrp) {
                return (
                    height,
                    txid,
                    u32::try_from(vout).unwrap(),
                    address,
                    transaction,
                );
            }
        }
    }
    panic!("no segwit coinbase payout in the last 25 blocks before {tip}");
}

fn probe(chain: Chain, endpoint: &str, hrp: &str) -> Value {
    let pins = tempfile::tempdir().unwrap();
    let provider = Electrum::new(
        PublicEndpoint::Electrum(endpoint.into()),
        Arc::new(Pins::in_directory(pins.path()).unwrap()),
    )
    .unwrap();
    let tip = provider.call(chain, "getblockchaininfo", &[]).unwrap();
    let genesis = provider.call(chain, "getblockhash", &[json!(0)]).unwrap();
    assert_eq!(genesis, json!(chain.genesis().unwrap().0.to_string()));
    let features = provider.probe(chain, "server.features", json!([])).unwrap();
    assert_eq!(
        features["genesis_hash"],
        json!(chain.genesis().unwrap().0.to_string())
    );
    let height = tip["blocks"].as_u64().unwrap();
    let (block, coinbase, vout, address, transaction) =
        recent_coinbase_payout(&provider, chain, height, hrp);
    let script = &transaction.output[usize::try_from(vout).unwrap()].script_pubkey;
    let balance = provider
        .probe(
            chain,
            "blockchain.scripthash.get_balance",
            json!([scripthash(script)]),
        )
        .unwrap();
    let rows = provider
        .call(chain, "addressutxos", &[json!(address)])
        .unwrap();
    let rows = rows.as_array().unwrap();
    let unspent_total: u64 = rows.iter().map(|row| row["value"].as_u64().unwrap()).sum();
    assert!(
        rows.iter()
            .any(|row| row["txid"] == json!(coinbase) && row["vout"] == json!(vout))
    );
    let coinbase_out = provider
        .call(
            chain,
            "gettxout",
            &[json!(coinbase), json!(vout), json!(true)],
        )
        .unwrap();
    assert_eq!(coinbase_out["coinbase"], true);
    assert_eq!(
        coinbase_out["confirmations"].as_u64().unwrap(),
        height - block + 1
    );
    let verbose = provider
        .call(chain, "getrawtransaction", &[json!(coinbase), json!(true)])
        .unwrap();
    assert_eq!(
        verbose["confirmations"].as_u64().unwrap(),
        height - block + 1
    );
    let header = provider
        .call(chain, "getblockheader", &[verbose["blockhash"].clone()])
        .unwrap();
    assert_eq!(header["height"], json!(block));
    let pinned = std::fs::read_dir(pins.path().join("electrum-pins"))
        .unwrap()
        .count();
    assert_eq!(pinned, 1);
    json!({
        "chain": chain.label(),
        "endpoint": endpoint,
        "server": features["server_version"],
        "tip": tip,
        "coinbase_block": block,
        "coinbase_txid": coinbase,
        "payout_address": address,
        "payout_vout": vout,
        "scripthash_balance": balance,
        "unspent_rows": rows.len(),
        "unspent_total_sats": unspent_total,
        "coinbase_output": coinbase_out,
    })
}

#[test]
#[ignore = "live read-only Electrum probe; third-party coinbase address, no identity, no broadcast"]
fn live_electrum_servers_serve_genesis_tip_and_third_party_unspents() {
    let mainnet = probe(
        Chain::LitecoinMainnet,
        "ssl://electrum.ltc.xurious.com:50002",
        "ltc",
    );
    eprintln!("{}", serde_json::to_string_pretty(&mainnet).unwrap());
    let testnet = probe(
        Chain::LitecoinTestnet,
        "ssl://electrum-ltc.bysh.me:51002",
        "tltc",
    );
    eprintln!("{}", serde_json::to_string_pretty(&testnet).unwrap());
    assert!(mainnet["tip"]["blocks"].as_u64().unwrap() > 2_000_000);
    assert!(testnet["tip"]["blocks"].as_u64().unwrap() > 1_000_000);
}
