use bitcoin::{
    Transaction,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_core::multipart::{DataPart, Geometry, MultipartRecord};
use urma_identity::{
    identity::IdentitySigner, keyring::Keyring, phrase::IdentityPhrase, root::Root,
};
use urma_wallet::{
    account::{Account, KeyPath},
    funding::Funding,
    wallet::{FeeBudget, FeeRate, SpendRequest},
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "isolated Litecoin regtest; no live network or real keys"]
fn litecoin_standard_full_record_and_dust() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/urma-ltc-policy");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::tempdir_in(root).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _daemon = Daemon(
        Command::new("litecoind")
            .arg(format!("-datadir={}", directory.path().display()))
            .arg(format!("-rpcport={port}"))
            .args([
                "-regtest",
                "-server=1",
                "-listen=0",
                "-connect=0",
                "-dnsseed=0",
                "-discover=0",
                "-acceptnonstdtxn=0",
                "-dustrelayfee=0.0003",
                "-txindex=1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let rpc = loop {
        if let Ok(client) = Client::new(
            &format!("http://127.0.0.1:{port}"),
            Auth::CookieFile(directory.path().join("regtest/.cookie")),
        ) && client.call::<Value>("getblockchaininfo", &[]).is_ok()
        {
            break client;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "Litecoin startup failed"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let signer = Keyring::create(&phrase, "public-test-vector")
        .unwrap()
        .active()
        .unwrap();
    let root = Root::from_phrase(&phrase).unwrap();
    let funder = Account::new(
        Chain::LitecoinTestnet,
        root.account(Chain::LitecoinTestnet).unwrap(),
    )
    .unwrap();
    let expected = funder.receive_script().unwrap();
    let descriptor: Value = rpc
        .call(
            "getdescriptorinfo",
            &[json!(format!("raw({})", hex::encode(expected.as_bytes())))],
        )
        .unwrap();
    let addresses: Value = rpc
        .call("deriveaddresses", &[descriptor["descriptor"].clone()])
        .unwrap();
    let address = &addresses[0];
    let blocks: Value = rpc
        .call("generatetoaddress", &[json!(102), address.clone()])
        .unwrap();
    let block: Value = rpc
        .call("getblock", &[blocks[0].clone(), json!(1)])
        .unwrap();
    let raw: String = rpc
        .call(
            "getrawtransaction",
            &[block["tx"][0].clone(), json!(false), blocks[0].clone()],
        )
        .unwrap();
    let previous: Transaction = deserialize(&hex::decode(&raw).unwrap()).unwrap();
    let vout = previous
        .output
        .iter()
        .position(|out| out.script_pubkey == expected)
        .unwrap();
    let funding = Funding {
        raw_transaction: raw,
        vout: u32::try_from(vout).unwrap(),
    };
    let record = MultipartRecord::Data(DataPart {
        index: 0,
        payload: vec![0xa5; Geometry::DATA_BYTES],
    });
    let small = urma_runtime::publication::prepare_multipart(
        &MultipartRecord::Data(DataPart {
            index: 0,
            payload: vec![],
        }),
        &signer,
        vec![funding.clone()],
        &expected,
        Chain::LitecoinTestnet,
        1,
    )
    .unwrap();
    let small_commit: Transaction = deserialize(&hex::decode(&small.commit).unwrap()).unwrap();
    let small_signed = funder
        .sign(
            &SpendRequest {
                transaction: &small_commit,
                prevouts: std::slice::from_ref(&previous.output[vout]),
                budget: FeeBudget {
                    chain: Chain::LitecoinTestnet.genesis().unwrap(),
                    rate: FeeRate(std::num::NonZeroU64::new(1).unwrap()),
                    maximum_base_units: 500_000,
                },
            },
            &[KeyPath::RECEIVE],
        )
        .unwrap();
    let small_accept: Value = rpc
        .call(
            "testmempoolaccept",
            &[json!([hex::encode(serialize(&small_signed))])],
        )
        .unwrap();
    assert_eq!(small_accept[0]["allowed"], true, "{small_accept}");
    let pair = urma_runtime::publication::prepare_multipart(
        &record,
        &signer,
        vec![funding],
        &expected,
        Chain::LitecoinTestnet,
        1,
    )
    .unwrap();
    let commit: Transaction = deserialize(&hex::decode(&pair.commit).unwrap()).unwrap();
    let signed = funder
        .sign(
            &SpendRequest {
                transaction: &commit,
                prevouts: std::slice::from_ref(&previous.output[vout]),
                budget: FeeBudget {
                    chain: Chain::LitecoinTestnet.genesis().unwrap(),
                    rate: FeeRate(std::num::NonZeroU64::new(1).unwrap()),
                    maximum_base_units: 500_000,
                },
            },
            &[KeyPath::RECEIVE],
        )
        .unwrap();
    let accepted: Value = rpc
        .call(
            "testmempoolaccept",
            &[json!([hex::encode(serialize(&signed))])],
        )
        .unwrap();
    assert_eq!(accepted[0]["allowed"], true, "{accepted}");
    let _: Value = rpc
        .call(
            "sendrawtransaction",
            &[json!(hex::encode(serialize(&signed)))],
        )
        .unwrap();
    let _: Value = rpc
        .call("generatetoaddress", &[json!(1), address.clone()])
        .unwrap();
    let mut reveal: Transaction = deserialize(&hex::decode(&pair.reveal).unwrap()).unwrap();
    assert_eq!(reveal.weight().to_wu(), 264134);
    assert_eq!(reveal.vsize(), 66034);
    assert_eq!(reveal.output[0].value.to_sat(), 3300);
    let accepted: Value = rpc
        .call("testmempoolaccept", &[json!([pair.reveal])])
        .unwrap();
    assert_eq!(accepted[0]["allowed"], true, "{accepted}");
    let parsed = urma_core::envelope::verify_reveal(&reveal, &signed).unwrap();
    assert_eq!(
        MultipartRecord::decode(&parsed.record)
            .unwrap()
            .encode()
            .unwrap()
            .len(),
        262144
    );
    reveal.output[0].value = bitcoin::Amount::from_sat(1000);
    let hash = SighashCache::new(&reveal)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&signed.output[0])),
            TapLeafHash::from_script(&parsed.script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let signature = signer
        .sign_author(Message::from_digest(hash.to_byte_array()))
        .unwrap();
    reveal.input[0].witness = bitcoin::Witness::from_slice(&[
        signature.as_ref(),
        parsed.script.as_bytes(),
        &parsed.control.serialize(),
    ]);
    let rejected: Value = rpc
        .call(
            "testmempoolaccept",
            &[json!([hex::encode(serialize(&reveal))])],
        )
        .unwrap();
    assert_eq!(rejected[0]["allowed"], false, "{rejected}");
    assert_eq!(rejected[0]["reject-reason"], "dust", "{rejected}");
    println!(
        "Litecoin strict policy: 262144-byte record, 264134 WU, 66034 vB accepted; 3300 litoshi retained; 1000-litoshi output rejected as dust."
    );
}

#[test]
fn quote_uses_256k_geometry_and_chain_dust_budget() {
    let phrase = IdentityPhrase::parse(&format!("{}about", "abandon ".repeat(11))).unwrap();
    let signer = Keyring::create(&phrase, "public-test-vector")
        .unwrap()
        .active()
        .unwrap();
    let quote = urma_runtime::quote::multipart(
        480 * Geometry::DATA_BYTES as u64,
        &signer,
        &Account::new(
            Chain::LitecoinTestnet,
            Root::from_phrase(&phrase)
                .unwrap()
                .account(Chain::LitecoinTestnet)
                .unwrap(),
        )
        .unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(quote.parts, 480);
    assert_eq!(quote.leaves, 1);
    assert_eq!(quote.records, 482);
    assert_eq!(quote.retained_value, 3300);
    assert_eq!(quote.funding, quote.maximum_fee + 483 * 3300);
}
