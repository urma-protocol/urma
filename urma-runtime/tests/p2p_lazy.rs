use serde_json::json;
use urma_chain::observation::Chain;
use urma_runtime::config::LITECOIN_MAINNET_CHECKPOINT;
use urma_runtime::light::{LightSync, Progress};
use urma_runtime::p2p::P2pProvider;
use urma_runtime::transport::Provider;

#[test]
fn the_light_client_stays_cold_until_a_block_range_need() {
    let dir = tempfile::tempdir().unwrap();
    let provider = P2pProvider::new(Chain::LitecoinMainnet, dir.path()).unwrap();
    let cold = Progress {
        headers_synced: 0,
        headers_target: 0,
        peers_connected: 0,
        synced: false,
    };
    assert_eq!(provider.state(), LightSync::Cold(cold));
    assert!(!provider.supports("getblockchaininfo"));
    assert!(!provider.supports("getblockhash"));
    assert!(!provider.supports("getrawtransaction"));
    assert!(!provider.supports("sendrawtransaction"));
    assert_eq!(provider.state(), LightSync::Cold(cold));
    let checkpoint = "3d72f3b771193d234afe50762ed0d11adfed33457c06f2274b03f477a683819a";
    let header = provider
        .call(
            Chain::LitecoinMainnet,
            "getblockheader",
            &[json!(checkpoint)],
        )
        .unwrap();
    assert_eq!(header["height"], json!(LITECOIN_MAINNET_CHECKPOINT.height));
    assert_eq!(
        header["hash"],
        json!(checkpoint),
        "header reads are served from the cached chain without a worker"
    );
    let refused = provider
        .call(
            Chain::LitecoinMainnet,
            "getblock",
            &[json!(checkpoint), json!(0)],
        )
        .unwrap_err();
    assert!(refused.to_string().contains("not been started"));
    let refused = provider
        .call(Chain::LitecoinMainnet, "getblockchaininfo", &[])
        .unwrap_err();
    assert!(refused.to_string().contains("not been started"));
    assert!(
        provider
            .call(
                Chain::LitecoinTestnet,
                "getblockheader",
                &[json!(checkpoint)]
            )
            .is_err()
    );
    assert_eq!(provider.state(), LightSync::Cold(cold));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
