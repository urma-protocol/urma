use urma_chain::observation::Chain;
use urma_runtime::{
    endpoints::{self, PublicEndpoint},
    node::{Node, Presence},
};

const ROOT: &str = "a84ed0fe81ac9addead54fe04b3909165cdecd3b7f177251eeb416d4bcb4877f";

#[test]
fn public_sources_are_https_and_never_accept_credentials() {
    for (chain, count, electrum) in [
        (Chain::LitecoinMainnet, 6, 4),
        (Chain::LitecoinTestnet, 4, 2),
    ] {
        let sources = endpoints::defaults(chain);
        assert_eq!(sources.len(), count);
        let electrum_count = sources
            .iter()
            .filter(|source| matches!(source, PublicEndpoint::Electrum(_)))
            .count();
        assert_eq!(electrum_count, electrum);
        assert!(matches!(sources[0], PublicEndpoint::Electrum(_)));
        assert!(
            !sources
                .iter()
                .any(|source| source.url().contains("testnetscan"))
        );
        for source in sources {
            source.validate().unwrap();
        }
    }
    for url in [
        "http://example.org",
        "https://user:password@example.org",
        "https://example.org/?token=secret",
    ] {
        assert!(PublicEndpoint::Rpc(url.into()).validate().is_err());
    }
    for url in [
        "https://electrum.example.org:50002",
        "ssl://electrum.example.org",
        "ssl://user:pw@electrum.example.org:50002",
        "ssl://electrum.example.org:50002/path",
    ] {
        assert!(PublicEndpoint::Electrum(url.into()).validate().is_err());
    }
    let plain = PublicEndpoint::Electrum("tcp://127.0.0.1:50001".into());
    assert_eq!(
        plain.electrum_target().unwrap().wire,
        endpoints::Wire::PlainTcp
    );
    let tls = PublicEndpoint::Electrum("ssl://electrum.example.org:50002".into());
    assert_eq!(tls.electrum_target().unwrap().wire, endpoints::Wire::Tls);
    assert_ne!(
        Chain::LitecoinMainnet.genesis().unwrap(),
        Chain::LitecoinTestnet.genesis().unwrap()
    );
}

#[test]
#[ignore = "read-only public HTTPS gate; no identity, signing or broadcast"]
fn live_wrong_network_source_falls_back_and_explorer_recovers_the_same_bytes() {
    let root = ROOT.parse().unwrap();
    let rpc = Node::with_public_sources(
        Chain::LitecoinTestnet,
        vec![
            PublicEndpoint::Rpc("https://litecoin-mainnet.gateway.tatum.io".into()),
            PublicEndpoint::Rpc("https://litecoin-testnet.gateway.tatum.io".into()),
            PublicEndpoint::Esplora("https://litecoinspace.org/testnet/api".into()),
        ],
    )
    .unwrap();
    let tx = rpc.transaction(root).unwrap();
    assert_eq!(tx.compute_txid(), root);
    assert!(matches!(
        rpc.presence(root).unwrap(),
        Presence::Confirmed { .. }
    ));
    let explorer = Node::with_public_sources(
        Chain::LitecoinTestnet,
        vec![
            PublicEndpoint::Rpc("https://127.0.0.1:9".into()),
            PublicEndpoint::Esplora("https://litecoinspace.org/testnet/api".into()),
        ],
    )
    .unwrap();
    assert_eq!(explorer.transaction(root).unwrap(), tx);
    assert!(matches!(
        explorer.presence(root).unwrap(),
        Presence::Confirmed { .. }
    ));
    let verified = urma_runtime::recovery::verified_record(&explorer, root).unwrap();
    assert_eq!(verified.txid(), root);
}
