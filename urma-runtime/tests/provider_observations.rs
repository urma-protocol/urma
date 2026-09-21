pub use urma_runtime::{config, endpoints, error};
pub mod transaction {
    pub use urma_chain::transaction::decode_bounded as decode;
}
pub mod esplora {
    include!("../src/esplora.rs");
}
pub mod remote {
    include!("../src/remote.rs");
}
mod transport {
    include!("../src/transport.rs");

    #[test]
    fn missing_is_not_reported_for_failed_or_malformed_providers() {
        assert!(Pool::new(Vec::new()).is_err());
        let missing = || Error::Missing("transaction not found on selected network".into());
        for (responses, absent) in [
            (vec![missing(), missing()], true),
            (
                vec![missing(), Error::Unsupported("source offline".into())],
                false,
            ),
            (
                vec![Error::Missing("public RPC omitted result".into())],
                false,
            ),
        ] {
            let mut workers = Vec::new();
            let mut threads = Vec::new();
            for response in responses {
                let (sender, receiver) = mpsc::sync_channel::<Request>(1);
                workers.push(sender);
                threads.push(std::thread::spawn(move || {
                    receiver
                        .recv()
                        .unwrap()
                        .response
                        .send(Err(response))
                        .unwrap();
                }));
            }
            let pool = Pool { workers };
            let error = pool
                .call(Chain::LitecoinTestnet, "getrawtransaction", &[])
                .unwrap_err();
            assert_eq!(matches!(error, Error::Missing(_)), absent);
            for worker in threads {
                worker.join().unwrap();
            }
        }
    }
}
