use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use urma_chain::observation::Chain;
use urma_runtime::{
    error::Error,
    transport::{BlockEncoding, Evidence, Provider, Router},
};

const ABSENT: &str = "transaction not found on selected network";

struct Fake {
    name: &'static str,
    evidence: Evidence,
    unsupported: &'static [&'static str],
    replies: Mutex<Vec<Result<Value, Error>>>,
    calls: Arc<AtomicUsize>,
}

impl Fake {
    fn new(name: &'static str, replies: Vec<Result<Value, Error>>) -> Self {
        Self {
            name,
            evidence: Evidence::PublicProviderObservation,
            unsupported: &[],
            replies: Mutex::new(replies),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn light(mut self) -> Self {
        self.evidence = Evidence::LightClientInclusion;
        self
    }

    fn without(mut self, methods: &'static [&'static str]) -> Self {
        self.unsupported = methods;
        self
    }

    fn boxed(self) -> Box<dyn Provider> {
        Box::new(self)
    }
}

impl Provider for Fake {
    fn label(&self) -> String {
        self.name.to_owned()
    }
    fn evidence(&self) -> Evidence {
        self.evidence
    }
    fn block_encoding(&self) -> BlockEncoding {
        BlockEncoding::Core
    }
    fn supports(&self, method: &str) -> bool {
        !self.unsupported.contains(&method)
    }
    fn call(&self, _chain: Chain, _method: &str, _args: &[Value]) -> Result<Value, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut replies = self.replies.lock().unwrap();
        if replies.is_empty() {
            return Err(Error::Unsupported(format!("{} exhausted", self.name)));
        }
        replies.remove(0)
    }
}

fn hash() -> Value {
    json!("11".repeat(32))
}

fn missing() -> Error {
    Error::Missing(ABSENT.into())
}

fn offline() -> Error {
    Error::Unsupported("source offline".into())
}

#[test]
fn missing_is_not_reported_for_failed_or_malformed_providers() {
    assert!(Router::new(Vec::new()).is_err());
    for (responses, absent) in [
        (vec![missing(), missing()], true),
        (vec![missing(), offline()], false),
        (
            vec![Error::Missing("public RPC omitted result".into())],
            false,
        ),
    ] {
        let providers = responses
            .into_iter()
            .map(|response| Fake::new("fake", vec![Err(response)]).boxed())
            .collect();
        let router = Router::new(providers).unwrap();
        let error = router
            .call(
                Chain::LitecoinTestnet,
                "getrawtransaction",
                &[json!("00"), json!(false)],
            )
            .unwrap_err();
        assert_eq!(matches!(error, Error::Missing(_)), absent);
    }
}

#[test]
fn capability_routing_skips_providers_without_the_method() {
    let router = Router::new(vec![
        Fake::new("rpc", vec![Ok(json!([]))])
            .without(&["addressutxos"])
            .boxed(),
        Fake::new("esplora", vec![Ok(json!([]))]).boxed(),
    ])
    .unwrap();
    let rows = router
        .answer(Chain::LitecoinTestnet, "addressutxos", &[json!("addr")])
        .unwrap();
    assert_eq!(rows.label, "esplora");
    assert!(
        router
            .call(Chain::LitecoinTestnet, "getindexinfo", &[])
            .is_err()
    );
}

#[test]
fn failover_is_sequential_in_evidence_then_configured_order() {
    let weak = Fake::new("weak", vec![Ok(hash()), Ok(hash())]);
    let strong = Fake::new("strong", vec![Err(offline()), Ok(hash())]).light();
    let router = Router::new(vec![weak.boxed(), strong.boxed()]).unwrap();
    let first = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(first.label, "weak");
    let second = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(second.label, "strong");
}

#[test]
fn no_fan_out_when_the_first_candidate_answers() {
    let router = Router::new(vec![
        Fake::new("a", vec![Ok(hash())]).boxed(),
        Fake::new("b", vec![Ok(hash())]).boxed(),
    ])
    .unwrap();
    let answer = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(answer.label, "a");
    let second = router
        .call(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(second, hash());
    assert!(
        router
            .call(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
            .is_err()
    );
}

#[test]
fn circuit_breaker_opens_after_consecutive_failures() {
    let flaky = Fake::new(
        "flaky",
        vec![Err(offline()), Err(offline()), Err(offline()), Ok(hash())],
    );
    let steady = Fake::new(
        "steady",
        vec![Ok(hash()), Ok(hash()), Ok(hash()), Ok(hash())],
    );
    let router = Router::new(vec![flaky.boxed(), steady.boxed()]).unwrap();
    for _ in 0..3 {
        let answer = router
            .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
            .unwrap();
        assert_eq!(answer.label, "steady");
    }
    let answer = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(answer.label, "steady");
    assert_eq!(router.labels(), vec!["flaky", "steady"]);
}

#[test]
fn rate_limited_provider_is_skipped_until_its_cooldown_passes() {
    let limited = Fake::new(
        "limited",
        vec![
            Err(Error::RateLimited(Duration::from_secs(120))),
            Ok(hash()),
        ],
    );
    let spare = Fake::new("spare", vec![Ok(hash()), Ok(hash())]);
    let router = Router::new(vec![limited.boxed(), spare.boxed()]).unwrap();
    let first = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(first.label, "spare");
    let second = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(second.label, "spare");
}

#[test]
fn tip_race_is_bounded_and_only_for_tip_queries() {
    let tip = || Ok(json!({"blocks":1,"bestblockhash":hash(),"initialblockdownload":false}));
    let a = Fake::new("a", vec![tip(), Ok(hash()), tip()]);
    let b = Fake::new("b", vec![tip(), tip()]);
    let c = Fake::new("c", vec![tip(), tip()]);
    let (a_calls, b_calls, c_calls) = (a.calls.clone(), b.calls.clone(), c.calls.clone());
    let router = Router::new(vec![a.boxed(), b.boxed(), c.boxed()])
        .unwrap()
        .race_tip(true);
    router
        .call(Chain::LitecoinTestnet, "getblockchaininfo", &[])
        .unwrap();
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b_calls.load(Ordering::SeqCst), 1);
    assert_eq!(c_calls.load(Ordering::SeqCst), 0);
    let answer = router
        .answer(Chain::LitecoinTestnet, "getblockhash", &[json!(1)])
        .unwrap();
    assert_eq!(answer.label, "a");
    assert_eq!(b_calls.load(Ordering::SeqCst), 1);
    router
        .call(Chain::LitecoinTestnet, "getblockchaininfo", &[])
        .unwrap();
    assert_eq!(c_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn evidence_is_the_weakest_tier_and_never_local() {
    let router = Router::new(vec![
        Fake::new("light", Vec::new()).light().boxed(),
        Fake::new("public", Vec::new()).boxed(),
    ])
    .unwrap();
    assert_eq!(router.evidence(), Evidence::PublicProviderObservation);
    let light_only = Router::new(vec![Fake::new("light", Vec::new()).light().boxed()]).unwrap();
    assert_eq!(light_only.evidence(), Evidence::LightClientInclusion);
    assert_eq!(light_only.evidence().label(), "light_client_inclusion");
}
