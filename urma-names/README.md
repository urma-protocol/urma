# urma-names

**Registry-based names with deterministic state and resolution.**

[crates.io](https://crates.io/crates/urma-names) · [API reference](https://docs.rs/urma-names/latest/urma_names/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-names) · [URMA](https://urma.rosint.org)

Use `urma-names` to encode URMANAM1 records, evaluate registry state and resolve a name within a particular registry. It includes both the state engine and the indexing/scanning support needed to follow the chain.

## Get started

```sh
cargo add urma-names
```

### Validate a name

```rust
use urma_names::name::Name;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = Name::parse("newsroom")?;
    assert_eq!(name.as_str(), "newsroom");
    Ok(())
}
```

Parsing validates the label; it neither requests nor registers a name.

## API guide

| Entry point | Use it for |
| --- | --- |
| [`name`](https://docs.rs/urma-names/latest/urma_names/name/) | Name parsing and normalization. |
| [`payload`](https://docs.rs/urma-names/latest/urma_names/payload/) | Registry payload encoding and decoding. |
| [`engine`](https://docs.rs/urma-names/latest/urma_names/engine/) | Registry state transitions and resolution. |
| [`state`](https://docs.rs/urma-names/latest/urma_names/state/) | Name and approval state. |
| [`index`](https://docs.rs/urma-names/latest/urma_names/index/) | Persisted names-index handling. |
| [`scan`](https://docs.rs/urma-names/latest/urma_names/scan/) | Chain scanning and reconciliation. |

## Where it fits

Use [urma-web](https://crates.io/crates/urma-web) for the site publications that a registry can reference. [urma-cli](https://crates.io/crates/urma-cli) exposes request, review, approval, scan and resolution commands, plus the HTTP gateway.

## Boundaries

Names are scoped to registry state and a network; this is not DNS or a universal namespace. A resolver needs an up-to-date index. Registry approval rules, pending requests and chain reorganizations affect what resolves.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
