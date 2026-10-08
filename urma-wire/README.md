# urma-wire

**Verified public records and a reorganization-aware local feed.**

[crates.io](https://crates.io/crates/urma-wire) · [API reference](https://docs.rs/urma-wire/latest/urma_wire/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-wire) · [URMA](https://urma.rosint.org)

Use `urma-wire` to read Wire records, maintain a confirmed index and build a feed view. It keeps record verification and chain reconciliation separate from the desktop or browser interface that presents the conversation.

## Get started

```sh
cargo add urma-wire
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`reader`](https://docs.rs/urma-wire/latest/urma_wire/reader/) | The `Reader` interface for blocks, transactions and chain identity. |
| [`index`](https://docs.rs/urma-wire/latest/urma_wire/index/) | Confirmed indexing and reconciliation after chain reorganizations. |
| [`view`](https://docs.rs/urma-wire/latest/urma_wire/view/) | Feed views built from indexed records. |

## Where it fits

Implement the `Reader` interface for your chain data source. [urma-profiles](https://crates.io/crates/urma-profiles) provides typed Wire records; [urma-runtime](https://crates.io/crates/urma-runtime) provides publication primitives. For the existing command-line workflow, start with `urma wire --help` in [urma-cli](https://crates.io/crates/urma-cli).

## Boundaries

An author key identifies a record signer, not a verified real-world person. Linked media remains external to the Wire record unless separately preserved. Feed state can change when the underlying chain reorganizes.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
