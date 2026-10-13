# urma-node-client

**Typed loopback access to a local URMA Node.**

[crates.io](https://crates.io/crates/urma-node-client) · [API reference](https://docs.rs/urma-node-client/latest/urma_node_client/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-node-client) · [URMA](https://urma.rosint.org)

Use `urma-node-client` when an application talks to an explicitly configured local [URMA Node](https://github.com/urma-protocol/urma-node) over its bearer-authenticated loopback API. The client reads status, records, objects, the Wire index and Names projections. It never opens an archive, starts a daemon or joins a peer network.

## Get started

```sh
cargo add urma-node-client
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`Client`](https://docs.rs/urma-node-client/latest/urma_node_client/struct.Client.html) | Requests to a node at a loopback endpoint with a bearer token. |
| [`model`](https://docs.rs/urma-node-client/latest/urma_node_client/model/) | `ServiceStatus` and the other typed responses; `API_VERSION` versions the contract. |
| [`names`](https://docs.rs/urma-node-client/latest/urma_node_client/names/) | Names V0 status, resolution and paged views. |
| [`projection`](https://docs.rs/urma-node-client/latest/urma_node_client/projection/) | Wire pages and cursors: application views over the archive's local index. |

## Where it fits

The daemon and its desktop app live in [urma-node](https://github.com/urma-protocol/urma-node). [urma-cli](https://crates.io/crates/urma-cli) uses this client when an `archive` endpoint is configured; without one, every URMA client stays autonomous.

## Boundaries

Responses come from the trusted local operator. Typed decoding does not independently verify records cryptographically, and it is not evidence that the chain data is complete.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
