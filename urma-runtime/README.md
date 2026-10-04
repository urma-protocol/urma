# urma-runtime

**The publication and recovery layer between records and networks.**

[crates.io](https://crates.io/crates/urma-runtime) · [API reference](https://docs.rs/urma-runtime/latest/urma_runtime/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-runtime) · [URMA](https://urma.rosint.org)

Use `urma-runtime` when an application needs to plan, publish, observe or recover URMA content. It composes record codecs, identity signing, funding and network transports while keeping preparation separate from submission.

## Get started

```sh
cargo add urma-runtime
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`plan`](https://docs.rs/urma-runtime/latest/urma_runtime/plan/) | Publication plans, budgets and validation. |
| [`publication`](https://docs.rs/urma-runtime/latest/urma_runtime/publication/) | Atomic public-record transaction preparation. |
| [`publish`](https://docs.rs/urma-runtime/latest/urma_runtime/publish/) | Publication execution and progress. |
| [`disk_plan`](https://docs.rs/urma-runtime/latest/urma_runtime/disk_plan/) | Disk-backed plans for larger publications. |
| [`disk_publish`](https://docs.rs/urma-runtime/latest/urma_runtime/disk_publish/) | Execution of disk-backed publications. |
| [`source`](https://docs.rs/urma-runtime/latest/urma_runtime/source/) | Sources of records and transaction evidence. |
| [`recovery`](https://docs.rs/urma-runtime/latest/urma_runtime/recovery/) | Recovery of published content. |
| [`journal`](https://docs.rs/urma-runtime/latest/urma_runtime/journal/) | Publication state retained across attempts. |
| [`node`](https://docs.rs/urma-runtime/latest/urma_runtime/node/) | The node-facing runtime interface. |
| [`transport`](https://docs.rs/urma-runtime/latest/urma_runtime/transport/) | The `Provider` trait and the capability router behind public reads. |
| [`p2p`](https://docs.rs/urma-runtime/latest/urma_runtime/p2p/) | Native Litecoin peer-to-peer light client: header sync from an embedded checkpoint, block fetch by hash. |

### Peer-to-peer light client

`p2p::P2pProvider::new(chain, cache_dir)` connects outbound to Litecoin peers found through the DNS seeds, syncs block headers from an embedded retarget-boundary checkpoint and serves `getblockchaininfo`, `getblockhash`, `getblockheader` and `getblock(hash, 0)` through the `Provider` trait with `Evidence::LightClientInclusion` and Esplora block framing. Headers are validated for continuity, scrypt proof of work, the Core retarget schedule, median-time-past and clock horizon; the most-work branch wins and a reorganization drops cached blocks above the fork. Blocks are checked against the verified header and their Merkle and witness commitments. The header chain is cached under the caller's directory with atomic writes; on reload the file is anchored to the checkpoint and the trailing window is re-proved.

Trust statement: this is header-chain plus inclusion validation, not consensus validation. It proves that a block carrying the claimed work is on the heaviest header chain the connected peers present, and that a transaction is inside that block. It does not validate scripts, amounts, MWEB extension data or the UTXO set, and it cannot detect a majority-hashrate chain that violates consensus rules. The checkpoint is a trusted root: mainnet height 3187295/3187296 and testnet height 4904927/4904928, each cross-checked against two independent public sources before embedding. `progress()` reports headers synced against the best peer height so callers can show real sync state; the provider only advertises its methods once the first full header round has completed.

## Public transport

`Node::public(chain)` and `Node::public_in(chain, cache_dir)` read the chain without a local node, provider key, paid plan or RPC cookie. Both build a `transport::Router` over providers that implement `transport::Provider`; `Node::with_providers` accepts any provider set, `Node::connect` keeps the local RPC path.

### Provider kinds

| Provider | Transport | Serves | Does not serve |
| --- | --- | --- | --- |
| Electrum (`ssl://host:port`, `tcp://host:port`) | JSON lines over TLS, protocol 1.4 | tip, block hashes, transactions, address unspents, output lookups, broadcast | raw blocks, mempool listing, mempool preflight |
| Esplora (`https://…/api`) | REST | everything above plus raw blocks and the mempool list | mempool preflight |
| JSON-RPC gateway (`https://…`) | Core-style JSON-RPC | node methods including mempool preflight | address unspents |
| Light client | in-process, supplied by the application | header-chain inclusion checks | provided by the application |

The light client slot sits first in the provider list and is empty in this crate; an application that carries one hands it to `Node::with_providers`.

### Routing and failover

For every call the router keeps the providers that support the method, orders them by evidence tier and then by health, and tries them one at a time. There is no fan-out: one request reaches one provider, and the next provider is asked only after the previous one failed. Three consecutive failures open a provider's circuit for 30 s; an HTTP 429 or a gateway's own request budget parks it for the `Retry-After` window (default 60 s, at most 300 s). A record that one provider reports as absent is retried on the others, and `Error::Missing` is returned only when every tried provider agrees. Every answer is validated against the request before it is returned: block hashes parse, transactions hash to the requested id, blocks decode and match their hash and merkle root in the answering provider's encoding, unspent rows carry the fields the wallet reads. A failed or timed-out read is an error, never an empty balance.

### Defaults per chain

| Chain | Providers, in order |
| --- | --- |
| Litecoin mainnet | `ssl://electrum.ltc.xurious.com:50002`, `ssl://electrum-ltc.bysh.me:50002`, `ssl://backup.electrum-ltc.org:443`, `ssl://electrum1.cipig.net:20063`, `https://litecoinspace.org/api`, `https://litecoin-mainnet.gateway.tatum.io` |
| Litecoin testnet | `ssl://electrum-ltc.bysh.me:51002`, `ssl://electrum.ltc.xurious.com:51002`, `https://litecoinspace.org/testnet/api`, `https://litecoin-testnet.gateway.tatum.io` |
| Bitcoin testnet4 | `https://mempool.space/testnet4/api` |
| Bitcoin regtest | none; use `Node::connect` |

Every provider must return the selected chain's genesis hash before it serves anything else. `endpoints::defaults(chain)` returns the list; `Node::with_public_sources` accepts your own.

### Certificate pinning

Electrum servers commonly use self-signed certificates, so the TLS session does not rely on certificate authorities. On the first connection to a host the SHA-256 digest of the server's leaf certificate is pinned (trust on first use) and every later handshake must present the same certificate and prove possession of its key. With `Node::public_in(chain, cache_dir)` pins live in `<cache_dir>/electrum-pins/<host>_<port>.sha256`; `Node::public` keeps them in memory for the session and logs that it does so. A changed certificate is refused and logged as `electrum certificate rejected`. For the user that means either the operator rotated the certificate or something between the client and the server is intercepting the connection; delete the pin file only after confirming the new fingerprint with the operator, and until then the router serves reads from the remaining providers.

### Evidence tiers

`Node::inclusion_evidence()` names the weakest provider in the set, and journals record it next to every observation.

| Label | Proves | Does not prove |
| --- | --- | --- |
| `local_validating_node` | your own node validated the block and its transactions under consensus rules | nothing beyond your node's view of the chain |
| `light_client_inclusion` | a header chain with valid proof of work includes the transaction at the reported height | that the block's transactions are valid, or that the chain is the heaviest one |
| `public_provider_observation` | a third-party server reported the transaction, its block hash and height, and the bytes hash to the requested id | that the block exists or was validated; a provider can omit, delay or misreport inclusion |

A routed node never reports `local_validating_node`. Signed records are authenticated by their own signatures at every tier; the tier only states what the inclusion and confirmation counts rest on.

## Where it fits

A typical application prepares and reviews a plan, approves its funding and fees, then publishes while retaining the plan and journal for recovery or continuation. [urma-git](https://crates.io/crates/urma-git), [urma-files](https://crates.io/crates/urma-files) and [urma-cli](https://crates.io/crates/urma-cli) compose these primitives into user workflows.

## Boundaries

Network calls and publication can have external effects and incur fees. Preserve the prepared transaction identity and progress state when resuming work. A successful submission and a confirmed publication are different states; use the observation and recovery APIs for evidence.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
