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

`p2p::P2pProvider::new(chain, cache_dir)` loads the Litecoin header cache synchronously from an embedded retarget-boundary checkpoint. Its worker starts when explicitly warmed or when the router considers block or header reads. The worker connects outbound to Litecoin peers found through the DNS seeds and syncs headers. Once ready, the provider serves `getblockchaininfo`, `getblockhash`, `getblockheader` and `getblock(hash, 0)` through the `Provider` trait with `Evidence::LightClientInclusion` and Esplora block framing. Incoming headers are validated for continuity, scrypt proof of work, the Core retarget schedule, median-time-past and clock horizon; the most-work branch presented by connected peers wins and a reorganization drops cached blocks above the fork. Blocks are checked against the verified header and their Merkle and witness commitments.

The V0 header cache uses atomic writes under the caller's directory. Reload checks the embedded checkpoint and its trusted successor, continuity throughout the file, and difficulty transitions and median-time-past across the entire available history. The first successor is pinned by hash and exempt from the expected-difficulty calculation. Median-time-past uses up to 11 preceding headers from the available history; bootstrap does not supply the headers before the checkpoint. Scrypt proof of work is rechecked for the last 2,016 cached headers, or all post-checkpoint headers if fewer are present. The older prefix is trusted local state previously accepted by the client; reload does not independently re-prove its work. Keep this trust boundary when copying or restoring a cache.

The clock horizon applies separately to incoming peer headers. Reload does not compare historical timestamps with today's clock, so a clock that has moved backwards does not invalidate or delete the cache. Such a clock can still cause incoming headers to fail the live horizon check.

Trust statement: P2P validates headers and fetched block commitments. It relies on the embedded checkpoint, the cached prefix and the chain branches connected peers present. It does not validate scripts, amounts, MWEB extension data or the UTXO set, and it cannot detect a majority-hashrate chain that violates consensus rules. Transaction inclusion requires checking the transaction against the fetched block; a public provider's inclusion report alone does not establish it. The checkpoint is a trusted root: mainnet height 3187295/3187296 and testnet height 4904927/4904928, each cross-checked against two independent public sources before embedding. `progress()` reports headers synced against the best peer height so callers can show real sync state; the provider only advertises its methods after a full header round has completed and while peers are connected.

### Measuring startup

From the workspace root, run the offline harness in Cargo's optimized release profile:

```sh
URMA_STARTUP_SAMPLES=7 URMA_STARTUP_REVISION=contextual \
  cargo test --offline --locked --release -p urma-runtime --target-dir target \
  --test p2p_startup_costs -- --ignored --nocapture
```

This always uses the two committed retarget fixtures, each with 2,018 headers (161,440 bytes). To additionally measure an existing cache, set `URMA_STARTUP_CACHE` to an absolute file path and `URMA_STARTUP_CHAIN` to `mainnet` or `testnet`. Input reads are bounded to the production capacity, and the loader receives a temporary copy. JSON records include byte digest, anchor/start height, tip hash, count and size so before/after runs can be checked for identical input. No cache path appears in successful JSON; input errors retain normal path context.

Each dataset gets one unreported warmup, then 7 samples by default (configurable from 3 to 100), in serial order: production reload, standalone tail PoW, standalone full PoW. Reload includes reading, decoding, contextual replay, tail PoW and index construction; contextual timings come directly from production tracing. Standalone PoW uses already decoded headers and the production worker cap, proving the anchor first. It does not enable full PoW in production. The file cache is warm; host load and CPU frequency are uncontrolled. Before/after reload totals also include the changed tracing overhead. Small fixtures and ordinary caches do not establish the worst case of testnet's minimum-difficulty lookback. Absent stage events are omitted rather than reported as zero.

For a separate, explicitly requested live read-only probe on a copy of a cache:

```sh
URMA_STARTUP_CACHE=/absolute/path/to/headers.bin URMA_STARTUP_CHAIN=testnet \
  python3 scripts/measure-startup-live.py
```

The wrapper builds in release first, then uses GNU `timeout` with a 90-second deadline and a further 5 seconds before forced termination. Its Python parent owns and removes staging under `target`, including after a timeout. This probe performs public network verification, peer discovery/connect and header sync, with pins and header persistence confined to temporary state. It installs a global subscriber so worker events are emitted as they complete, including partial measurements before a timeout. It publishes no transactions and accesses no wallet keys. A successful run is one sample of the connected peers and current network conditions. Cargo's `--offline` prevents dependency downloads; the live test itself accesses the network. The offline harness command does not run this separate test binary.

Technical timings use DEBUG events on target `urma_startup`, with `stage`, `chain` and `elapsed_ms`. Cache stages separate read/decode/context/PoW/index; other stages separate header-chain construction, network verification, discovery/connect, header requests, batch application and persistence. `header_sync_round` includes requests, application and persistence, so these nested times should not be summed with it. Library hosts must enable this target in their subscriber. The CLI uses `log_level: "debug"` in the JSON settings selected by `URMA_CONFIG`; `URMA_LOG_OUTPUT=stderr` sends diagnostics to the console. Its logging does not use `RUST_LOG`.

## Public transport

`Node::public(chain)` and `Node::public_in(chain, cache_dir)` read the chain without a local node, provider key, paid plan or RPC cookie. Both build a `transport::Router` over providers that implement `transport::Provider`. On native targets, `Node::public_in` adds the built-in P2P light client for Litecoin mainnet and testnet and persists Electrum certificate pins. `Node::public` uses public servers with session-only pins and no P2P light client. `Node::with_providers` accepts any provider set; `Node::connect` uses a local Core node over loopback HTTP with cookie authentication and checks the selected chain's genesis hash.

Although P2P cache loading itself is offline, constructing a `Node` separately verifies the selected network through `getblockhash(0)`. The complete `Node::public_in` constructor therefore requires a network response.

### Provider kinds

| Provider | Transport | Serves | Does not serve |
| --- | --- | --- | --- |
| Electrum (`ssl://host:port`, `tcp://host:port`) | JSON lines over TLS, protocol 1.4 | tip, block hashes, transactions, address unspents, output lookups, broadcast | raw blocks, mempool listing, mempool preflight |
| Esplora (`https://…/api`) | REST | everything above plus raw blocks and the mempool list | mempool preflight |
| JSON-RPC gateway (`https://…`) | Core-style JSON-RPC | node methods including mempool preflight | address unspents |
| P2P light client | native Litecoin peer-to-peer | tip, block hashes, headers and raw blocks anchored to its header chain | transaction lookup, address unspents, output lookups, broadcast, mempool listing and preflight |

With `Node::public_in`, the built-in Litecoin light client sits first in the provider list. Other chains and `Node::public` start with public servers. Applications can supply their own providers through `Node::with_providers`.

### Routing and failover

For every call the router keeps the providers that support the method and orders them by evidence tier and then by health. By default it tries them one at a time without fan-out: the next provider is asked only after the previous one failed or reported absence. Opt-in `Router::race_tip(true)` allows concurrent `getblockchaininfo` calls. Three consecutive failures open a provider's circuit for 30 s; an HTTP 429 or a gateway's own request budget parks it for the `Retry-After` window (default 60 s, at most 300 s). A record that one provider reports as absent is retried on the others; if no tried provider supplies an answer and at least one reports absence, the router returns `Error::Missing` even if the others failed. Every answer is validated against the request before it is returned: block hashes parse, transactions hash to the requested id, blocks decode and match their hash and merkle root in the answering provider's encoding, unspent rows carry the fields the wallet reads. A failed or timed-out read is an error, never an empty balance.

Fallback happens per call. During P2P startup, for history before its checkpoint, for unsupported methods or after a failed P2P call, a public server may supply the answer. HTTP block reads check the requested block hash, Merkle root and witness commitment, but do not independently validate a Litecoin header chain or its difficulty transitions. Configuring P2P alongside HTTP does not cross-validate every HTTP response against P2P. A hash supplied by P2P can constrain a later HTTP block fetch; it does not authenticate a separate HTTP transaction-inclusion claim.

### Defaults per chain

| Chain | Providers, in order |
| --- | --- |
| Litecoin mainnet | `ssl://electrum.ltc.xurious.com:50002`, `ssl://electrum-ltc.bysh.me:50002`, `ssl://backup.electrum-ltc.org:443`, `ssl://electrum1.cipig.net:20063`, `https://litecoinspace.org/api`, `https://litecoin-mainnet.gateway.tatum.io` |
| Litecoin testnet | `ssl://electrum-ltc.bysh.me:51002`, `ssl://electrum.ltc.xurious.com:51002`, `https://litecoinspace.org/testnet/api`, `https://litecoin-testnet.gateway.tatum.io` |
| Bitcoin testnet4 | `https://mempool.space/testnet4/api` |
| Bitcoin regtest | none; use `Node::connect` |

The built-in HTTP and Electrum providers check the selected chain's genesis hash before serving reads; P2P uses that chain's embedded checkpoint and network parameters. `endpoints::defaults(chain)` returns the public-server list; `Node::with_public_sources` accepts your own.

### Certificate pinning

Electrum servers commonly use self-signed certificates, so the TLS session does not rely on certificate authorities. On the first connection to a host the SHA-256 digest of the server's leaf certificate is pinned (trust on first use) and every later handshake must present the same certificate and prove possession of its key. With `Node::public_in(chain, cache_dir)` pins live in `<cache_dir>/electrum-pins/<host>_<port>.sha256`; `Node::public` keeps them in memory for the session and logs that it does so. A changed certificate is refused and logged as `electrum certificate rejected`. For the user that means either the operator rotated the certificate or something between the client and the server is intercepting the connection; delete the pin file only after confirming the new fingerprint with the operator, and until then the router serves reads from the remaining providers.

### Evidence tiers

`Node::inclusion_evidence()` names the weakest provider in the configured set, and journals record that conservative label. A default `Node::public_in` therefore retains `public_provider_observation` even when P2P serves some calls. `Node::observe` reports the provider and evidence of its individual answer; callers must retain those distinctions when combining or caching observations.

| Label | Evidence basis | Limits |
| --- | --- | --- |
| `local_validating_node` | a local Core full node trusted to validate consensus and select the chain | URMA does not independently repeat Core's consensus validation; evidence follows that node's view |
| `light_client_inclusion` | P2P header validation and fetched block commitments, with the V0 cache trust boundary above | transaction inclusion needs a check against the block; no full consensus validation or guarantee of the globally heaviest chain |
| `public_provider_observation` | a third-party report, with local transaction-ID and fetched-block integrity checks | chain selection and inclusion reports remain provider claims; the provider can omit, delay or misreport them |

A routed node never reports `local_validating_node`. Signed records are authenticated by their own signatures at every tier; the tier only states what the inclusion and confirmation counts rest on.

## Where it fits

A typical application prepares and reviews a plan, approves its funding and fees, then publishes while retaining the plan and journal for recovery or continuation. [urma-git](https://crates.io/crates/urma-git), [urma-files](https://crates.io/crates/urma-files) and [urma-cli](https://crates.io/crates/urma-cli) compose these primitives into user workflows.

## Boundaries

Network calls and publication can have external effects and incur fees. Preserve the prepared transaction identity and progress state when resuming work. A successful submission and a confirmed publication are different states; use the observation and recovery APIs for evidence.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
