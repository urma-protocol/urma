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

## Where it fits

A typical application prepares and reviews a plan, approves its funding and fees, then publishes while retaining the plan and journal for recovery or continuation. [urma-git](https://crates.io/crates/urma-git), [urma-files](https://crates.io/crates/urma-files) and [urma-cli](https://crates.io/crates/urma-cli) compose these primitives into user workflows.

## Boundaries

Network calls and publication can have external effects and incur fees. Preserve the prepared transaction identity and progress state when resuming work. A successful submission and a confirmed publication are different states; use the observation and recovery APIs for evidence.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
