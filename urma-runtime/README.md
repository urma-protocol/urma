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

## Where it fits

A typical application prepares and reviews a plan, approves its funding and fees, then publishes while retaining the plan and journal for recovery or continuation. [urma-git](https://crates.io/crates/urma-git), [urma-files](https://crates.io/crates/urma-files) and [urma-cli](https://crates.io/crates/urma-cli) compose these primitives into user workflows.

## Boundaries

Network calls and publication can have external effects and incur fees. Preserve the prepared transaction identity and progress state when resuming work. A successful submission and a confirmed publication are different states; use the observation and recovery APIs for evidence.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
