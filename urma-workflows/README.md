# urma-workflows

**Archive and identity-vault operations built from shared components.**

[crates.io](https://crates.io/crates/urma-workflows) · [API reference](https://docs.rs/urma-workflows/latest/urma_workflows/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-workflows) · [URMA](https://urma.rosint.org)

Use `urma-workflows` for the small application-level operations that combine the core, identity and runtime layers. It provides archive sealing/recovery and identity-vault file workflows.

## Get started

```sh
cargo add urma-workflows
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`archive`](https://docs.rs/urma-workflows/latest/urma_workflows/archive/) | Seal private content and recover it from a `RecordSource`; read private recovery-key files. |
| [`vault`](https://docs.rs/urma-workflows/latest/urma_workflows/vault/) | Identity-vault creation, loading and recovery operations. |

## Where it fits

For archive bytes, start with `archive::seal` and `archive::recover`, using a `RecoverySecret` from [urma-identity](https://crates.io/crates/urma-identity). For collections, catalogs and Capture sessions, use [urma-files](https://crates.io/crates/urma-files). For command-line use, install [urma-cli](https://crates.io/crates/urma-cli).

## Boundaries

Sealing content does not publish it. Recovering an archive needs the matching recovery secret and accessible records. Identity-vault recovery and private-content recovery are separate operations.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
