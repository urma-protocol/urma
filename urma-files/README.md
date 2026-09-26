# urma-files

**Private collections and Capture workflows for journalistic originals.**

[crates.io](https://crates.io/crates/urma-files) · [API reference](https://docs.rs/urma-files/latest/urma_files/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-files) · [URMA](https://urma.rosint.org)

Use `urma-files` to ingest files and directories, describe them in authenticated catalogs, and recover them later. Its Capture layer adds session context and relationships between originals and derivatives for journalism workflows.

## Get started

```sh
cargo add urma-files
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`ingest`](https://docs.rs/urma-files/latest/urma_files/ingest/) | Collection ingestion and encrypted content preparation. |
| [`catalog`](https://docs.rs/urma-files/latest/urma_files/catalog/) | Catalog entries, content descriptions and collection structure. |
| [`capture`](https://docs.rs/urma-files/latest/urma_files/capture/) | Capture sessions, originals, derivatives and context validation. |
| [`inventory`](https://docs.rs/urma-files/latest/urma_files/inventory/) | Collection inventory operations. |
| [`chain`](https://docs.rs/urma-files/latest/urma_files/chain/) | Collection publication and chain recovery integration. |
| [`recover`](https://docs.rs/urma-files/latest/urma_files/recover/) | Restoring content from a collection. |
| [`safety`](https://docs.rs/urma-files/latest/urma_files/safety/) | Filesystem safety checks for file workflows. |

## Where it fits

The CLI exposes these workflows as `urma capture` and `urma archive`. Use [urma-identity](https://crates.io/crates/urma-identity) for recovery secrets and [urma-runtime](https://crates.io/crates/urma-runtime) for publication and transport. This crate is the file/Capture foundation for applications, rather than a camera interface.

## Boundaries

A recovery route beyond the original device requires that the necessary records survive and remain accessible, along with the private recovery secret. Authenticated context preserves what was recorded; it does not independently prove that a scene or assertion was true.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
