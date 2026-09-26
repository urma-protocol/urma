# urma-web

**Web packages and verified resources for URMA publications.**

[crates.io](https://crates.io/crates/urma-web) · [API reference](https://docs.rs/urma-web/latest/urma_web/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-web) · [URMA](https://urma.rosint.org)

Use `urma-web` to package a static site, describe pinned resources and store recovered publications with verification. It implements the URMAWEB1 profile used by the CLI and the HTTP gateway.

## Get started

```sh
cargo add urma-web
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`package`](https://docs.rs/urma-web/latest/urma_web/package/) | Site packages, file entries, pinned entries and resource lookup. |
| [`pack`](https://docs.rs/urma-web/latest/urma_web/pack/) | Pack a directory using a `PackRequest`. |
| [`grammar`](https://docs.rs/urma-web/latest/urma_web/grammar/) | Path, label and media-type validation. |
| [`store`](https://docs.rs/urma-web/latest/urma_web/store/) | Store and retrieve verified publications and declared resources. |

## Where it fits

Start with `pack::pack_directory` for local packaging. Use [urma-runtime](https://crates.io/crates/urma-runtime) for publication and recovery and [urma-names](https://crates.io/crates/urma-names) for registry resolution. [urma-cli](https://crates.io/crates/urma-cli) provides `urma web` and `urma gateway` for end-to-end operation.

## Boundaries

The package declares which resources belong to a site. Pinned objects must be retrieved and verified as well; a link to an external resource does not preserve it. This crate provides the package and store, while the HTTP server lives in the CLI.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
