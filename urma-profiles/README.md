# urma-profiles

**Typed application records above the URMA byte format.**

[crates.io](https://crates.io/crates/urma-profiles) · [API reference](https://docs.rs/urma-profiles/latest/urma_profiles/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-profiles) · [URMA](https://urma.rosint.org)

Use `urma-profiles` to give protocol records application-specific meaning. It connects the generic record and private-container primitives to Wire, Git and private-file workflows.

## Get started

```sh
cargo add urma-profiles
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`wire`](https://docs.rs/urma-profiles/latest/urma_profiles/wire/) | Typed public text, reply and identity-profile handling. |
| [`git`](https://docs.rs/urma-profiles/latest/urma_profiles/git/) | Git-specific record/profile encoding. |
| [`private`](https://docs.rs/urma-profiles/latest/urma_profiles/private/) | Private-file and captured-original sealing with typed recovery secrets. |

## Where it fits

Use [urma-core](https://crates.io/crates/urma-core) for the underlying codecs and proof primitives. Use [urma-wire](https://crates.io/crates/urma-wire), [urma-git](https://crates.io/crates/urma-git) or [urma-files](https://crates.io/crates/urma-files) for higher-level indexing and workflows. Names and Web have their own profile crates.

## Boundaries

Encoding a profile is separate from publishing it or proving its inclusion. A profile gives records structure; it does not authenticate a real-world identity or the truth of an assertion.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
