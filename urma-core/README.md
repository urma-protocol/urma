# urma-core

**Record formats and proof validation, without I/O.**

[crates.io](https://crates.io/crates/urma-core) · [API reference](https://docs.rs/urma-core/latest/urma_core/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-core) · [URMA](https://urma.rosint.org)

Use `urma-core` when implementing a reader, encoder or verifier for URMA records. It is the protocol foundation shared by Capture, Git, Wire and other application profiles.

## Get started

```sh
cargo add urma-core
```

### Encode and decode a public record

```rust
use urma_core::format::PublicRecord;

fn main() -> Result<(), urma_core::error::Error> {
    let record = PublicRecord::Post("For the record.".to_owned());
    let bytes = record.encode()?;
    assert_eq!(PublicRecord::decode(&bytes)?, record);
    Ok(())
}
```

This round trip checks the record format. Verifying its publication requires the relevant transaction proofs as well.

## API guide

| Entry point | Use it for |
| --- | --- |
| [`format`](https://docs.rs/urma-core/latest/urma_core/format/) | Public records, record kinds and content types. |
| [`container`](https://docs.rs/urma-core/latest/urma_core/container/) | Sealing and reconstruction of private objects. |
| [`envelope`](https://docs.rs/urma-core/latest/urma_core/envelope/) | Taproot record envelopes and transaction proof checks. |
| [`multipart`](https://docs.rs/urma-core/latest/urma_core/multipart/) | Multipart records, inventory, membership and consistency checks. |
| [`topics`](https://docs.rs/urma-core/latest/urma_core/topics/) | Structured topic encoding for Wire records. |

## Where it fits

Use [urma-profiles](https://crates.io/crates/urma-profiles) for typed application records and [urma-runtime](https://crates.io/crates/urma-runtime) for transport, publication and recovery. Private-object sealing takes caller-supplied randomness; key management belongs in [urma-identity](https://crates.io/crates/urma-identity).

## Boundaries

This crate performs no network or filesystem I/O. Protocol byte layouts and limits are defined by the API, rather than duplicated here.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
