# urma-io

**Small I/O primitives for bounded input and deliberate output.**

[crates.io](https://crates.io/crates/urma-io) · [API reference](https://docs.rs/urma-io/latest/urma_io/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-io) · [URMA](https://urma.rosint.org)

Use `urma-io` for the file operations shared by URMA components: reading with an explicit size limit, writing through a temporary file, and hashing streams.

## Get started

```sh
cargo add urma-io
```

### Hash bytes from a reader

```rust
use std::io::Cursor;

fn main() -> Result<(), std::io::Error> {
    let mut input = Cursor::new(b"For the record.");
    let checksum = urma_io::digest(&mut input)?;
    assert_eq!(input.position(), b"For the record.".len() as u64);
    let _ = checksum;
    Ok(())
}
```

`digest` reads from the stream's current position; it does not rewind it.

## API guide

| Entry point | Use it for |
| --- | --- |
| [`read_bounded`](https://docs.rs/urma-io/latest/urma_io/fn.read_bounded.html) | Read a file with a caller-selected byte limit. |
| [`write_new`](https://docs.rs/urma-io/latest/urma_io/fn.write_new.html) | Write atomically without replacing an existing destination. |
| [`write_replace`](https://docs.rs/urma-io/latest/urma_io/fn.write_replace.html) | Atomically replace a destination. |
| [`digest`](https://docs.rs/urma-io/latest/urma_io/fn.digest.html) | Compute a SHA-256 digest from a reader. |

## Where it fits

For sensitive inputs on supported native targets, see `read_private`, `read_regular` and `create_private_directory` in the API. These are used by [urma-identity](https://crates.io/crates/urma-identity), [urma-runtime](https://crates.io/crates/urma-runtime) and higher-level workflows.

## Boundaries

Native private-file helpers rely on Unix filesystem semantics. A WASM build does not imply browser access to native filesystem operations. Choose the helper appropriate to the target and handle its errors.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
