# URMA

This repository contains the URMA Rust workspace. It includes libraries for identity and wallet operations, records and proofs, archives, Git and web profiles, plus the `urma` command-line program.

Project homepage: [urma.rosint.org](https://urma.rosint.org). This checkout is a snapshot being prepared for release; its current changes should not be assumed to be present in a published `0.2.0` package.

## Workspace

The crates are organized around reusable components:

- `urma-core`, `urma-io`, `urma-chain`, `urma-identity` and `urma-wallet` provide the foundational APIs.
- `urma-profiles`, `urma-wire`, `urma-names` and `urma-web` handle record and profile formats.
- `urma-runtime`, `urma-workflows`, `urma-files` and `urma-git` provide higher-level operations.
- `urma-cli` provides the `urma` command-line program.

Each crate has its own README with a brief description. The crate manifests describe dependencies and current package versions.

## Build and install from this checkout

With a Rust toolchain and Cargo installed, run from the repository root:

```sh
cargo build -p urma-cli --locked
cargo install --path urma-cli --locked
```

The installed executable is `urma`. For a first read-only Git checkout on Litecoin testnet, provide a real transaction ID:

```sh
urma git clone '<TXID>' --testnet
```

The CLI defaults to Litecoin mainnet when no network flag is specified.

## Development

Use `cargo check --workspace` to check the workspace, or `cargo test -p <crate>` to test a specific crate.

## License

The workspace is licensed under [0BSD](LICENSE).
