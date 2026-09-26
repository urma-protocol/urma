# urma-identity

**Identity keys, recovery phrases and encrypted vaults.**

[crates.io](https://crates.io/crates/urma-identity) · [API reference](https://docs.rs/urma-identity/latest/urma_identity/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-identity) · [URMA](https://urma.rosint.org)

Use `urma-identity` when an application needs URMA author identities, signing interfaces and password-protected identity storage. It also provides a separate type for private-content recovery secrets.

## Get started

```sh
cargo add urma-identity
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`identity`](https://docs.rs/urma-identity/latest/urma_identity/identity/) | Identity slots, derived keys and the `IdentitySigner` interface. |
| [`keys`](https://docs.rs/urma-identity/latest/urma_identity/keys/) | Author identities and private-content recovery secret types. |
| [`phrase`](https://docs.rs/urma-identity/latest/urma_identity/phrase/) | Identity recovery phrases. |
| [`keyring`](https://docs.rs/urma-identity/latest/urma_identity/keyring/) | Named identities and active identity selection. |
| [`vault`](https://docs.rs/urma-identity/latest/urma_identity/vault/) | Encrypted vault encoding and recovery. |

## Where it fits

Use `IdentitySigner` with [urma-wallet](https://crates.io/crates/urma-wallet) or [urma-runtime](https://crates.io/crates/urma-runtime). For filesystem-level vault operations, start with [urma-workflows](https://crates.io/crates/urma-workflows). The CLI exposes these operations under `urma key`.

## Boundaries

An identity recovery phrase and a private archive recovery secret serve different purposes. Preserving one does not substitute for preserving the other. Applications are responsible for how secrets are collected, stored and backed up.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
