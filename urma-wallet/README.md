# urma-wallet

**Addresses, funding inputs and transaction signing.**

[crates.io](https://crates.io/crates/urma-wallet) · [API reference](https://docs.rs/urma-wallet/latest/urma_wallet/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-wallet) · [URMA](https://urma.rosint.org)

Use `urma-wallet` to connect an URMA identity signer to publication funding. It handles address construction, funding-output interpretation and signing without making wallet UI decisions for an application.

## Get started

```sh
cargo add urma-wallet
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`address`](https://docs.rs/urma-wallet/latest/urma_wallet/address/) | Address construction and network-specific address handling. |
| [`funding`](https://docs.rs/urma-wallet/latest/urma_wallet/funding/) | Funding transaction inputs and previous-output validation. |
| [`signing`](https://docs.rs/urma-wallet/latest/urma_wallet/signing/) | Transaction-signing helpers. |
| [`wallet`](https://docs.rs/urma-wallet/latest/urma_wallet/wallet/) | Spend requests, fee budgets and wallet operations. |

## Where it fits

Provide an `IdentitySigner` from [urma-identity](https://crates.io/crates/urma-identity). Use [urma-runtime](https://crates.io/crates/urma-runtime) for network interaction and the publication lifecycle, or `urma wallet --help` in [urma-cli](https://crates.io/crates/urma-cli) for the command-line workflow.

## Boundaries

A funding output must match the signing identity and the operation being prepared. Address or signature construction alone does not establish that an output is currently spendable; network observation and fee approval belong in the surrounding workflow.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
