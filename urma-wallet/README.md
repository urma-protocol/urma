# urma-wallet

**Addresses, funding inputs and transaction signing.**

[crates.io](https://crates.io/crates/urma-wallet) · [API reference](https://docs.rs/urma-wallet/latest/urma_wallet/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-wallet) · [URMA](https://urma.rosint.org)

Use `urma-wallet` to fund URMA publications and transfers from a BIP84 account. It handles destination parsing, funding-output interpretation and P2WPKH signing without making wallet UI decisions for an application. The identity key never signs a transaction input.

## Get started

```sh
cargo add urma-wallet
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`account`](https://docs.rs/urma-wallet/latest/urma_wallet/account/) | BIP84 account keys, receive and change addresses, multi-input P2WPKH signing. |
| [`address`](https://docs.rs/urma-wallet/latest/urma_wallet/address/) | Destination parsing, including Litecoin legacy base58. |
| [`funding`](https://docs.rs/urma-wallet/latest/urma_wallet/funding/) | Funding transaction inputs and previous-output validation. |
| [`signing`](https://docs.rs/urma-wallet/latest/urma_wallet/signing/) | P2WPKH signature verification. |
| [`wallet`](https://docs.rs/urma-wallet/latest/urma_wallet/wallet/) | Spend requests, fee budgets and wallet operations. |

## Where it fits

Build an `Account` from `Root::account` in [urma-identity](https://crates.io/crates/urma-identity). Use [urma-runtime](https://crates.io/crates/urma-runtime) for network interaction and the publication lifecycle, or `urma wallet --help` in [urma-cli](https://crates.io/crates/urma-cli) for the command-line workflow.

## Boundaries

Each funding output must pay the account child named by its key path. Address or signature construction alone does not establish that an output is currently spendable; network observation and fee approval belong in the surrounding workflow.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Cristian Zmole. [Project contact](mailto:urma@rosint.org).
