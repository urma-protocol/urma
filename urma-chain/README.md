# urma-chain

**Chain observations and transaction validation for URMA readers.**

[crates.io](https://crates.io/crates/urma-chain) · [API reference](https://docs.rs/urma-chain/latest/urma_chain/) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-chain) · [URMA](https://urma.rosint.org)

Use `urma-chain` to describe where a transaction was observed, decode transaction data and apply chain-specific validation. It provides the chain vocabulary used by publication and indexing components.

## Get started

```sh
cargo add urma-chain
```

## API guide

| Entry point | Use it for |
| --- | --- |
| [`observation`](https://docs.rs/urma-chain/latest/urma_chain/observation/) | Chain identities, block references, placement and observation trust. |
| [`transaction`](https://docs.rs/urma-chain/latest/urma_chain/transaction/) | Bounded transaction decoding. |
| [`decode`](https://docs.rs/urma-chain/latest/urma_chain/decode/) | Decoding URMA records from transaction envelopes. |
| [`validation`](https://docs.rs/urma-chain/latest/urma_chain/validation/) | Chain and proof-of-work validation helpers. |
| [`pow`](https://docs.rs/urma-chain/latest/urma_chain/pow/) | Header proof of work per chain (scrypt for Litecoin, sha256d for Bitcoin), Core retarget rules and chainwork. |

`Chain::params()` carries the peer-to-peer magic, default port, DNS seeds, proof-of-work limit and retarget schedule for each supported chain. `pow::expected_bits` reproduces Litecoin Core's `GetNextWorkRequired`, including the 2016-block lookback, the testnet minimum-difficulty rules and 256-bit wraparound of the intermediate product. Header validation is light-client validation: it proves work and continuity, not transaction consensus.

## Where it fits

Connect these types to a transport through [urma-runtime](https://crates.io/crates/urma-runtime), or use them when building a reader for [urma-wire](https://crates.io/crates/urma-wire). See the `Chain` API for supported networks.

## Boundaries

An observation records its trust source. A provider claim and an observation from a validating node are not interchangeable, and a transaction in a mempool is not a confirmed inclusion.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Part of the [URMA workspace](https://github.com/urma-protocol/urma), maintained by Zmole Cristian. [Project contact](mailto:urma@rosint.org).
