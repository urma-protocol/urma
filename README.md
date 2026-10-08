# URMA

**For the right to report. For code that stays within reach.**

An open protocol and Rust toolkit for publishing records, verifying what you retrieve, and recovering content through independent readers.

[Website](https://urma.rosint.org) · [Command-line guide](https://github.com/urma-protocol/urma/tree/master/urma-cli#readme) · [Rust packages](https://crates.io/search?q=urma) · [Source](https://github.com/urma-protocol/urma)

## What you can build

**Capture — journalism and freedom of the press.** Preserve journalistic originals and their context with an encrypted recovery route beyond the original device. The workspace provides Capture ingestion, catalogs, publication and recovery components; it is a foundation for applications, not a finished camera product.

**Git — code beyond a single host.** Publish committed snapshots and recover them with verified checkout. This gives code another route for preservation and distribution when a repository or hosting account disappears.

The same foundation also supports:

- **Archives:** encrypted files, directories and collections.
- **Wire:** public text, identities, replies and a locally verified feed.
- **Web and Names:** site packages, pinned resources and registry-based name resolution, with an HTTP gateway for ordinary browsers.

Recovery depends on completed publication and accessible records. Private content also needs its separately preserved recovery secret. Verifying a record establishes properties of the bytes and their proofs; it does not establish the truth of a story or guarantee perpetual availability.

## Start with the command line

Install the published CLI in a Unix environment with a current stable Rust toolchain:

```sh
cargo install urma-cli --locked
urma --help
```

The package is `urma-cli`; the installed program is `urma`.

Explore the workflows without publishing anything:

```sh
urma capture --help
urma git --help
urma archive --help
urma wire --help
urma web --help
urma names --help
```

For each operation, use its help to choose the network, inputs and destination explicitly. Publication can spend network fees. Planning, inspection and recovery are separate steps; the [CLI README](https://github.com/urma-protocol/urma/tree/master/urma-cli#readme) explains where to begin.

## Use the libraries

Add the component your application needs, for example:

```sh
cargo add urma-core
```

The core handles bytes and proofs without network or filesystem I/O. The runtime connects those primitives to transports, publication and recovery. Profiles and workflows give the records application-specific meaning.

| Crate | Responsibility |
| --- | --- |
| [urma-core](https://github.com/urma-protocol/urma/tree/master/urma-core#readme) | Record codecs, private containers and proof validation |
| [urma-io](https://github.com/urma-protocol/urma/tree/master/urma-io#readme) | Bounded reads, atomic writes and stream hashing |
| [urma-chain](https://github.com/urma-protocol/urma/tree/master/urma-chain#readme) | Chain observations, transaction decoding and validation |
| [urma-identity](https://github.com/urma-protocol/urma/tree/master/urma-identity#readme) | Identity keys, recovery phrases and encrypted vaults |
| [urma-wallet](https://github.com/urma-protocol/urma/tree/master/urma-wallet#readme) | Addresses, funding inputs and signing |
| [urma-profiles](https://github.com/urma-protocol/urma/tree/master/urma-profiles#readme) | Typed Wire, Git and private-content profiles |
| [urma-runtime](https://github.com/urma-protocol/urma/tree/master/urma-runtime#readme) | Publication plans, transports, journals and recovery |
| [urma-workflows](https://github.com/urma-protocol/urma/tree/master/urma-workflows#readme) | Archive and identity-vault operations |
| [urma-files](https://github.com/urma-protocol/urma/tree/master/urma-files#readme) | Capture, file collections, catalogs and restoration |
| [urma-git](https://github.com/urma-protocol/urma/tree/master/urma-git#readme) | Git snapshots, publication and verified checkout |
| [urma-wire](https://github.com/urma-protocol/urma/tree/master/urma-wire#readme) | Public record reading and a reorganization-aware index |
| [urma-names](https://github.com/urma-protocol/urma/tree/master/urma-names#readme) | Names-registry payloads, state transitions and resolution |
| [urma-web](https://github.com/urma-protocol/urma/tree/master/urma-web#readme) | Web packages, pinned objects and verified storage |
| [urma-cli](https://github.com/urma-protocol/urma/tree/master/urma-cli#readme) | The `urma` command-line application and HTTP gateway |

Each crate README links to its package and API reference. Supported options, limits and dependency versions live in the API documentation, CLI help and Cargo manifests rather than a second table of changing values here.

## Work from source

```sh
git clone https://github.com/urma-protocol/urma.git
cd urma
cargo build --workspace --locked
cargo install --path urma-cli --locked
```

For a focused check while developing a component:

```sh
cargo test -p urma-core --locked
```

Git workflows invoke the `git` executable, so install Git as well as Rust when using those workflows. Source on the development branch and published packages can differ; use the documentation for the package version your application actually resolves.

## Project status

URMA is a V0 protocol under active development. Protocol versions and Rust package versions describe different layers. A published crate is available implementation code, not a declaration of complete protocol conformance or an external security audit.

For bugs and concrete proposals, use the [issue tracker](https://github.com/urma-protocol/urma/issues). For project contact: [urma@rosint.org](mailto:urma@rosint.org).

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Maintained by Cristian Zmole as part of [ROSINT](https://rosint.org).
