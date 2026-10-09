# urma-cli

**Capture for journalism. Git for code beyond a single host. One command line.**

[crates.io](https://crates.io/crates/urma-cli) · [Source](https://github.com/urma-protocol/urma/tree/master/urma-cli) · [URMA](https://urma.rosint.org)

`urma-cli` installs **`urma`**, the command-line application for URMA publication, verification and recovery. It brings Capture, Git, archives, Wire, Names and Web workflows together with identity and wallet management.

## Install

In a Unix environment, with a current stable Rust toolchain:

```sh
cargo install urma-cli --locked
urma --help
```

Git workflows also require the `git` executable. To install from a checkout of the URMA repository instead:

```sh
cargo install --path urma-cli --locked
```

## Find your workflow

| Command | Purpose |
| --- | --- |
| `urma capture` | Preserve journalistic originals and explicit session context |
| `urma git` | Publish committed snapshots, recover proofs and clone verified code |
| `urma archive` | Encrypt, publish and restore files, directories and collections |
| `urma wire` | Publish public text and read a locally indexed feed |
| `urma key` | Manage identity vaults, recovery backups and archive recovery keys |
| `urma wallet` | Inspect addresses, funds and fee estimates |
| `urma web` | Pack, publish and retrieve site packages and pinned resources |
| `urma names` | Request, review, approve and resolve registry-scoped names |
| `urma gateway` | Serve registry names and verified site content over HTTP |
| `urma expert` | Work with lower-level protocol tools |

Use help to inspect inputs, network options and output paths before running an operation:

```sh
urma capture --help
urma git --help
urma web pack --help
urma names resolve --help
```

These help commands do not publish records or spend funds. Defaults and limits are documented by the installed command's help, so this README does not duplicate values that can change.

## Capture: preserve the originals

The Capture workflow starts with `ingest`, which seals originals with explicit session context. `inspect` authenticates the catalog; `recover` restores a local capture. For chain publication, `plan` prepares the work without broadcasting, `publish` approves and submits it, and `resume` continues that publication. `recover-chain` discovers and restores previously published material.

Keep the private recovery secret separately from the device or storage you may lose. Recovery needs both that secret and accessible records. The workflow authenticates recorded bytes and context; it cannot establish the truth of a scene by itself.

## Git: keep another route to the code

`prepare` freezes the committed HEAD snapshot, scans its content and quotes publication. `inspect` and `review` support checking the material before it becomes public. `publish` and `resume` handle publication; `watch` observes progress without submitting missing transactions.

On the reading side, `recover` retrieves content and proofs, `clone` creates an editable repository, and `verify` checks retained proofs and Git content offline. This preserves a committed snapshot, not every branch and the repository's entire history.

Start with the exact operation's help:

```sh
urma git prepare --help
urma git clone --help
urma git verify --help
```

## Publication and recovery

Choose the network explicitly using the options available for the selected operation. Planning and inspection are separate from publication, which can spend network fees. Retain the prepared plan and progress state when continuing an interrupted publication.

Private archives use recovery secrets distinct from identity-vault recovery phrases. Public records can expose their contents; inspect Git snapshots and other public material before approval. Access to retained records remains necessary even when the original application or host is gone.

### Explicit offline container recovery

Use `urma expert recover-container` to recover one object from a local packed
private container containing unrelated or invalid records:

```sh
URMA_OUTPUT=json urma expert recover-container --key recovery.key --input bundle.urma --output recovered.bin
```

The recovery key contains exactly 32 raw bytes and needs private file permissions
(for example, `chmod 600 recovery.key`). This mode reads bounded input and uses
neither a chain source nor an identity vault. It scans the entire container before
export. Container framing remains strict: damaged count, record-length framing,
truncation or trailing bytes are errors; it does not search for magic bytes or
resynchronize damaged framing.

Unrelated records and invalid candidates, including invalid metadata or IV after
MAC verification, are omitted and counted. Only fully valid authenticated records
determine the object. Exactly one object is required; another authenticated object
is an error even if incomplete. All chunks, consistent metadata, the original
length and whole-file hash must verify. Distinct fully valid records at the same
object/index, including a padding-only difference, make the object conflicted;
byte-identical duplicates are accepted. Resource and source failures remain errors.

JSON success reports `status: "recovered-object"`, `object_id`, `chunks`, `bytes`,
`sha256`, `content_type`, `skipped_unrelated` and `rejected_records`. This describes
the recovered object; it does not certify every source record or a complete source
inventory. Output configuration and recovery validation happen before writing.
Their failures exit unsuccessfully and leave a new output absent. Export writes a
complete file atomically without replacing an existing destination. A durability
error after the file has been committed, or an error reporting the result, can
still return failure with that complete file present.

The strict `urma expert open` and `store-local` commands, directory discovery with
`recover-local`, and Archive collection/file and identity-vault workflows retain
their existing contracts. Choose this recovery mode explicitly when tolerating
invalid or unrelated records within intact packed-container framing.

## Chain sources

Without any configuration `urma` reads the chain through the public providers of [urma-runtime](https://crates.io/crates/urma-runtime): Electrum servers first, then an Esplora explorer, then a JSON-RPC gateway, each checked against the selected network's genesis block. No local node, API key or paid plan is involved; `--testnet` switches the provider set with the network.

Electrum certificates are pinned on first use under `~/.local/share/urma/electrum-pins/` (`$XDG_DATA_HOME/urma/electrum-pins/` when set), one `<host>_<port>.sha256` file per server. A server whose certificate changed is refused until its pin file is removed; confirm the new fingerprint with the operator before removing it.

To use your own node instead, set `rpc_url` and `node_auth_file` in `~/.config/urma/config.json`, or export `URMA_RPC_URL` and `URMA_NODE_AUTH_FILE`. Both must be present; the node must listen on a loopback address with cookie authentication. Chain-facing `urma expert` commands that connect to Core require this local node; offline encoding, opening and recovery commands do not.

Command output names the evidence behind chain observations. `chain_evidence` in JSON reports, `source` in observation journals and the `Observation source` line of Git recovery carry one of three labels: `local_validating_node` means your node validated the blocks; `light_client_inclusion` means a proof-of-work header chain includes the transaction; `public_provider_observation` means third-party servers reported inclusion and the bytes were verified against the requested ids, but no block was validated locally. Record signatures are verified at every tier; the label states only what confirmation counts rest on.

## Build an application

The command line composes the [URMA Rust libraries](https://github.com/urma-protocol/urma#use-the-libraries). Use the relevant library directly when building another interface; `urma-cli` is the executable package.

## License

[0BSD](https://github.com/urma-protocol/urma/blob/master/LICENSE). Maintained by Cristian Zmole as part of [URMA](https://urma.rosint.org). [Project contact](mailto:urma@rosint.org).
