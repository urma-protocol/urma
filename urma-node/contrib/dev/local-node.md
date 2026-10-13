# Local development node

`local-node.sh` prepares and runs one URMA Node for development: a CLI, the
desktop app or a test talks to it at `127.0.0.1:28331`. It is not an installer;
for a supervised service see [the systemd template](../systemd/README.md).

```sh
cargo build --release -p urma-node -p urma-cli --locked
export URMA_NODE=$PWD/target/release/urma-node
urma-node/contrib/dev/local-node.sh ~/urma-dev offline
```

## What it does

Every step is skipped when its result already exists, so rerunning it just
starts the node again.

| Path | Content |
| --- | --- |
| `DIR/` and `DIR/data/` | archive directory, mode 0700 |
| `DIR/config.json` | chain, application start, retention |
| `DIR/service.token` | bearer token (`urma-node create-token`) |
| `DIR/peer.key` | overlay transport key (`urma-node create-peer-key`), not a wallet key |

It prints the CLI/app `archive` entry,
`{"archive":{"endpoint":"127.0.0.1:28331","token_file":"DIR/service.token"}}`.
If `$URMA_CONFIG` (default `~/.config/urma/config.json`) does not exist it is
created with that entry. An existing file is never modified: merge the
printed entry yourself.

The node then runs `serve` in the foreground:

| Mode | Flags | Network |
| --- | --- | --- |
| `offline` | none | none; serves local state only |
| `p2p` | `--p2p --no-commit-public --peer-key DIR/peer.key` | Litecoin headers and blocks, URMA overlay; missing commit parents only from URMA peers |

`--urma-seed MULTIADDR` and `--urma-peer MULTIADDR` (repeatable) pass through
in `p2p` mode. The built-in seed of the chain is used too.

`--chain-peer IP:PORT` (repeatable, `p2p` only) picks the Litecoin peers for
headers and blocks. Pinned peers replace peer discovery entirely: no DNS
seeds, no gossiped addresses.

```sh
local-node.sh ~/urma-tltc p2p --start-height H --start-hash X --chain-peer 127.0.0.1:19335
```

If 28331 is taken (another dev node), set `URMA_NODE_LISTEN=127.0.0.1:PORT`.
The printed `archive` entry follows it. A busy port fails with
`Address already in use` before anything listens.

## Application start

Without options the config uses the Litecoin testnet values from
`urma-node/tests/cross_host_fixture.rs`: height 100, hash
`69d7e94e291990264740f506e1ef0eef23e75dcfc7955a453b47260f12fb70e7`. That
block is synthetic. It is fine for `offline`, but no real peer serves it, so
`p2p` with these values cannot synchronize.

For a real start pick a height at or after the embedded checkpoint
(Litecoin testnet 4,904,927, mainnet 3,187,295) and its block hash:

```sh
litecoin-cli -testnet getblockhash 4905000
# or https://litecoinspace.org/testnet/api/block-height/4905000
local-node.sh ~/urma-tltc p2p --start-height 4905000 --start-hash HASH
```

The start is part of the archive identity. The script refuses a `DIR` whose
`config.json` has a different chain, start or retention: use a new `DIR`.

## Status

```sh
urma-node-control --endpoint 127.0.0.1:28331 --token-file DIR/service.token status
curl -s -H "Authorization: Bearer $(cat DIR/service.token)" http://127.0.0.1:28331/v1/status
```

| Field | `offline`, fresh archive | `p2p`, syncing |
| --- | --- | --- |
| `archive.selected_tip` | `null`: no header source | rises from the embedded checkpoint toward the chain tip |
| `archive.indexed_through` | `null` | contiguous block range scanned from the application start; trails `selected_tip` |
| `archive.scanned_blocks`, `stored_transactions` | 0 | grow as blocks are scanned and URMA records found |
| `archive.unresolved_dependencies` | 0 | reveals whose commit parent is not yet local |
| `archive.peer_synced_through` | `null` | range a peer listed and the node verified; trusts that peer's completeness |
| `last_sync_error` | `null` | header or block source failure of the latest round (and its `_at` time) |
| `last_dependency_error`, `commit_sources` | `null`, `[]` | `[{"label":"overlay",…}]`; no `public` entry because of `--no-commit-public` |
| `last_retention_error`, `retention_configured` | `null`, `false` | object recovery failures; `true` for unpruned |
| `overlay` | `null`: no peer key | `peer_id`, `peer_book`, `connected`, `discovery` (`seeds`, `reached`, …) and per-peer cursors |
| `last_inventory_error`, `last_discovery_error` | `null` | latest failed overlay step |
| `cache_limit_bytes`, `last_cache_maintenance` | 128 MiB, `null` | receipt of the last cache step |

Any `last_*_error` describes only the latest attempt of that worker.

## Stop

Press Ctrl-C, or send SIGTERM to the process. You can also request a stop over HTTP:

```sh
curl -s -X POST -H "Authorization: Bearer $(cat DIR/service.token)" http://127.0.0.1:28331/v1/shutdown
```

`urma-node-control` has no shutdown command. Every route only requests a
cooperative stop; wait for the process to exit before reopening the archive
(for example with `urma-node status`).

## Point the UI or CLI at it

Clients need the endpoint `127.0.0.1:28331` and the token file
`DIR/service.token`, which is the same pair as the printed `archive` entry. The
CLI reads that entry from its config. The app connects through
`urma-node-client` (`Client::new(endpoint, token)`) with the same values. Keep
the token in its file; never put it in arguments or the environment.
