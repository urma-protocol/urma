# URMA Node: operator morning checklist (Litecoin testnet)

The daemon runs as the user unit `urma-node.service`
([unit file](systemd/urma-node.service)), archive in
`~/.local/share/urma/node-testnet`, control API on `127.0.0.1:28331`, URMA
peers on `0.0.0.0:28332`. Litecoin Core (`litecoin-testnet.service`) is
optional.

## Open it

- Litecoin Core first (it is not started automatically):
  `systemctl --user start litecoin-testnet`. Within about 10 seconds the
  daemon's `local-rpc` entry turns from the "cookie file missing" error to
  `null`. The daemon runs either way; without Core it only lacks that source.
- App: **URMA Node** in the application menu (`~/.local/bin/urma-node-app`).
- Daemon state: `systemctl --user status urma-node`
- Daemon logs: `journalctl --user -u urma-node -f`
- Status JSON:

  ```sh
  urma-node-control --endpoint 127.0.0.1:28331 \
    --token-file ~/.local/share/urma/node-testnet/service.token status
  ```

## What to expect

| Field | Healthy |
| --- | --- |
| `chain_peers` | above 0 within a minute (Litecoin P2P peers) |
| `archive.selected_tip` | height rising toward the testnet tip |
| `archive.indexed_through` | rising from 4912417, trailing `selected_tip` |
| `overlay.peer_id`, `overlay.connected` | own URMA peer id; connected URMA peers (can be 0) |
| `commit_sources[0]` (`local-rpc`) `last_error` | `null` while litecoind runs |
| `last_sync_error` | `null`, or a transient peer error with a recent `_at` |

`local-rpc` follows litecoind within 10 seconds:

- litecoind stopped: `"commit source: cookie file missing: litecoind not running?"`
- litecoind running with txindex: `null`

Try it: `systemctl --user stop litecoin-testnet`, watch the field flip, then
`systemctl --user start litecoin-testnet`. The daemon keeps running either way.

## Stop and start

```sh
systemctl --user stop urma-node     # cooperative stop, at most 30 s
systemctl --user start urma-node
systemctl --user restart urma-node
```

The unit is enabled, so it starts with the user session. `Restart=on-failure`
restarts it 10 s after a crash; a clean stop stays stopped. Wait for `stop` to
return before running anything that opens the archive directly.
