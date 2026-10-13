#!/usr/bin/env bash
# Development-only local URMA Node. See local-node.md.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: local-node.sh DIR offline|p2p [options]
  --chain CHAIN          litecoin-testnet (default) or litecoin-mainnet
  --start-height H       application start height (default: fixture 100)
  --start-hash HASH      application start block hash (default: fixture)
  --retention MODE       unpruned (default) or pruned
  --urma-seed MULTIADDR  p2p only, repeatable
  --urma-peer MULTIADDR  p2p only, repeatable
  --chain-peer IP:PORT   p2p only, repeatable; Litecoin peers replacing DNS seeds
env: URMA_NODE (binary, default urma-node in PATH),
     URMA_NODE_LISTEN (control address, default 127.0.0.1:28331),
     URMA_CONFIG (CLI config, default $HOME/.config/urma/config.json)
EOF
    exit 2
}

[ $# -ge 2 ] || usage
dir=$1
mode=$2
shift 2
case $mode in offline | p2p) ;; *) usage ;; esac

listen=${URMA_NODE_LISTEN:-127.0.0.1:28331}
chain=litecoin-testnet
height=100
hash=69d7e94e291990264740f506e1ef0eef23e75dcfc7955a453b47260f12fb70e7
retention=unpruned
passthrough=()
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case $1 in
    --chain) chain=$2 ;;
    --start-height) height=$2 ;;
    --start-hash) hash=$2 ;;
    --retention) retention=$2 ;;
    --urma-seed | --urma-peer | --chain-peer)
        [ "$mode" = p2p ] || { echo "$1 needs p2p mode" >&2; exit 2; }
        passthrough+=("$1" "$2")
        ;;
    *) usage ;;
    esac
    shift 2
done

node=${URMA_NODE:-urma-node}
command -v "$node" >/dev/null || { echo "urma-node binary not found: $node" >&2; exit 1; }

mkdir -p -m 700 "$dir"
dir=$(cd "$dir" && pwd)
chmod 700 "$dir"
mkdir -p -m 700 "$dir/data"
chmod 700 "$dir/data"

config=$dir/config.json
wanted=$(printf '{\n  "chain": "%s",\n  "application_start": {\n    "height": %s,\n    "hash": "%s"\n  },\n  "retention": "%s"\n}\n' \
    "$chain" "$height" "$hash" "$retention")
if [ -e "$config" ]; then
    if [ "$(cat "$config")" != "$wanted" ]; then
        echo "$config differs from the requested chain/start/retention;" >&2
        echo "an archive's identity is fixed: use a new DIR." >&2
        exit 1
    fi
else
    printf '%s\n' "$wanted" >"$config"
fi

run() { "$node" --data "$dir/data" --config "$config" "$@"; }
[ -e "$dir/service.token" ] || run create-token "$dir/service.token"
[ -e "$dir/peer.key" ] || run create-peer-key "$dir/peer.key"

entry=$(printf '{"archive":{"endpoint":"%s","token_file":"%s"}}' "$listen" "$dir/service.token")
cli=${URMA_CONFIG:-$HOME/.config/urma/config.json}
echo "CLI/app archive entry: $entry" >&2
if [ -e "$cli" ]; then
    echo "$cli exists and was not modified; merge the entry above if wanted." >&2
else
    mkdir -p "$(dirname "$cli")"
    (umask 077 && printf '%s\n' "$entry" >"$cli")
    echo "wrote $cli" >&2
fi

args=(serve --listen "$listen" --token-file "$dir/service.token")
if [ "$mode" = p2p ]; then
    args+=(--p2p --no-commit-public --peer-key "$dir/peer.key" "${passthrough[@]}")
fi
echo "status: urma-node-control --endpoint $listen --token-file $dir/service.token status" >&2
exec "$node" --data "$dir/data" --config "$config" "${args[@]}"
