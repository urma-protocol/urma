#!/usr/bin/env python3
"""Run the opt-in live probe with a parent-owned staging directory and deadline."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if not os.environ.get("URMA_STARTUP_CACHE"):
        raise SystemExit("URMA_STARTUP_CACHE must name an explicit absolute cache path")
    if not Path(os.environ["URMA_STARTUP_CACHE"]).is_absolute():
        raise SystemExit("URMA_STARTUP_CACHE must be absolute")
    if os.environ.get("URMA_STARTUP_CHAIN") not in {"mainnet", "testnet"}:
        raise SystemExit("URMA_STARTUP_CHAIN must be mainnet or testnet")
    root = Path(__file__).resolve().parent.parent
    target = root / "target"
    command = ["cargo", "test", "--offline", "--locked", "--release", "-p", "urma-runtime",
               "--target-dir", str(target), "--test", "p2p_startup_live_costs"]
    build = subprocess.run(command + ["--no-run"], cwd=root, check=False)
    if build.returncode:
        return build.returncode
    with tempfile.TemporaryDirectory(prefix="startup-live-", dir=target) as staging:
        environment = dict(os.environ, URMA_STARTUP_STAGING=staging)
        result = subprocess.run(
            ["timeout", "--kill-after=5s", "90s"] + command + ["--", "--ignored", "--nocapture"],
            cwd=root, env=environment, check=False,
        )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
