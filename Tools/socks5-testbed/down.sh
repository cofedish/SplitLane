#!/usr/bin/env bash
# Stop and remove the SplitLane SOCKS5 testbed.
set -euo pipefail
cd "$(dirname "$0")"
echo "==> Stopping SOCKS5 testbed"
docker compose down --remove-orphans
