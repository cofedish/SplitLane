#!/usr/bin/env bash
# Start the SplitLane SOCKS5 testbed and wait until it is actually usable.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Starting SOCKS5 testbed"
docker compose up -d --wait

# `--wait` covers container health, not SOCKS5 readiness, so probe the published ports.
for port in 11080 11081; do
    for attempt in $(seq 1 30); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            echo "==> 127.0.0.1:$port ready"
            break
        fi
        if [ "$attempt" -eq 30 ]; then
            echo "!! 127.0.0.1:$port never became ready" >&2
            docker compose logs >&2
            exit 1
        fi
        sleep 0.5
    done
done

cat <<'SUMMARY'

Testbed ready:
  127.0.0.1:11080   SOCKS5, no authentication
  127.0.0.1:11081   SOCKS5, username=splitlane password=lane-secret
  origin.test:80    nginx, reachable ONLY through the proxies

Run the integration tests:
  SPLITLANE_SOCKS5_INTEGRATION=1 swift test

Stop:
  Tools/socks5-testbed/down.sh
SUMMARY
