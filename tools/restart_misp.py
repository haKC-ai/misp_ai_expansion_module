#!/usr/bin/env bash
set -euo pipefail

CIDS=$(docker ps --filter "name=misp" -q)

if [ -z "$CIDS" ]; then
  echo "No running MISP containers found."
  exit 1
fi

echo "Restarting MISP containers..."
for cid in $CIDS; do
  NAME=$(docker ps --filter "id=$cid" --format '{{.Names}}')
  echo "  - $NAME ($cid)"
  docker restart "$cid" >/dev/null
done

echo "All MISP containers restarted."
