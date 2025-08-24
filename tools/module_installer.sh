#!/usr/bin/env bash
set -euo pipefail

# Usage: ./install_ai_module.sh [PATH/TO/ai_event_analysis.py]
SRC="${1:-modules/expansion/ai_event_analysis.py}"
[ -f "$SRC" ] || { echo "Source not found: $SRC"; exit 1; }

# 1) Locate the misp-modules container
CID="$(docker ps --filter "name=misp-modules" -q | head -n1)"
[ -n "$CID" ] || { echo "No running misp-modules container found."; exit 1; }
echo "Using container: $CID"

# 2) Figure out the destination directory inside the container
DEST="$(docker exec "$CID" bash -lc '
set -e
# Preferred source tree path (present in official images)
if [ -d /usr/local/src/misp-modules/misp_modules/modules/expansion ]; then
  echo /usr/local/src/misp-modules/misp_modules/modules/expansion; exit 0
fi
# Fallback: site-packages/dist-packages
python3 - <<PY
import site, os
for p in (site.getsitepackages() + [site.getusersitepackages()]):
    if p and os.path.isdir(p):
        d = os.path.join(p, "misp_modules", "modules", "expansion")
        if os.path.isdir(os.path.join(p, "misp_modules")):
            print(d)
            break
PY
' 2>/dev/null | head -n1)"

if [ -z "$DEST" ]; then
  # Last-resort scan (shallow)
  DEST="$(docker exec "$CID" bash -lc "set -e; \
    find /usr /opt -maxdepth 5 -type d -path '*/misp_modules/modules/expansion' 2>/dev/null | head -n1")"
fi

[ -n "$DEST" ] || { echo "Could not locate misp_modules/modules/expansion in container."; exit 1; }
echo "Destination in container: $DEST"

# 3) Create dest (just in case) and copy the file in
docker exec "$CID" bash -lc "mkdir -p '$DEST'"
docker cp "$SRC" "$CID:$DEST/ai_event_analysis.py"
echo "Copied $(basename "$SRC") -> $CID:$DEST/ai_event_analysis.py"

# 4) Restart the container so misp-modules reloads the handler
docker restart "$CID" >/dev/null
echo "Restarted misp-modules container."

# 5) Basic verification
# Try to fetch the /modules index from inside the container and grep our module name
sleep 1
if docker exec "$CID" bash -lc "curl -fsS http://misp-modules:6666/modules | grep -qi 'AI Event Analysis'"; then
  echo "Module visible at /modules."
else
  echo "Could not confirm via /modules. Dumping last 50 logs lines:"
  docker logs --tail=50 "$CID" || true
fi
