#!/usr/bin/env bash
set -euo pipefail

MOD_ROOT="$(cd "$(dirname "$0")" && pwd)"
MODULE_SRC="$MOD_ROOT/modules/expansion/ai_event_analysis.py"
PREP_SRC="$MOD_ROOT/tools/misp_server_prep.py"

[[ -f "$MODULE_SRC" ]] || { echo "Module not found at $MODULE_SRC"; exit 1; }

VENV_DIR="${VENV_DIR:-$MOD_ROOT/.venv}"
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$MOD_ROOT/requirements.txt"

echo "[info] venv ready at: $VENV_DIR"
echo "[info] installing ai_event_analysis.py into the ACTIVE misp-modules installation (not into the venv)"


DEST_DIR=""

docker_misp_modules_cid() {
  docker ps --filter "name=misp-modules" --format '{{.ID}}' | head -n1
}

if command -v docker >/dev/null 2>&1; then
  CID="$(docker_misp_modules_cid || true)"
  if [[ -n "${CID:-}" ]]; then
    echo "[info] Detected running Docker misp-modules container: $CID"
    set +e
    DEST_DIR_IN_CTN="$(docker exec "$CID" bash -lc "
      set -e
      # 1) Source checkout path (common in official images)
      if [ -d /usr/local/src/misp-modules/misp_modules/modules/expansion ]; then
        echo /usr/local/src/misp-modules/misp_modules/modules/expansion; exit 0
      fi
      # 2) site-packages / dist-packages
      python3 - <<'PY'
import site, os
candidates = []
for p in (site.getsitepackages()+[site.getusersitepackages()]):
    if p and os.path.isdir(p):
        d = os.path.join(p, 'misp_modules', 'modules', 'expansion')
        if os.path.isdir(os.path.join(p, 'misp_modules')):
            candidates.append(d)
if candidates:
    print(candidates[0])
PY
    " 2>/dev/null)"
    rc=$?
    set -e
    if [[ $rc -eq 0 && -n "$DEST_DIR_IN_CTN" ]]; then
      echo "[info] Container destination: $DEST_DIR_IN_CTN"
      docker exec "$CID" bash -lc "install -m 0644 -D /dev/stdin \"$DEST_DIR_IN_CTN/ai_event_analysis.py\"" < "$MODULE_SRC"
      echo "[ok] Installed ai_event_analysis.py to container:$DEST_DIR_IN_CTN"
      echo "[info] Restarting misp-modules container to pick up changes"
      docker restart "$CID" >/dev/null
      INSTALLED_IN="docker:$CID"
    else
      echo "[warn] Could not locate misp_modules path inside container; will try host-based install."
    fi
  fi
fi

if [[ -z "${INSTALLED_IN:-}" ]]; then
  # Try system python3 (outside venv) to resolve misp_modules
  # shellcheck disable=SC2016
  PY_CMD='import importlib, pathlib; import misp_modules as m; print(pathlib.Path(m.__file__).parent)'
  if "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
# Intentionally empty: we just ensure venv works; not used for path resolution
PY
  then
    : 
  fi

  set +e
  SYSTEM_MODULES_DIR="$(/usr/bin/env python3 -c "$PY_CMD" 2>/dev/null)"
  set -e

  if [[ -n "${SYSTEM_MODULES_DIR:-}" ]]; then
    DEST_DIR="$SYSTEM_MODULES_DIR/modules/expansion"
    sudo mkdir -p "$DEST_DIR"
    sudo install -m 0644 "$MODULE_SRC" "$DEST_DIR/"
    echo "[ok] Installed ai_event_analysis.py to $DEST_DIR (system Python)"
    INSTALLED_IN="host"
  else
    # 3) Fallback: look for common locations on disk
    echo "[warn] System python couldn't import misp_modules; scanning common paths..."
    set +e
    DEST_DIR="$(/usr/bin/env bash -lc "shopt -s nullglob; \
      for d in \
        /usr/local/src/misp-modules/misp_modules/modules/expansion \
        /usr/local/lib/python*/dist-packages/misp_modules/modules/expansion \
        /usr/local/lib/python*/site-packages/misp_modules/modules/expansion \
        /usr/lib/python*/dist-packages/misp_modules/modules/expansion \
        /opt/*/misp_modules/modules/expansion \
      ; do [ -d \"\$d\" ] && echo \"\$d\" && break; done" | head -n1)"
    set -e
    if [[ -n "$DEST_DIR" ]]; then
      sudo install -m 0644 "$MODULE_SRC" "$DEST_DIR/"
      echo "[ok] Installed ai_event_analysis.py to $DEST_DIR (found by scan)"
      INSTALLED_IN="host"
    fi
  fi
fi

if [[ -z "${INSTALLED_IN:-}" ]]; then
  cat >&2 <<'ERR'
[error] Could not locate a misp_modules installation to install into.

Hints:
  - If you run misp-modules via Docker, start it first, then rerun this installer.
    e.g. `docker ps | grep misp-modules` should show a container.
  - If you run misp-modules as a service on the host:
      sudo apt install misp-modules  # or the method you used
    then rerun this installer.
ERR
  exit 1
fi

if [[ "${INSTALLED_IN}" = "host" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled misp-modules >/dev/null 2>&1 || systemctl status misp-modules >/dev/null 2>&1; then
      echo "[info] Restarting systemd service: misp-modules"
      sudo systemctl restart misp-modules || true
    fi
  fi
fi

echo "[done] ai_event_analysis.py installed (${INSTALLED_IN})"
echo "Activate venv when you want the prep wizard:  . \"$VENV_DIR/bin/activate\""

if [[ "${1:-}" == "--prep" ]]; then
  if [[ -f "$PREP_SRC" ]]; then
    echo "[info] Launching MISP Server Prep wizard..."
    "$VENV_DIR/bin/python" "$PREP_SRC"
  else
    echo "[warn] Prep wizard not found at $PREP_SRC"
  fi
else
  echo "[hint] Run prep wizard anytime: $VENV_DIR/bin/python \"$PREP_SRC\""
fi
