#!/usr/bin/env bash
set -euo pipefail

MOD_ROOT="$(cd "$(dirname "$0")" && pwd)"
MODULE_SRC="$MOD_ROOT/modules/expansion/ai_event_analysis.py"
PREP_SRC="$MOD_ROOT/tools/misp_server_prep.py"

if [[ ! -f "$MODULE_SRC" ]]; then
  echo "Module not found. Expected at $MODULE_SRC"
  exit 1
fi

VENV_DIR="${VENV_DIR:-$MOD_ROOT/.venv}"

python3 -m venv "$VENV_DIR"
. "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$MOD_ROOT/requirements.txt"

PY_CMD='import importlib, pathlib, misp_modules; print(pathlib.Path(misp_modules.__file__).parent)'
MODULES_DIR="$("$VENV_DIR/bin/python" -c "$PY_CMD")"
DEST_DIR="$MODULES_DIR/modules/expansion"

mkdir -p "$DEST_DIR"
cp "$MODULE_SRC" "$DEST_DIR/"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-enabled misp-modules >/dev/null 2>&1; then
    sudo systemctl restart misp-modules
  fi
fi

echo "Installed ai_event_analysis.py to $DEST_DIR"
echo "Activate venv with: . $VENV_DIR/bin/activate"

if [[ "${1:-}" == "--prep" ]]; then
  if [[ -f "$PREP_SRC" ]]; then
    echo "Launching MISP Server Prep wizard..."
    "$VENV_DIR/bin/python" "$PREP_SRC"
  else
    echo "Prep wizard not found at $PREP_SRC"
  fi
else
  echo "Run prep wizard anytime: $VENV_DIR/bin/python $PREP_SRC"
fi
