#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${OQS_INSTALL_PATH:-}" && -f "$REPO_ROOT/.native-prefix" ]]; then
  export OQS_INSTALL_PATH="$(cat "$REPO_ROOT/.native-prefix")"
fi
PYTHON_BIN="${VITAL_Q_PYTHON:-$REPO_ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo 'Run bash setup.sh first, or set VITAL_Q_PYTHON to your Python executable.' >&2
  exit 1
fi
if [[ $# -eq 0 ]]; then set -- replay; fi
exec "$PYTHON_BIN" "$REPO_ROOT/scripts/reproduce.py" "$@"
