#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
MODE="${1:-full}"
if [[ "$MODE" != replay && "$MODE" != full ]]; then echo 'Usage: bash setup.sh [replay|full] [--build-native]' >&2; exit 2; fi
PYTHON_BIN="${VITAL_Q_SETUP_PYTHON:-python3.12}"
"$PYTHON_BIN" -m venv .venv
if [[ "$MODE" == replay ]]; then REQUIREMENTS=requirements-replay.txt; else REQUIREMENTS=requirements.txt; fi
.venv/bin/python -m pip install -r "$REQUIREMENTS"
if [[ "$MODE" == full && "${2:-}" == --build-native ]]; then
  BUILD_ROOT="$REPO_ROOT/build/native-$(date +%Y%m%d-%H%M%S)"
  bash src/release/build_native.sh "$BUILD_ROOT"
  printf '%s\n' "$BUILD_ROOT/install" > "$REPO_ROOT/.native-prefix"
fi
echo 'Setup complete. Run: bash run.sh replay'
