#!/usr/bin/env bash
# Run the full FlowStopper pipeline + eval against the third-party benchmark app and write
# docs/metrics/bench_<app>.json. NOT part of `make check` (never gates it).
#
# Prereq: the app is running (scripts/bench_fetch.sh up, or `make bench-fetch`).
# Scope (R3): the benchmark host is allow-listed here VIA CONFIG ONLY (ALLOWED_HOSTS env), never by
# editing FlowStopper/. localhost/127.0.0.1 are allowed by default; we add the compose alias `pygoat`.
set -uo pipefail
cd "$(dirname "$0")/.."

APP="pygoat"
PORT="${BENCH_PORT:-8100}"
TARGET="http://127.0.0.1:$PORT"
export ALLOWED_HOSTS="${ALLOWED_HOSTS:-localhost,127.0.0.1,::1,$APP}"

SRC="bench/$APP/src"
OUT="bench/$APP/out"
KEY="bench/$APP/answer_key.json"
METRICS="docs/metrics/bench_$APP.json"
FS="${FS:-.venv/bin/FlowStopper}"
[ -x "$FS" ] || FS="FlowStopper"

if [ ! -d "$SRC" ]; then
  echo "[bench] $SRC missing. Run: make bench-fetch"
  exit 1
fi
mkdir -p "$OUT" docs/metrics

echo "[bench] target=$TARGET  ALLOWED_HOSTS=$ALLOWED_HOSTS"
if ! curl -sf -o /dev/null --max-time 3 "$TARGET" 2>/dev/null; then
  echo "[bench] note: $TARGET not reachable yet. Start it with: make bench-fetch"
fi

echo "[bench] SAST+DAST+correlate -> $OUT/issues.json"
"$FS" scan --source "$SRC" --target "$TARGET" --out "$OUT" || true

if [ -f "$OUT/issues.json" ]; then
  echo "[bench] eval against $KEY -> $METRICS"
  "$FS" eval --key "$KEY" --issues "$OUT/issues.json" --out "$METRICS" || true
  if [ -f "$METRICS" ]; then
    echo "[bench] ===== metrics ($METRICS) ====="
    cat "$METRICS"
  fi
else
  echo "[bench] No issues.json produced."
  echo "[bench] The scan pipeline (P3-A1) and eval (P1-B5/P3-B1) are not implemented yet."
  echo "[bench] 'make bench' will produce $METRICS once they land. This is expected pre-Phase-3."
fi
