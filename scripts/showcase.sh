#!/usr/bin/env bash
# One command to showcase FlowStopper on a demo target (Owner: A).
#
#   scripts/showcase.sh mock_a        (also: -MockA, mock_b, -MockB)
#   scripts/showcase.sh stop          stop the target containers and the API this script started
#   scripts/showcase.sh list          show the available targets
#
# It starts the target in Docker, scans it, scores the result against the answer key (when one
# exists), starts the API if it is not already running, and prints every link worth opening.
set -u
cd "$(dirname "$0")/.."

FS=".venv/bin/FlowStopper"
API_PORT="${API_PORT:-8000}"
API="http://127.0.0.1:${API_PORT}"
PIDFILE="out/showcase_api.pid"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { echo "showcase: $*" >&2; exit 1; }

# ---- target table ---------------------------------------------------------------------------
# sets: LABEL COMPOSE PROJECT PORT SRC KEY UNSEEN
select_target() {
  local want
  want=$(printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/^-*//; s/[-_ ]//g')
  UNSEEN=""
  case "$want" in
    mocka)
      LABEL="Mock A (Flask)"; COMPOSE="apps/mock_a/docker-compose.yml"; PROJECT=""
      PORT=5050; SRC="apps/mock_a"; KEY="apps/mock_a/answer_key.json" ;;
    mockb)
      LABEL="Mock B (FastAPI, held-out)"; COMPOSE="apps/mock_b/docker-compose.yml"; PROJECT=""
      PORT=8090; SRC="apps/mock_b"; KEY="apps/mock_b/answer_key.json"
      UNSEEN="docs/metrics/mock_b_first_run.json" ;;   # its first run, before any tuning (spec P6-J1)
    *) return 1 ;;
  esac
  NAME="$want"
}

compose() { # compose <compose-file> <project> <args...>
  local file="$1" project="$2"; shift 2
  if [ -n "$project" ]; then docker compose -p "$project" -f "$file" "$@"; else docker compose -f "$file" "$@"; fi
}

usage() {
  cat <<'EOF'
usage: scripts/showcase.sh <target>      (or: make showcase APP=<target>)

targets:  mock_a   our Flask fixture                 (also -MockA)
          mock_b   our FastAPI fixture, held out     (also -MockB)
other:    stop     stop what this script started
EOF
}

stop_all() {
  for t in mock_a mock_b; do
    select_target "$t" && [ -f "$COMPOSE" ] && compose "$COMPOSE" "$PROJECT" down >/dev/null 2>&1 && echo "stopped: $LABEL"
  done
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null && echo "stopped: API (pid $(cat "$PIDFILE"))"
    rm -f "$PIDFILE"
  fi
}

[ $# -ge 1 ] || { usage; exit 64; }
case "$1" in
  stop) stop_all; exit 0 ;;
  list|help|-h|--help) usage; exit 0 ;;
esac
select_target "$1" || { echo "showcase: unknown target '$1'" >&2; usage; exit 64; }

# ---- preflight --------------------------------------------------------------------------------
[ -x "$FS" ] || die "$FS not found; run 'make setup' first"
[ -f "$COMPOSE" ] || die "$COMPOSE not found (is this target on another branch?)"
[ -d "$SRC" ] || die "$SRC not found"
if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running; trying 'colima start' ..."
  colima start >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop or Colima and retry."
fi
mkdir -p out

# ---- 1. start the target ----------------------------------------------------------------------
bold "[1/4] Starting $LABEL on http://127.0.0.1:${PORT} ..."
compose "$COMPOSE" "$PROJECT" up -d --build >/dev/null 2>&1 || die "docker compose failed for $COMPOSE"
ok=""
for _ in $(seq 1 150); do
  code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null)
  case "$code" in 2*|3*) ok=1; break ;; esac
  sleep 1
done
[ -n "$ok" ] || die "the target did not answer on port ${PORT}; logs: docker compose -f $COMPOSE logs"
echo "      up (HTTP $code)"

# ---- 2. scan ----------------------------------------------------------------------------------
OUT="out/showcase_${NAME}"
rm -rf "$OUT"
bold "[2/4] Scanning (SAST + DAST + correlation) and scoring against the answer key ..."
EXTRA_ARGS=()
if [ -f "$KEY" ]; then
  EXTRA_ARGS+=(--key "$KEY")   # scores go to the terminal AND the report's Evaluation tab
  [ -n "$UNSEEN" ] && [ -f "$UNSEEN" ] && EXTRA_ARGS+=(--unseen-from "$UNSEEN")
else
  echo "      (no answer key for this target: no scores, the Evaluation tab will say so)"
fi
"$FS" scan --source "$SRC" --target "http://127.0.0.1:${PORT}" --out "$OUT" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
  || die "scan failed"

# ---- 3. confirm the scores reached the report -------------------------------------------------
bold "[3/4] Checking the report ..."
if [ -f "$OUT/evaluation.json" ]; then
  echo "      scores saved in $OUT/evaluation.json and embedded in $OUT/report.html (Evaluation tab)"
else
  echo "      report written without scores"
fi

# ---- 4. API / links ---------------------------------------------------------------------------
bold "[4/4] Checking the API ..."
# Restart the API this script started earlier, so it always serves the current code and reads the
# newest scan. An API started some other way is left alone and reused.
if [ -f "$PIDFILE" ]; then
  kill "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE"
  for _ in $(seq 1 10); do curl -s -m 1 "$API/health" >/dev/null 2>&1 || break; sleep 1; done
fi
if ! curl -s -m 2 "$API/health" >/dev/null 2>&1; then
  nohup "$FS" serve --host 127.0.0.1 --port "$API_PORT" < /dev/null > out/showcase_api.log 2>&1 &
  echo $! > "$PIDFILE"
  for _ in $(seq 1 30); do curl -s -m 2 "$API/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -s -m 2 "$API/health" >/dev/null 2>&1 || die "the API did not start; see out/showcase_api.log"
  echo "      started the API on $API (pid $(cat "$PIDFILE"))"
else
  echo "      API already running on $API (not started by this script; restart it if you changed code)"
fi

SID=$(.venv/bin/python -c "import json,sys; print(json.load(open('$OUT/scan_meta.json'))['scan_id'])")
HERE="$(pwd)"
echo
bold "== $LABEL: results =="
echo "  Report (open this)      $API/scans/$SID/report"
[ -f "$OUT/evaluation.json" ] && echo "  Evaluation tab (scores) $API/scans/$SID/report#tab-evaluation"
echo "  Report as a file        file://$HERE/$OUT/report.html"
echo "  All issues (JSON)       $API/issues?scan_id=$SID"
echo "  Confirmed only          $API/issues?scan_id=$SID&label=confirmed"
echo "  Scan status / timings   $API/scans/$SID"
echo "  SARIF export            $API/scans/$SID/sarif"
echo "  API docs (try it)       $API/docs"
echo "  Findings list (md)      $HERE/$OUT/findings.md"
[ -f "$OUT/evaluation.json" ] && echo "  Scores (JSON)           $HERE/$OUT/evaluation.json"
echo "  The scanned app         http://127.0.0.1:${PORT}/"
echo
echo "  Stop everything:        make showcase-stop"
