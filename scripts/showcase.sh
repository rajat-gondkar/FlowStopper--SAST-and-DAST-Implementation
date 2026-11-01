#!/usr/bin/env bash
# One command to showcase FlowStopper on a target (Owner: A).
#
#   scripts/showcase.sh mock_a                       (also: -MockA, mock_b, -MockB)
#   scripts/showcase.sh ~/Desktop/their_app          any folder with the app's source
#   scripts/showcase.sh ~/Desktop/their_app --target http://127.0.0.1:5000
#   scripts/showcase.sh stop                         stop what this script started
#   scripts/showcase.sh list                         show the targets and options
#
# For a folder, the source in it is analysed (parsed, never run). The app itself is either already
# running (--target URL) or started from the folder's docker-compose file. The scan is scored only
# when an answer key is given (--key FILE); with no key the report's Evaluation tab says so.
set -u
cd "$(dirname "$0")/.."

FS=".venv/bin/FlowStopper"
API_PORT="${API_PORT:-8000}"
API="http://127.0.0.1:${API_PORT}"
PIDFILE="out/showcase_api.pid"
STARTED="out/showcase_started.txt"   # "compose-file|project" of every folder app this script started

if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[0m'; else B=""; R=""; fi
bold() { printf '%s%s%s\n' "$B" "$*" "$R"; }
step() { printf '  %s%s%s %s\n' "$B" "$1" "$R" "$2"; }
die() { echo "showcase: $*" >&2; exit 1; }

# ---- target table ---------------------------------------------------------------------------
# sets: LABEL COMPOSE PROJECT PORT SRC KEY UNSEEN NAME
select_target() {
  local want
  want=$(printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/^-*//; s/[-_ ]//g')
  UNSEEN=""; KEY=""; PORT=""; PROJECT=""
  case "$want" in
    mocka)
      LABEL="Mock A (Flask)"; COMPOSE="apps/mock_a/docker-compose.yml"
      PORT=5050; SRC="apps/mock_a"; KEY="apps/mock_a/answer_key.json" ;;
    mockb)
      LABEL="Mock B (FastAPI, held-out)"; COMPOSE="apps/mock_b/docker-compose.yml"
      PORT=8090; SRC="apps/mock_b"; KEY="apps/mock_b/answer_key.json"
      UNSEEN="docs/metrics/mock_b_first_run.json" ;;   # its first run, before any tuning (spec P6-J1)
    *) return 1 ;;
  esac
  NAME="$want"
}

# Any folder: sets SRC LABEL NAME COMPOSE PROJECT. A leading ~ is expanded here, because the shell
# does not expand it inside APP=~/x.
select_folder() {
  local p="$1"
  case "$p" in "~") p="$HOME" ;; "~/"*) p="$HOME/${p#"~/"}" ;; esac
  [ -d "$p" ] || return 1
  SRC=$(cd "$p" && pwd)
  NAME="app_$(printf '%s' "$(basename "$SRC")" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' '_')"
  LABEL="$(basename "$SRC")"
  UNSEEN=""; KEY=""; PORT=""; COMPOSE=""
  PROJECT="flowstopper-${NAME#app_}"
  local f
  for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    if [ -f "$SRC/$f" ]; then COMPOSE="$SRC/$f"; break; fi
  done
  IS_FOLDER=1
}

compose() { # compose <compose-file> <project> <args...>
  local file="$1" project="$2"; shift 2
  if [ -n "$project" ]; then docker compose -p "$project" -f "$file" "$@"; else docker compose -f "$file" "$@"; fi
}

# Host ports the compose project publishes, one per line.
published_ports() {
  compose "$COMPOSE" "$PROJECT" ps --format json 2>/dev/null | .venv/bin/python -c '
import json, sys
raw = sys.stdin.read().strip()
rows = json.loads(raw) if raw.startswith("[") else [json.loads(x) for x in raw.splitlines() if x.strip()]
ports = {p["PublishedPort"] for r in rows for p in (r.get("Publishers") or []) if p.get("PublishedPort")}
print("\n".join(str(p) for p in sorted(ports)))
' 2>/dev/null
}

usage() {
  cat <<'EOF'
usage: scripts/showcase.sh <target> [options]      (or: make showcase APP=<target> [TARGET=url] [KEY=file] [AUTH=file])

targets:  mock_a        our Flask fixture                  (also -MockA)
          mock_b        our FastAPI fixture, held out      (also -MockB)
          <folder>      any folder with an app's source, e.g. ~/Desktop/their_app
other:    stop          stop what this script started

options (for a folder):
  --target URL   the app is already running at URL; nothing is started
                 (without it the folder's docker-compose file is started and its port is detected)
  --key FILE     score the scan against an answer key (otherwise no scores)
  --auth FILE    login config for an app that needs a session (see README, --auth-config)
EOF
}

stop_all() {
  local t f p
  for t in mock_a mock_b; do
    select_target "$t" && [ -f "$COMPOSE" ] && compose "$COMPOSE" "$PROJECT" down >/dev/null 2>&1 && echo "stopped: $LABEL"
  done
  if [ -f "$STARTED" ]; then
    while IFS='|' read -r f p; do
      [ -n "$f" ] && [ -f "$f" ] && compose "$f" "$p" down >/dev/null 2>&1 && echo "stopped: $f"
    done < "$STARTED"
    rm -f "$STARTED"
  fi
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

WHAT="$1"; shift
OPT_TARGET=""; OPT_KEY=""; OPT_AUTH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || die "--target needs a URL"; OPT_TARGET="$2"; shift 2 ;;
    --key)    [ $# -ge 2 ] || die "--key needs a file"; OPT_KEY="$2"; shift 2 ;;
    --auth)   [ $# -ge 2 ] || die "--auth needs a file"; OPT_AUTH="$2"; shift 2 ;;
    *) echo "showcase: unknown option '$1'" >&2; usage; exit 64 ;;
  esac
done

IS_FOLDER=""
if ! select_target "$WHAT"; then
  select_folder "$WHAT" || { echo "showcase: '$WHAT' is neither mock_a / mock_b nor an existing folder" >&2; usage; exit 64; }
fi
expand_tilde() { # the shell does not expand ~ inside VAR=~/x, so do it here
  case "$1" in "~") printf '%s' "$HOME" ;; "~/"*) printf '%s' "$HOME/${1#"~/"}" ;; *) printf '%s' "$1" ;; esac
}
OPT_KEY=$(expand_tilde "$OPT_KEY")
OPT_AUTH=$(expand_tilde "$OPT_AUTH")
[ -n "$OPT_KEY" ] && KEY="$OPT_KEY"
AUTH="$OPT_AUTH"
[ -z "$AUTH" ] || [ -f "$AUTH" ] || die "--auth file not found: $AUTH"
[ -z "$KEY" ] || [ -f "$KEY" ] || die "answer key not found: $KEY"

# ---- preflight --------------------------------------------------------------------------------
[ -x "$FS" ] || die "$FS not found; run 'make setup' first"
[ -d "$SRC" ] || die "$SRC not found"
START_APP=1
[ -n "$OPT_TARGET" ] && START_APP=""
if [ -n "$START_APP" ]; then
  [ -n "$COMPOSE" ] && [ -f "$COMPOSE" ] || die "no docker-compose file in $SRC. Start the app yourself, then run again with: --target http://127.0.0.1:<port>"
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running; trying 'colima start' ..."
    colima start >/dev/null 2>&1 || true
    docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop or Colima, or start the app yourself and pass --target."
  fi
fi
mkdir -p out

# ---- 1. start (or find) the target -----------------------------------------------------------
echo
bold "FlowStopper showcase: $LABEL"
echo
BASE_URL=""
if [ -z "$START_APP" ]; then
  BASE_URL="${OPT_TARGET%/}"
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE_URL/" 2>/dev/null)
  { [ -n "$code" ] && [ "$code" != "000" ]; } || die "nothing answers at $BASE_URL"
  step "[1/4]" "App          already running at $BASE_URL"
else
  step "[1/4]" "App          starting in Docker ..."
  if ! compose "$COMPOSE" "$PROJECT" up -d --build > out/showcase_compose.log 2>&1; then
    tail -n 15 out/showcase_compose.log >&2
    die "docker compose failed for $COMPOSE (full output: out/showcase_compose.log). If a container name is already in use, run: make showcase-stop"
  fi
  if [ -n "$IS_FOLDER" ]; then
    grep -qxF "$COMPOSE|$PROJECT" "$STARTED" 2>/dev/null || echo "$COMPOSE|$PROJECT" >> "$STARTED"
    for _ in $(seq 1 150); do
      for p in $(published_ports); do
        code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${p}/" 2>/dev/null)
        if [ -n "$code" ] && [ "$code" != "000" ]; then BASE_URL="http://127.0.0.1:${p}"; break 2; fi
      done
      sleep 1
    done
    [ -n "$BASE_URL" ] || die "no published port of $COMPOSE answered HTTP. Start the app yourself and pass --target; logs: docker compose -f $COMPOSE logs"
  else
    for _ in $(seq 1 150); do
      code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null)
      case "$code" in 2*|3*) BASE_URL="http://127.0.0.1:${PORT}"; break ;; esac
      sleep 1
    done
    [ -n "$BASE_URL" ] || die "the target did not answer on port ${PORT}; logs: docker compose -f $COMPOSE logs"
  fi
  step "     " "             up at $BASE_URL"
fi

# ---- 2. scan ----------------------------------------------------------------------------------
OUT="out/showcase_${NAME}"
LOG="out/showcase_${NAME}.log"
rm -rf "$OUT"
EXTRA_ARGS=()
[ -n "$AUTH" ] && EXTRA_ARGS+=(--auth-config "$AUTH")
if [ -n "$KEY" ]; then
  EXTRA_ARGS+=(--key "$KEY")   # scores go to the report's Evaluation tab
  [ -n "$UNSEEN" ] && [ -f "$UNSEEN" ] && EXTRA_ARGS+=(--unseen-from "$UNSEEN")
fi
step "[2/4]" "Scan         source + running app ..."
"$FS" scan --source "$SRC" --target "$BASE_URL" --out "$OUT" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} > "$LOG" 2>&1 \
  || { tail -n 25 "$LOG" >&2; die "scan failed (full log: $LOG)"; }

# ---- 3. API -----------------------------------------------------------------------------------
step "[3/4]" "API          checking ..."
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
  step "     " "             started on $API"
else
  step "     " "             already running on $API (not started by this script)"
fi

# ---- 4. summary -------------------------------------------------------------------------------
step "[4/4]" "Done"
SUMMARY=$(.venv/bin/python - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
m = json.load(open(f"{out}/scan_meta.json"))
c, i = m["counts"], m["counts"]["issues"]
print(m["scan_id"])
print(f'{c["routes"]} routes · {c["sast_findings"]} code findings · {c["dast_findings"]} runtime findings '
      f'({c["dast_requests"]} requests) · {m["timings_s"]["total"]} s')
print(f'{i["reported"]} issues: {i["confirmed"]} confirmed · {i["code_only"]} code-only · '
      f'{i["runtime_only"]} runtime-only   ({i["suppressed"]} suppressed, hidden)')
PY
)
SID=$(printf '%s\n' "$SUMMARY" | sed -n 1p)
HERE="$(pwd)"
echo
bold "Results"
printf '  %s\n' "$(printf '%s\n' "$SUMMARY" | sed -n 2p)"
printf '  %s\n' "$(printf '%s\n' "$SUMMARY" | sed -n 3p)"
if [ -f "$OUT/evaluation.json" ]; then
  echo
  bold "Scores (against the answer key you gave)"
  sed -n '/^Metric /,$p' "$LOG" | grep -v '^scan:' | sed 's/^/  /'
fi
echo
bold "Open in your browser"
row() { printf '  %-18s %s\n' "$1" "$2"; }
row "Report" "$API/scans/$SID/report"
[ -f "$OUT/evaluation.json" ] && row "Evaluation tab" "$API/scans/$SID/report#tab-evaluation"
row "API docs" "$API/docs"
row "Scanned app" "$BASE_URL/"
echo
bold "API data (JSON)"
row "All issues" "$API/issues?scan_id=$SID"
row "Confirmed only" "$API/issues?scan_id=$SID&label=confirmed"
row "Scan status" "$API/scans/$SID"
row "SARIF" "$API/scans/$SID/sarif"
echo
bold "Files"
row "Report" "$HERE/$OUT/report.html"
row "Findings list" "$HERE/$OUT/findings.md"
[ -f "$OUT/evaluation.json" ] && row "Scores" "$HERE/$OUT/evaluation.json"
row "Scan log" "$HERE/$LOG"
echo
printf '  Stop everything: %smake showcase-stop%s\n\n' "$B" "$R"
