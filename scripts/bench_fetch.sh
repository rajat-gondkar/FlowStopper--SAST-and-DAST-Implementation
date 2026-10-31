#!/usr/bin/env bash
# Fetch and run a third-party benchmark target locally.
#
# We DO NOT vendor its source: the app is cloned at a PINNED commit into bench/<app>/src/
# (git-ignored) and run via Docker Compose using OUR OWN bench/<app>/docker-compose.yml (the upstream
# repo ships only a Dockerfile). Choice, pin and usage permission: docs/DECISIONS.md D-15.
# Licence + credit: THIRD_PARTY.md.
#
# Usage: scripts/bench_fetch.sh {clone|up|down|all}   (default: all = clone + up)
set -euo pipefail
cd "$(dirname "$0")/.."

APP="vulnerable-flask-app"
REPO="https://github.com/we45/Vulnerable-Flask-App.git"
# The upstream repo has no release tags; we pin the exact commit on master and verify after checkout.
# Open source; usage permitted by the authors (we45) for this event. See docs/DECISIONS.md D-15.
SHA="b6a4f97afd466e83e1f60781494252dec1c37039"

SRC="bench/$APP/src"
PROJECT="flowstopper-bench-$APP"
# Published on 127.0.0.1 only. 8100 avoids API 8000 / Mock A 5050 / Mock B 8090.
export BENCH_PORT="${BENCH_PORT:-8100}"
COMPOSE=(docker compose -p "$PROJECT" -f "bench/$APP/docker-compose.yml")

clone() {
  if [ -d "$SRC/.git" ] && [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)" = "$SHA" ]; then
    echo "[bench] $APP already present at $SHA"
    return 0
  fi
  rm -rf "$SRC"
  mkdir -p "$(dirname "$SRC")"
  echo "[bench] cloning $REPO"
  git clone --quiet "$REPO" "$SRC"
  git -C "$SRC" checkout --quiet "$SHA" 2>/dev/null || {
    echo "[bench] ERROR: commit $SHA not found in $REPO (history changed?). Update SHA in this script."
    exit 1
  }
  got="$(git -C "$SRC" rev-parse HEAD)"
  [ "$got" = "$SHA" ] || { echo "[bench] ERROR: HEAD $got != pinned $SHA"; exit 1; }
  echo "[bench] checked out $got"
}

up() {
  clone
  command -v docker >/dev/null || { echo "[bench] docker not found; install Docker to run the benchmark app."; exit 1; }
  echo "[bench] starting $APP via Docker Compose on http://127.0.0.1:$BENCH_PORT"
  "${COMPOSE[@]}" up -d --build
  echo "[bench] up. Stop with: scripts/bench_fetch.sh down"
}

down() {
  "${COMPOSE[@]}" down -v 2>/dev/null || true
  echo "[bench] stopped $APP"
}

case "${1:-all}" in
  clone) clone ;;
  up)    up ;;
  down)  down ;;
  all)   up ;;
  *) echo "usage: $0 {clone|up|down|all}"; exit 2 ;;
esac
