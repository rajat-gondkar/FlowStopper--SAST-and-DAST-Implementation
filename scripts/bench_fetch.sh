#!/usr/bin/env bash
# Fetch and run a third-party benchmark target locally.
#
# We DO NOT vendor its source (rule R1 / licence hygiene): the app is cloned at a PINNED commit
# into bench/<app>/src/ (git-ignored) and run via Docker Compose using our own thin override.
# Choice + pin rationale: docs/DECISIONS.md (D-15). Licence + credit: THIRD_PARTY.md.
#
# Usage: scripts/bench_fetch.sh {clone|up|down|all}   (default: all = clone + up)
set -euo pipefail
cd "$(dirname "$0")/.."

APP="pygoat"
REPO="https://github.com/adeyosemanputra/pygoat.git"
# v2.0.1 is the classic, lightweight Django PyGoat (simple docker-compose, OWASP labs in
# introduction/views.py). We deliberately avoid v3.x, which runs traefik + per-lab Docker-in-Docker
# containers and is a poor static-analysis target. See docs/DECISIONS.md (D-15).
TAG="v2.0.1"
# Exact commit for reproducibility; verified after checkout. Bump TAG and SHA together.
SHA="c11e8429349cc05ff38564d3bf7ef09fb2411874"

SRC="bench/$APP/src"
PROJECT="flowstopper-bench-$APP"
# Published on 127.0.0.1 only. 8100 avoids API 8000 / Mock A 5050 / Mock B 8090.
export BENCH_PORT="${BENCH_PORT:-8100}"
COMPOSE=(docker compose -p "$PROJECT" -f "$SRC/docker-compose.yml" -f "bench/$APP/compose.override.yml")

clone() {
  if [ -d "$SRC/.git" ] && [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)" = "$SHA" ]; then
    echo "[bench] $APP already present at $SHA"
    return 0
  fi
  rm -rf "$SRC"
  mkdir -p "$(dirname "$SRC")"
  echo "[bench] cloning $REPO @ $TAG"
  git clone --quiet --branch "$TAG" --depth 1 "$REPO" "$SRC"
  got="$(git -C "$SRC" rev-parse HEAD)"
  if [ "$got" != "$SHA" ]; then
    echo "[bench] ERROR: tag $TAG resolved to $got, expected $SHA (tag moved?)."
    echo "[bench] Refusing to continue for reproducibility. Update SHA in this script if intended."
    exit 1
  fi
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
