# FlowStopper developer tasks. Works with the GNU Make 3.81 shipped on macOS.
# Override the interpreter with: make setup PYTHON=/path/to/python3.12
PYTHON ?= $(shell command -v python3.12 || command -v python3.13 || command -v python3.11 || command -v python3)
VENV   := .venv
PY     := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help setup lint fmt test check schemas fixtures lock doctor validate-key demo bench-fetch bench bench-down clean

help: ## list targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-13s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(PY):
	@$(MAKE) setup

setup: ## create .venv, install pinned deps (requirements-dev.lock) and the package (editable)
	@$(PYTHON) -c 'import sys; v = sys.version_info; sys.exit(0 if v >= (3, 11) else "Python >= 3.11 required, found %d.%d" % v[:2])'
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --quiet --upgrade pip
	$(PY) -m pip install --quiet -r requirements-dev.lock
	$(PY) -m pip install --quiet --no-deps -e .
	@echo "setup OK ($$($(PY) --version)). Next: make check"

lint: $(PY) ## ruff lint + format check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

fmt: $(PY) ## auto-fix lint issues and format
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

test: $(PY) ## run pytest
	$(PY) -m pytest -q

check: lint test ## lint + tests; must be green before every merge to main

schemas: $(PY) ## regenerate docs/schemas/*.schema.json from the models
	$(PY) scripts/export_schemas.py

fixtures: $(PY) ## regenerate fixtures/*.json from scripts/build_fixtures.py
	$(PY) scripts/build_fixtures.py

lock: ## regenerate requirements.lock + requirements-dev.lock (clean venvs)
	PYTHON=$(PYTHON) ./scripts/lock.sh

doctor: ## check local prerequisites and repo state
	@$(PYTHON) scripts/doctor.py

validate-key: $(PY) ## validate an answer key: make validate-key KEY=keys/answer_key.json
	$(PY) -m FlowStopper.evalkit.keyschema $(KEY)

demo: ## start Mock A and scan it end to end (implemented in P5-A3)
	@echo "make demo is implemented in P5-A3 (Dev A)."; exit 1

bench-fetch: ## clone the pinned third-party benchmark app (git-ignored) and run it via Docker Compose
	./scripts/bench_fetch.sh all

bench: $(PY) ## scan + eval the benchmark app -> docs/metrics/bench_<app>.json (run `make bench-fetch` first; never gates check)
	FS=$(abspath $(PY:python=FlowStopper)) ./scripts/bench.sh

bench-down: ## stop the benchmark app
	./scripts/bench_fetch.sh down

clean: ## remove caches and scan outputs (keeps .venv)
	rm -rf .pytest_cache .ruff_cache build *.egg-info out
	find . -path ./.venv -prune -o -name __pycache__ -type d -prune -exec rm -rf {} +
