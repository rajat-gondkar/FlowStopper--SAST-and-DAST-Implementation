# FlowStopper developer tasks. Works with the GNU Make 3.81 shipped on macOS.
# Override the interpreter with: make setup PYTHON=/path/to/python3.12
PYTHON ?= $(shell command -v python3.12 || command -v python3.13 || command -v python3.11 || command -v python3)
VENV   := .venv
PY     := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help setup lint fmt test check schemas fixtures lock doctor validate-key demo demo-down showcase showcase-stop bench-fetch bench bench-down clean

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

# `make demo` needs only Docker (with Compose) and make: Mock A runs from its own compose file, and
# the FlowStopper image scans it over Mock A's compose network (DECISIONS_Dev1 A-60). The Mock A
# names live here and in compose files, never in FlowStopper/ (R6). Never scans apps/mock_b.
MOCK_A_COMPOSE   := apps/mock_a/docker-compose.yml
MOCK_A_CONTAINER := flowstopper-mock-a
MOCK_A_SERVICE   := mock_a
MOCK_A_PORT      := 5050
DEMO_OUT         := out/demo
DEMO_WAIT_TRIES  := 60
COMPOSE_TARGET   := docker compose -f docker-compose.yml -f docker-compose.target.yml

demo: ## start Mock A in Docker and scan it end to end with the FlowStopper image (stop: make demo-down)
	docker compose -f $(MOCK_A_COMPOSE) up -d --build
	docker compose build flowstopper
	@echo "waiting for Mock A on http://127.0.0.1:$(MOCK_A_PORT)/ ..."; \
	i=0; \
	until [ "$$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:$(MOCK_A_PORT)/)" = 200 ]; do \
		i=$$((i + 1)); \
		if [ $$i -ge $(DEMO_WAIT_TRIES) ]; then \
			echo "Mock A did not answer HTTP 200 after $(DEMO_WAIT_TRIES) tries."; \
			echo "Logs: docker compose -f $(MOCK_A_COMPOSE) logs; stop it: make demo-down"; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	echo "Mock A is up."
	@set -e; \
	NET=$$(docker inspect -f '{{range $$k, $$v := .NetworkSettings.Networks}}{{println $$k}}{{end}}' $(MOCK_A_CONTAINER) | head -n 1); \
	if [ -z "$$NET" ]; then echo "cannot find the network of container $(MOCK_A_CONTAINER)"; exit 1; fi; \
	echo "scanning http://$(MOCK_A_SERVICE):$(MOCK_A_PORT) over network $$NET"; \
	mkdir -p $(DEMO_OUT); \
	TARGET_SRC=./apps/mock_a TARGET_NETWORK=$$NET ALLOWED_HOSTS=localhost,127.0.0.1,::1,$(MOCK_A_SERVICE) \
		$(COMPOSE_TARGET) run --rm -T --user "$$(id -u):$$(id -g)" \
		-e FLOWSTOPPER_DB=/app/$(DEMO_OUT)/.flowstopper/scans.db \
		flowstopper scan --source /src --target http://$(MOCK_A_SERVICE):$(MOCK_A_PORT) --out /app/$(DEMO_OUT)
	@test -f $(DEMO_OUT)/report.html
	@echo "Report: $(abspath $(DEMO_OUT))/report.html"
	@echo "Mock A is still running; stop it with: make demo-down"

demo-down: ## stop the Mock A container started by make demo
	docker compose -f $(MOCK_A_COMPOSE) down

# Which bench/<app>/ the fetch/down targets use: make bench-fetch BENCH_APP=owasp-benchmark-python
BENCH_APP ?= vulnerable-flask-app

showcase: ## scan a demo target and print every link: make showcase APP=mock_a (mock_a|mock_b)
	@./scripts/showcase.sh $(or $(APP),mock_a)

showcase-stop: ## stop the targets and the API that `make showcase` started
	@./scripts/showcase.sh stop

bench-fetch: ## clone the pinned third-party benchmark app (git-ignored) and run it via Docker Compose
	./scripts/bench_fetch.sh all $(BENCH_APP)

bench: $(PY) ## scan + eval the benchmark app -> docs/metrics/bench_<app>.json (run `make bench-fetch` first; never gates check)
	FS=$(abspath $(PY:python=FlowStopper)) ./scripts/bench.sh

bench-down: ## stop the benchmark app
	./scripts/bench_fetch.sh down $(BENCH_APP)

clean: ## remove caches and scan outputs (keeps .venv)
	rm -rf .pytest_cache .ruff_cache build *.egg-info out
	find . -path ./.venv -prune -o -name __pycache__ -type d -prune -exec rm -rf {} +
