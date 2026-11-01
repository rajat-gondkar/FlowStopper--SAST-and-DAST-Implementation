# FlowStopper's OWN Dockerfile for the OWASP Benchmark for Python (upstream ships none). Not vendored:
# it copies the git-ignored, unmodified clone in src/ (pinned commit, scripts/bench_fetch.sh).
#
# Differences from upstream runBenchmark.sh (`flask --app app.py run --debug --port 8443 --cert=adhoc`):
#   - plain HTTP instead of an ad-hoc TLS cert (our scanner targets http://127.0.0.1);
#   - --no-reload (the reloader would import all 1,230 test modules twice); debug mode is kept;
#   - only the packages the app imports at runtime are installed, at upstream's pinned versions
#     (requirements.txt also pins scanner tooling such as mitmproxy/bandit that the app never imports).
FROM python:3.12-slim
WORKDIR /app
COPY src/requirements.txt /tmp/requirements.txt
RUN grep -iE '^(flask|werkzeug|jinja2|markupsafe|itsdangerous|click|blinker|lxml|elementpath|pyyaml|ldap3|pyasn1)==' /tmp/requirements.txt > /tmp/runtime.txt \
 && pip install --no-cache-dir -r /tmp/runtime.txt
COPY src/ /app/
# Run as a non-root user that owns /app (the app writes only under its own testfiles/). As root, the
# write-mode path-traversal tests truncate /etc/passwd during a scan, which then hides every read-based
# traversal proof that comes later (measurement environment only; the source is unchanged).
RUN useradd --create-home --uid 10001 bench && chown -R bench /app
USER bench
EXPOSE 8443
CMD ["flask", "--app", "app.py", "run", "--debug", "--no-reload", "--host", "0.0.0.0", "--port", "8443"]
