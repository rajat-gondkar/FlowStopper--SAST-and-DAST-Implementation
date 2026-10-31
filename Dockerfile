# FlowStopper image (P5-A3): the CLI and the HTTP API (`FlowStopper serve`). Base pinned per
# spec §P5-A3. (Dependency pins in requirements.lock were resolved on Python 3.12; 3.11.5+ is the floor.)
# The report templates ship as package-data (pyproject.toml), so the non-editable install below
# carries FlowStopper/report/templates/*.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ALLOWED_HOSTS=localhost,127.0.0.1,::1 \
    FLOWSTOPPER_DB=/app/data/scans.db \
    FLOWSTOPPER_OUT=/app/data/api

WORKDIR /app

# Install dependencies first (cached layer), from the exact lock.
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

# Install the package itself.
COPY pyproject.toml README.md ./
COPY FlowStopper ./FlowStopper
RUN pip install --no-cache-dir --no-deps .

# Run as a non-root user (spec §P5-A3). /app/data (SQLite store + API scan outputs) and /app/out
# (one-off `scan --out`) are writable by that user; a fresh named volume on /app/data inherits it.
RUN useradd --create-home --uid 10001 flowstopper \
    && mkdir -p /app/data /app/out \
    && chown -R flowstopper:flowstopper /app/data /app/out
USER flowstopper

EXPOSE 8000
ENTRYPOINT ["FlowStopper"]
CMD ["--help"]
