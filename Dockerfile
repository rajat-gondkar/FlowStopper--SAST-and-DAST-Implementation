# FlowStopper image. Phase 0 skeleton: builds and runs the CLI/API; the end-to-end `scan`
# wiring and `make demo` are completed in Phase 5 (P5-A3). Base pinned per spec §P5-A3.
# (Dependency pins in requirements.lock were resolved on Python 3.12; 3.11.5+ is the floor.)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ALLOWED_HOSTS=localhost,127.0.0.1,::1

WORKDIR /app

# Install dependencies first (cached layer), from the exact lock.
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

# Install the package itself.
COPY pyproject.toml README.md ./
COPY FlowStopper ./FlowStopper
RUN pip install --no-cache-dir --no-deps .

# Run as a non-root user (spec §P5-A3).
RUN useradd --create-home --uid 10001 flowstopper
USER flowstopper

EXPOSE 8000
ENTRYPOINT ["FlowStopper"]
CMD ["--help"]
