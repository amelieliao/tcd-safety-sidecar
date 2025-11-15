# ============================
#  TCD Safety Sidecar - FastAPI Service
#  Production-ready, deterministic, and cloud-deployable
# ============================

# ---------- Builder Stage ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build essentials (numpy/pydantic deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# Create isolated virtualenv for deterministic builds
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/python -m compileall -q -j 4 /opt/venv

# ---------- Runtime Stage ----------
FROM python:3.11-slim

WORKDIR /app

# Copy only what's needed (virtualenv + source)
COPY --from=builder /opt/venv /opt/venv
COPY . /app

# ---------- Environment Setup ----------
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TCD_PORT=8080 \
    TCD_PROMETHEUS_PORT=8000 \
    TCD_PROM_HTTP=1 \
    TCD_CONFIG_VERSION=1

# Expose API port and Prometheus metrics
EXPOSE 8080 8000

# ---------- Healthcheck ----------
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz').read(); exit(0)"

# ---------- Entrypoint ----------
ENTRYPOINT ["uvicorn", "tcd.service:http_create_app", "--host", "0.0.0.0", "--port", "8080"]