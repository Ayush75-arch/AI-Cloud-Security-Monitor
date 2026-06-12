# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /install /usr/local
COPY . .
RUN groupadd --system cloudguard && useradd --system --gid cloudguard --no-create-home cloudguard && chown -R cloudguard:cloudguard /app
USER cloudguard
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 CMD curl -f http://localhost:8000/health || exit 1
CMD ["gunicorn","app.main:app","--worker-class","uvicorn.workers.UvicornWorker","--workers","2","--bind","0.0.0.0:8000","--timeout","120","--graceful-timeout","30","--keep-alive","5","--access-logfile","-","--error-logfile","-"]
