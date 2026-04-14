# Shrike — Security Data Platform
# Any log in, triaged OCSF out.
#
# Multi-stage build:
#   Stage 1: OTel Collector binary
#   Stage 2: Python runtime with engine + ML deps
#
# Build:
#   docker build -t shrike .
#
# Run (models are bundled — no volume mount needed):
#   docker run -p 8080:8080 shrike

# Stage 1: OTel Collector binary (for syslog/OTLP ingestion)
FROM otel/opentelemetry-collector-contrib:0.120.0 AS otelcol

# Stage 2: Shrike runtime
FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# OTel Collector (embedded for syslog/OTLP intake)
COPY --from=otelcol /otelcol-contrib /usr/local/bin/otelcol-contrib

WORKDIR /app

# Python deps — install in layers for cache efficiency
# Layer 1: Core runtime (FastAPI, uvicorn, aiohttp)
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Layer 2: Engine deps (YAML patterns, field aliases, drain3)
RUN pip install --no-cache-dir \
    pyyaml \
    drain3

# Layer 3: ML deps (classifier + NER — largest layer, ~1.5GB)
# These are lazy-loaded: container works without them (pattern-only mode)
# but classifier and NER need them
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir \
    transformers \
    sentence-transformers \
    numpy

# Application code
COPY pyproject.toml README.md .
COPY shrike/ shrike/
RUN pip install --no-cache-dir --no-deps .

# Static assets (patterns, schemas, aliases, filters)
COPY patterns/ patterns/
COPY schemas/ schemas/
COPY data/field_aliases.json data/field_aliases.json
COPY filters/ filters/

# ML models (bundled via Git LFS — ~830MB total)
# Override at runtime: docker run -v /path/to/models:/app/models:ro shrike
COPY models/ocsf-classifier/ models/ocsf-classifier/
COPY models/shrike-ner/ models/shrike-ner/
RUN mkdir -p data/ground_truth

# Runtime directories
RUN mkdir -p /data/wal /data/output /data/otel /run/shrike

# Non-root user
RUN addgroup --system shrike && \
    adduser --system --ingroup shrike shrike && \
    chown -R shrike:shrike /data /run/shrike /app

# Ports
EXPOSE 8080 1514 4317 4318

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

USER shrike

# Default: production runtime server (OTel + pipeline + Splunk HEC)
# Override for CLI: docker run shrike python -m shrike.cli --input /data/logs.txt
CMD ["python", "-m", "shrike.runtime"]
