# Shrike — Log Normalization Engine
# Multi-stage build for minimal production image (~2.5GB target)

FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir ".[classifier]"

# Copy application code
COPY shrike/ shrike/
COPY schemas/ schemas/
COPY filters/ filters/

# Copy model artifacts (populated at build time or mount at runtime)
COPY models/ models/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default: run as FastAPI service
EXPOSE 8080
CMD ["python", "-m", "shrike.server", "--host", "0.0.0.0", "--port", "8080"]
