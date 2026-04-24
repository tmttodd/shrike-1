"""Lightweight development server for Shrike pipeline.

WARNING: This server has NO authentication and is intended for local
development and testing only. For production use, use shrike.runtime
which includes authentication and WAL-backed destinations.

Provides HTTP API for log normalization:
  POST /normalize — single log line → OCSF JSON
  POST /batch — multiple log lines → list of OCSF JSON
  GET /health — health check
  GET /info — pipeline info (loaded schemas, filters, model)

Usage:
    python -m shrike.server --host 127.0.0.1 --port 8080
    uvicorn shrike.server:app --host 127.0.0.1 --port 8080
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from shrike import __version__
from shrike.pipeline import ShrikePipeline


# Configuration from environment
CLASSIFIER_MODEL = os.environ.get("SHRIKE_CLASSIFIER_MODEL", "models/distilbert-ocsf-classifier")
CLASSIFIER_TYPE = os.environ.get("SHRIKE_CLASSIFIER_TYPE", "distilbert")
EXTRACTOR_API = os.environ.get("SHRIKE_EXTRACTOR_API", "http://localhost:11434/v1")
EXTRACTOR_MODEL = os.environ.get("SHRIKE_EXTRACTOR_MODEL", "shrike-extractor")
ACTIVE_FILTER = os.environ.get("SHRIKE_ACTIVE_FILTER", "")
SCHEMAS_DIR = os.environ.get("SHRIKE_SCHEMAS_DIR", "schemas/ocsf_v1.3/classes")

if HAS_FASTAPI:
    app = FastAPI(
        title="Shrike",
        description="Any log format in, OCSF JSON out.",
        version=__version__,
    )

    # Lazy-initialize pipeline
    _pipeline: ShrikePipeline | None = None

    def get_pipeline() -> ShrikePipeline:
        global _pipeline
        if _pipeline is None:
            classifier_path = Path(CLASSIFIER_MODEL) if CLASSIFIER_MODEL else None
            if classifier_path and not classifier_path.exists():
                classifier_path = None

            _pipeline = ShrikePipeline(
                classifier_model=classifier_path,
                classifier_type=CLASSIFIER_TYPE,
                extractor_api=EXTRACTOR_API,
                extractor_model=EXTRACTOR_MODEL,
                schemas_dir=SCHEMAS_DIR if SCHEMAS_DIR else None,
                active_filter=ACTIVE_FILTER if ACTIVE_FILTER else None,
            )
        return _pipeline

    class NormalizeRequest(BaseModel):
        raw_log: str
        filter: str | None = None

    class BatchRequest(BaseModel):
        logs: list[str]
        filter: str | None = None

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__}

    @app.get("/info")
    async def info():
        pipe = get_pipeline()
        return {
            "version": __version__,
            "classifier_type": CLASSIFIER_TYPE,
            "classifier_loaded": pipe._classifier is not None,
            "schema_classes": len(pipe.known_classes),
            "available_filters": pipe.available_filters,
        }

    @app.post("/normalize")
    async def normalize(req: NormalizeRequest):
        pipe = get_pipeline()
        result = pipe.process(req.raw_log)
        return JSONResponse(content=result.to_dict())

    @app.post("/batch")
    async def batch(req: BatchRequest):
        pipe = get_pipeline()
        results = pipe.process_batch(req.logs)
        return JSONResponse(content=[r.to_dict() for r in results if not r.dropped])


def main():
    parser = argparse.ArgumentParser(description="Shrike HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if not HAS_FASTAPI:
        print("FastAPI not installed. Install with: pip install fastapi uvicorn")
        return

    import uvicorn
    uvicorn.run("shrike.server:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
