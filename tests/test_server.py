"""Tests for the Shrike FastAPI server."""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from shrike.config import Config
from shrike.server import create_app


@pytest.fixture
def file_config(tmp_path) -> Config:
    """Config pointing at tmp directories for safe testing."""
    return Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
    )


@pytest.fixture
async def started_app(file_config):
    """Create app and run its lifespan startup."""
    app = create_app(file_config)
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def client(started_app) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client with lifespan already running."""
    transport = ASGITransport(app=started_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_health(client: AsyncClient) -> None:
    """GET /health returns status with destination info."""
    resp = await client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["mode"] == "full"
    assert "file_jsonl" in data["destinations"]

    dest = data["destinations"]["file_jsonl"]
    assert "healthy" in dest
    assert "pending" in dest
    assert "disk_usage_mb" in dest


async def test_ingest_batch(client: AsyncClient) -> None:
    """POST /v1/ingest accepts logs and returns accepted count."""
    payload = {"logs": ["line one", "line two", "line three"]}
    resp = await client.post("/v1/ingest", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["total"] == 3
    assert data["accepted"] == 3


async def test_ingest_empty(client: AsyncClient) -> None:
    """POST /v1/ingest with empty logs returns zero."""
    resp = await client.post("/v1/ingest", json={"logs": []})
    assert resp.status_code == 200

    data = resp.json()
    assert data["total"] == 0
    assert data["accepted"] == 0


async def test_health_no_destinations(tmp_path) -> None:
    """Health endpoint works with no configured destinations."""
    cfg = Config(
        destinations=[],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
    )
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"
            assert resp.json()["destinations"] == {}


# ------------------------------------------------------------------
# Auth tests (IMPORTANT-5)
# ------------------------------------------------------------------


async def test_ingest_requires_auth(tmp_path) -> None:
    """When ingest_api_key is configured, requests without the header get 401."""
    cfg = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
        ingest_api_key="secret-test-key",
    )
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # No auth header -> 401
            resp = await c.post("/v1/ingest", json={"logs": ["hello"]})
            assert resp.status_code == 401

            # Wrong key -> 401
            resp = await c.post(
                "/v1/ingest",
                json={"logs": ["hello"]},
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert resp.status_code == 401

            # Correct key -> 200
            resp = await c.post(
                "/v1/ingest",
                json={"logs": ["hello"]},
                headers={"Authorization": "Bearer secret-test-key"},
            )
            assert resp.status_code == 200
            assert resp.json()["accepted"] == 1


# ------------------------------------------------------------------
# WAL overflow test (IMPORTANT-5)
# ------------------------------------------------------------------


async def test_ingest_overflow_returns_507(tmp_path) -> None:
    """When all WALs are full, ingest returns HTTP 507."""
    cfg = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        wal_max_mb=0,  # Zero max = immediate overflow
        file_output_dir=str(tmp_path / "output"),
    )
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post("/v1/ingest", json={"logs": ["overflow-test"]})
            assert resp.status_code == 507
